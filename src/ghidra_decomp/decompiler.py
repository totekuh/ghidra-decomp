"""Core decompilation logic using pyghidra."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack
from pathlib import Path

import click

from . import __version__
from .artifacts import (
    SCHEMA_VERSION,
    atomic_write_chunks,
    atomic_write_json,
    atomic_write_text,
    build_fingerprint,
    ensure_directory,
    fsync_tree,
    publish_directory,
    recover_destination,
    sha256_file,
    snapshot_input,
    staging_lock,
    staging_prefix,
    validate_destination,
)

PROJECT_NAME = "project"

# Per-function decompilation outcomes recorded in sidecars and manifest counts.
# Every function ends in exactly one of these, so they sum to the discovered
# total. Reuse is tracked separately: a reused function still has the outcome it
# earned when it was first decompiled.
STATUS_SUCCESS = "success"
STATUS_FALLBACK = "fallback"
STATUS_FAILED = "failed"
STATUSES = (STATUS_SUCCESS, STATUS_FALLBACK, STATUS_FAILED)

# A widely used type — `char`, an error struct, a callback signature — can be
# referenced thousands of times, and `types.json` is read whole. The full total
# is always reported; only the enumerated list is bounded.
TYPE_USAGE_LIMIT = 200


def _sanitize_name(name: str, max_length: int = 80) -> str:
    """Turn a function name into a safe filename component."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).rstrip(". ") or "_"
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
    }
    if safe.upper() in reserved:
        safe = f"_{safe}"
    return safe[:max_length]


def _artifact_stem(address: str, name: str, max_length: int = 120) -> str:
    """Build a bounded, portable, collision-resistant artifact stem."""
    digest = hashlib.sha256(f"{address}\0{name}".encode()).hexdigest()[:24]
    safe_address = _sanitize_name(address, 40)
    name_limit = max(1, max_length - len(safe_address) - len(digest) - 2)
    safe_name = _sanitize_name(name, name_limit)
    return f"{safe_address}_{digest}_{safe_name}"


def _failure_comment(error: object) -> str:
    """Render every fallback error line as valid C++-style commentary."""
    lines = str(error).splitlines() or ["decompilation failed"]
    return "".join(f"// DECOMPILATION FAILED: {line}\n" for line in lines)


def _is_timeout_error(error: object) -> bool:
    """Detect the decompiler's timeout message without matching other failures."""
    text = str(error).lower()
    return "timeout" in text or "timed out" in text


def _summarize_statuses(records: list[dict]) -> dict:
    """Summarize per-function outcomes into the manifest's counts block.

    `successful`, `fallback`, and `failed` partition the discovered functions.
    `skipped` counts the reused subset and therefore overlaps them: it answers
    "how much work did this run avoid", not "how did this function end".
    """
    tally = dict.fromkeys(STATUSES, 0)
    skipped = 0
    for record in records:
        decompilation = record.get("decompilation", {})
        status = decompilation.get("status")
        if status in tally:
            tally[status] += 1
        else:
            # An unrecognized status must never silently vanish from the totals.
            tally[STATUS_FAILED] += 1
        if decompilation.get("reused"):
            skipped += 1
    return {
        "discovered": len(records),
        "successful": tally[STATUS_SUCCESS],
        "fallback": tally[STATUS_FALLBACK],
        "failed": tally[STATUS_FAILED],
        "skipped": skipped,
    }


def _addresses_with_status(records: list[dict], status: str) -> list[str]:
    """List the addresses of every function that ended in one status."""
    return [
        record["address"]
        for record in records
        if record.get("decompilation", {}).get("status") == status
    ]


def normalize_filters(filters: dict | None) -> dict[str, list[str]]:
    """Render the function selection in one canonical, comparable form.

    A filtered corpus is not interchangeable with an unfiltered one, so this
    shape is recorded in the manifest and compared before any reuse.
    """
    filters = filters or {}
    return {
        key: sorted(filters.get(key) or ())
        for key in ("include", "exclude", "function")
    }


def _artifact_hashes_match(previous: Path, record: dict) -> bool:
    """Check every artifact a record claims still hashes to the recorded digest."""
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, dict):
        return False
    for path_key, hash_key in (
        ("pseudocode", "pseudocode_sha256"),
        ("assembly", "assembly_sha256"),
        ("sidecar", "sidecar_sha256"),
    ):
        relative = artifacts.get(path_key)
        expected = artifacts.get(hash_key)
        if not isinstance(relative, str) or not isinstance(expected, str):
            return False
        path = previous / relative
        # A recorded path must stay inside the corpus it came from.
        if not path.resolve().is_relative_to(previous.resolve()):
            return False
        if not path.is_file() or sha256_file(path) != expected:
            return False
    return True


def _reusable_function_artifacts(previous: Path, record: dict) -> bool:
    """Decide whether a previously exported function may be reused verbatim.

    Reuse requires a settled successful outcome and artifacts that still hash to
    what the previous run recorded. A mismatch is never silently trusted; the
    function is decompiled again.
    """
    if record.get("decompilation", {}).get("status") != STATUS_SUCCESS:
        return False
    sidecar_relative = record.get("artifacts", {}).get("sidecar")
    if not isinstance(sidecar_relative, str):
        return False
    try:
        sidecar = json.loads((previous / sidecar_relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(sidecar, dict):
        return False
    return _artifact_hashes_match(previous, record)


def load_resume_index(
    previous: Path, request_fingerprint: dict, filters: dict | None = None
) -> dict[str, dict]:
    """Map artifact stem to the reusable record of a previous corpus.

    An empty map means a full export. That is the correct degradation whenever
    the previous output is missing, incomplete, built by another schema, or
    describes a different binary, analysis request, or function selection.

    Filters gate reuse but deliberately do not gate the analysis cache: the same
    binary analyzed the same way yields the same Ghidra project no matter which
    subset of its functions is later exported.
    """
    try:
        manifest = json.loads((previous / "manifest.json").read_text(encoding="utf-8"))
        records = json.loads((previous / "functions.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(manifest, dict) or not isinstance(records, list):
        return {}
    if manifest.get("schema_version") != SCHEMA_VERSION:
        return {}
    if manifest.get("status") != "complete":
        return {}
    previous_request = manifest.get("fingerprints", {}).get("request", {})
    if previous_request.get("sha256") != request_fingerprint.get("sha256"):
        return {}
    if manifest.get("export", {}).get("filters") != normalize_filters(filters):
        return {}

    reusable = {}
    for record in records:
        if not isinstance(record, dict) or "address" not in record:
            continue
        if not _reusable_function_artifacts(previous, record):
            continue
        reusable[_artifact_stem(record["address"], record["name"])] = record
    return reusable


def _thunk_target(func) -> dict | None:
    """Resolve what a thunk forwards to, so it is not a dead end in the callgraph.

    Returns None for a function that is not a thunk. A thunk whose target cannot
    be resolved still returns the keys, with null values, so consumers see one
    shape rather than having to test for a missing block.
    """
    if not func.isThunk():
        return None
    thunked = func.getThunkedFunction(True)
    if thunked is None:
        return {"name": None, "address": None}
    return {
        "name": thunked.getName(),
        "address": thunked.getEntryPoint().toString(),
    }


def _decompiler_notes(c_code: str) -> list[dict]:
    """Extract the decompiler's own block comments as structured records.

    The decompiler reports where it gave up — an unknown calling convention, a
    subroutine that does not return, a block it removed — inside `/* ... */`
    comments in the C it emits. Left as prose those are invisible to a consumer
    deciding how far to trust the pseudocode.

    Only the decompiler uses block comments; this tool's own header and failure
    lines are `//`, so nothing it wrote can be picked up here.
    """
    notes = []
    for block in re.findall(r"/\*(.*?)\*/", c_code, re.DOTALL):
        # A block may span lines, so collapse whitespace into one comparable string.
        text = " ".join(block.split())
        if not text:
            continue
        for prefix, kind in (
            ("WARNING:", "warning"),
            ("Unresolved local var:", "unresolved_local"),
        ):
            if text.startswith(prefix):
                notes.append({"kind": kind, "text": text[len(prefix) :].strip()})
                break
        else:
            notes.append({"kind": "note", "text": text})
    return notes


def _func_header_comment(func) -> str:
    """Build a metadata header comment for a decompiled function."""
    addr = func.getEntryPoint().toString()
    name = func.getName()
    body = func.getBody()
    size = body.getNumAddresses()
    convention = func.getCallingConventionName() or "unknown"
    param_count = func.getParameterCount()
    is_thunk = func.isThunk()

    lines = [
        f"// Function: {name}",
        f"// Address:  {addr}",
        f"// Size:     {size} bytes",
        f"// Calling:  {convention}",
        f"// Params:   {param_count}",
    ]
    if is_thunk:
        thunked = func.getThunkedFunction(True)
        thunk_name = thunked.getName() if thunked else "unknown"
        lines.append(f"// Thunk:    -> {thunk_name}")
    lines.append("")
    return "\n".join(lines)


def _start_pyghidra(ghidra_path: Path | None):
    """Import and start pyghidra, returning the module."""
    try:
        import pyghidra
    except ImportError:
        raise click.ClickException(
            "pyghidra is not installed. Install it with: pip install pyghidra\n"
            "pyghidra is bundled with Ghidra 12+."
        )

    if not pyghidra.started():
        try:
            pyghidra.start(install_dir=ghidra_path) if ghidra_path else pyghidra.start()
        except Exception as e:  # noqa: BLE001 - Java exceptions have no stable base class
            hint = ""
            if not ghidra_path:
                hint = (
                    "\nSet GHIDRA_INSTALL_DIR or pass --ghidra-path "
                    "to your Ghidra installation."
                )
            raise click.ClickException(f"Failed to start Ghidra: {e}{hint}")

    return pyghidra


def list_languages(*, ghidra_path: Path | None = None) -> None:
    """Print all Ghidra language IDs with their available compiler specs."""
    _start_pyghidra(ghidra_path)

    from ghidra.program.util import DefaultLanguageService

    svc = DefaultLanguageService.getLanguageService()
    descs = list(svc.getLanguageDescriptions(False))
    descs.sort(key=lambda d: str(d.getLanguageID()))

    for d in descs:
        lang_id = str(d.getLanguageID())
        processor = str(d.getProcessor())
        endian = str(d.getEndian())
        size = d.getSize()
        cspecs = [
            str(c.getCompilerSpecID())
            for c in d.getCompatibleCompilerSpecDescriptions()
        ]
        click.echo(
            f"{lang_id}  [{processor} {endian} {size}]  cspec: {', '.join(cspecs) or '-'}"
        )

    click.echo(f"\n{len(descs)} language(s).")


def decompile_binary(
    binary: Path,
    output: Path,
    *,
    timeout: int = 60,
    combined: bool = False,
    ghidra_path: Path | None = None,
    base_addr: str | None = None,
    language: str | None = None,
    compiler: str | None = None,
    entry: str | None = None,
    resume: bool = False,
    workers: int | None = None,
    include: tuple[str, ...] | None = None,
    exclude: tuple[str, ...] | None = None,
    function: tuple[str, ...] | None = None,
    gdt: tuple[str, ...] | None = None,
    gzf: bool = False,
    semgrep_config: str | None = None,
) -> None:
    """Decompile a binary and write structured output."""
    binary = binary.resolve()
    output = output.resolve()
    if binary.stat().st_size == 0:
        raise click.ClickException(f"Input file is empty: {binary}")
    if binary.is_relative_to(output):
        raise click.ClickException(
            f"Output directory must not contain the input binary: {output}"
        )

    ensure_directory(output.parent)
    try:
        recover_destination(output)
        expected_destination = validate_destination(output)
    except ValueError as error:
        raise click.ClickException(str(error)) from error

    # Archives are hashed into the analysis identity because applying one
    # changes what the analyzer and decompiler produce.
    gdt_identity = []
    for raw in gdt or ():
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise click.BadParameter(
                f"Data type archive not found: {path}", param_hint="'--gdt'"
            )
        gdt_identity.append({"path": str(path), "sha256": sha256_file(path)})

    requested_analysis = {
        "base_address": base_addr,
        "entry_point": entry,
        "language": language,
        "compiler": compiler,
        "data_type_archives": gdt_identity,
    }
    # Validated before Ghidra starts: a typo in a pattern should fail in
    # milliseconds, not after a full analysis.
    filters = {"include": include, "exclude": exclude, "function": function}
    compile_filters(include, exclude)
    staging = Path(tempfile.mkdtemp(prefix=staging_prefix(output), dir=output.parent))
    with ExitStack() as run_stack:
        # Registered first so it runs last: the staging lock is released before
        # the directory it guards is removed.
        run_stack.callback(shutil.rmtree, staging, ignore_errors=True)
        run_stack.enter_context(staging_lock(staging))
        with tempfile.TemporaryDirectory(prefix="ghidra-decomp-") as workspace:
            input_dir = Path(workspace) / "input"
            project_dir = Path(workspace) / "project"
            input_dir.mkdir()
            project_dir.mkdir()
            snapshot = input_dir / "binary"
            input_identity = snapshot_input(binary, snapshot)
            request_fingerprint = build_fingerprint(input_identity, requested_analysis)
            atomic_write_json(
                staging / ".run-state.json",
                {
                    "schema_version": SCHEMA_VERSION,
                    "status": "incomplete",
                    "tool": {"name": "ghidra-decomp", "version": __version__},
                    "request_fingerprint": request_fingerprint,
                },
            )

            pyghidra = _start_pyghidra(ghidra_path)
            pyghidra_version = getattr(pyghidra, "__version__", "unknown")

            resume_index: dict[str, dict] = {}
            if resume:
                resume_index = load_resume_index(output, request_fingerprint, filters)

            open_kwargs: dict[str, object] = {
                "analyze": False,
                "project_location": str(project_dir),
                "project_name": PROJECT_NAME,
            }
            if language is not None:
                open_kwargs["language"] = language
            if compiler is not None:
                open_kwargs["compiler"] = compiler

            stack = ExitStack()
            try:
                flat_api = stack.enter_context(
                    pyghidra.open_program(str(snapshot), **open_kwargs)
                )
            except Exception as e:  # noqa: BLE001 - Java exceptions have no stable base class
                stack.close()
                msg = str(e)
                if "No load spec found" in msg:
                    hint = (
                        f"Ghidra could not identify {binary.name}. Likely a raw or unknown "
                        "format.\nPass --language (and optionally --compiler) to force a "
                        "spec. Run with --list-languages to discover IDs."
                    )
                elif language is not None:
                    hint = (
                        f"Failed to load with --language {language}"
                        + (f" --compiler {compiler}" if compiler else "")
                        + f": {msg}"
                    )
                else:
                    hint = f"Failed to open program: {msg}"
                raise click.ClickException(hint)

            with stack:
                program = flat_api.getCurrentProgram()
                if base_addr is not None:
                    _rebase_program(program, base_addr)

                if entry is not None:
                    _mark_entry(program, flat_api, entry)

                if gdt:
                    _apply_gdts(program, gdt)

                _run_analysis(program, flat_api)
                _export_all(
                    program,
                    input_identity,
                    staging,
                    timeout,
                    combined=combined,
                    requested_analysis=requested_analysis,
                    request_fingerprint=request_fingerprint,
                    pyghidra_version=pyghidra_version,
                    workers=workers if workers is not None else default_workers(),
                    filters=filters,
                    gzf=gzf,
                    semgrep_config=semgrep_config,
                    resume_index=resume_index,
                    resume_source=output if resume_index else None,
                )

        try:
            leftover_backup = publish_directory(staging, output, expected_destination)
        except ValueError as error:
            raise click.ClickException(str(error)) from error
        if leftover_backup is not None:
            click.echo(
                f"Warning: published corpus but could not remove backup {leftover_backup}",
                err=True,
            )


def _parse_address(program, value: str, *, label: str, param_hint: str):
    """Parse an unsigned offset without passing a high-half integer through JPype."""
    try:
        addr_value = int(value, 0)
    except ValueError:
        raise click.BadParameter(
            f"Invalid {label} address: {value!r}. Use hex, decimal, or octal format.",
            param_hint=param_hint,
        )
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    if addr_value < 0 or addr_value >= 1 << addr_space.getSize():
        raise click.BadParameter(
            f"{label.capitalize()} address {value!r} is outside the "
            f"{addr_space.getSize()}-bit address space.",
            param_hint=param_hint,
        )
    try:
        # The String overload supports unsigned 64-bit offsets; Java long does not.
        address = addr_space.getAddress(f"{addr_value:x}")
    except Exception as e:  # noqa: BLE001 - Java exceptions have no stable base class
        raise click.BadParameter(
            f"Invalid {label} address {value!r}: {e}", param_hint=param_hint
        )
    if address is None:
        raise click.BadParameter(
            f"Invalid {label} address: {value!r}.", param_hint=param_hint
        )
    return address


def _rebase_program(program, base_addr: str) -> None:
    """Rebase the program to a new image base address."""
    new_base = _parse_address(
        program, base_addr, label="base", param_hint="'--base-addr'"
    )

    old_base = program.getImageBase()
    click.echo(f"Rebasing: {old_base} -> {new_base}")

    success = False
    tid = program.startTransaction("Rebase image")
    try:
        program.setImageBase(new_base, True)
        success = True
    finally:
        program.endTransaction(tid, success)


def _mark_entry(program, flat_api, entry: str) -> None:
    """Disassemble from entry, create a function there, mark as program entry."""
    entry_addr = _parse_address(program, entry, label="entry", param_hint="'--entry'")
    if not program.getMemory().contains(entry_addr):
        raise click.ClickException(
            f"Entry address {entry_addr} is not in program memory."
        )
    click.echo(f"Entry:   {entry_addr}")

    success = False
    tid = program.startTransaction("Mark entry point")
    try:
        flat_api.disassemble(entry_addr)
        if program.getListing().getInstructionAt(entry_addr) is None:
            raise click.ClickException(
                f"Ghidra could not disassemble the entry address {entry_addr}."
            )
        if flat_api.getFunctionAt(entry_addr) is None:
            flat_api.createFunction(entry_addr, "entry")
        if flat_api.getFunctionAt(entry_addr) is None:
            raise click.ClickException(
                f"Ghidra could not create a function at entry address {entry_addr}."
            )
        program.getSymbolTable().addExternalEntryPoint(entry_addr)
        success = True
    finally:
        program.endTransaction(tid, success)


def _apply_gdts(program, gdt_paths: tuple[str, ...]) -> list[dict]:
    """Load archive data types into the program before analysis.

    Applying an archive changes what the analyzer and decompiler produce, so it
    is part of the analysis identity, not an export option.
    """
    from ghidra.program.model.data import DataTypeConflictHandler, FileDataTypeManager
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File as JavaFile

    monitor = ConsoleTaskMonitor()
    applied = []
    dtm = program.getDataTypeManager()
    for raw in gdt_paths:
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise click.BadParameter(
                f"Data type archive not found: {path}", param_hint="'--gdt'"
            )
        click.echo(f"Applying data type archive: {path}")
        archive = FileDataTypeManager.openFileArchive(JavaFile(str(path)), False)
        success = False
        tid = program.startTransaction(f"Apply {path.name}")
        try:
            dtm.addDataTypes(
                list(archive.getAllDataTypes()),
                DataTypeConflictHandler.REPLACE_HANDLER,
                monitor,
            )
            success = True
        finally:
            program.endTransaction(tid, success)
            archive.close()
        applied.append({"path": str(path), "sha256": sha256_file(path)})
    return applied


def _export_gzf(program, destination: Path) -> None:
    """Write a Ghidra zip file so the analyzed program can be reopened in the GUI.

    `DomainFile.packFile` is used rather than `GzfExporter`. Auto-analysis leaves
    a database transaction open for the lifetime of the program, and the
    exporter's own locking rejects that with "Unable to lock due to active
    transaction"; packing the domain file does not take that lock.
    """
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File as JavaFile

    domain_file = program.getDomainFile()
    if domain_file is None:
        raise click.ClickException(
            "The program has no domain file, so no GZF export is possible."
        )
    try:
        domain_file.packFile(JavaFile(str(destination)), ConsoleTaskMonitor())
    except Exception as e:  # noqa: BLE001 - Java exceptions have no stable base class
        raise click.ClickException(f"Ghidra could not write {destination}: {e}")


def _run_semgrep(config: str, corpus: Path, destination: Path) -> dict:
    """Scan the exported pseudocode, writing SARIF beside the corpus.

    A scan failure is reported but never invalidates the corpus: the pseudocode
    is the product, and the scan is a secondary view of it.
    """
    import subprocess

    command = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--sarif",
        "--sarif-output",
        str(destination),
        "--quiet",
        str(corpus / "functions"),
    ]
    click.echo(f"Scanning pseudocode with semgrep --config {config}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise click.ClickException(
            "semgrep is not installed. Install it with: pip install semgrep"
        )
    if not destination.is_file():
        raise click.ClickException(
            f"semgrep produced no SARIF output (exit {result.returncode}):\n"
            f"{result.stderr.strip()}"
        )
    return {"config": config, "exit_code": result.returncode}


def _run_analysis(program, flat_api) -> None:
    """Run Ghidra's auto-analysis on the program."""
    click.echo("Running auto-analysis...")
    success = False
    tid = program.startTransaction("Auto-analysis")
    try:
        flat_api.analyzeAll(program)
        success = True
    finally:
        program.endTransaction(tid, success)


def compile_filters(
    include: tuple[str, ...] | None, exclude: tuple[str, ...] | None
) -> tuple[list[re.Pattern], list[re.Pattern]]:
    """Compile name filters, reporting a bad pattern as a usage error."""
    compiled = []
    for option, patterns in (("--include", include), ("--exclude", exclude)):
        collected = []
        for pattern in patterns or ():
            try:
                collected.append(re.compile(pattern))
            except re.error as error:
                raise click.BadParameter(
                    f"Invalid regular expression {pattern!r}: {error}",
                    param_hint=f"'{option}'",
                )
        compiled.append(collected)
    return compiled[0], compiled[1]


def _selected_by_name(
    name: str, include: list[re.Pattern], exclude: list[re.Pattern]
) -> bool:
    """Apply include-then-exclude semantics to one function name."""
    if include and not any(pattern.search(name) for pattern in include):
        return False
    return not any(pattern.search(name) for pattern in exclude)


def select_functions(
    functions: list,
    *,
    include: list[re.Pattern] | None = None,
    exclude: list[re.Pattern] | None = None,
    addresses: set[str] | None = None,
) -> list:
    """Narrow the discovered functions to those the run asked for.

    With no filters every function is kept. `--function` is a union with the
    name filters: an explicitly named address is always exported.
    """
    include = include or []
    exclude = exclude or []
    addresses = addresses or set()
    if not include and not exclude and not addresses:
        return list(functions)

    selected = []
    for func in functions:
        address = func.getEntryPoint().toString()
        if address in addresses or _selected_by_name(func.getName(), include, exclude):
            selected.append(func)
    return selected


def default_workers() -> int:
    """Choose a conservative worker count.

    JVM heap, not CPU count, is the binding constraint on a large binary, so
    this deliberately does not scale with every available core.
    """
    return min(4, os.cpu_count() or 1)


def _decompile_one(
    decomp, monitor, func, timeout: int
) -> tuple[str, str | None, str, list[dict]]:
    """Decompile one function: outcome, error, C output, and its locals.

    Locals are converted to plain dicts here rather than returned as Ghidra
    objects, because the decompilation result belongs to the worker that
    produced it and must not outlive this call.
    """
    try:
        result = decomp.decompileFunction(func, timeout, monitor)
    except Exception as e:  # noqa: BLE001 - isolate function failures
        return STATUS_FAILED, f"exception: {e}", "", []

    locals_ = _high_function_locals(result)

    if result and result.decompileCompleted():
        decomp_func = result.getDecompiledFunction()
        c_code = decomp_func.getC() if decomp_func else None
        if c_code:
            return STATUS_SUCCESS, None, str(c_code), locals_
        return STATUS_FALLBACK, "decompiler returned no C output", "", locals_

    error = (
        result.getErrorMessage() if result is not None else None
    ) or "decompilation did not complete"
    # A decompiler that ran out of time did not decline the function; it is
    # retryable and must not be reported as a settled fallback.
    status = STATUS_FAILED if _is_timeout_error(error) else STATUS_FALLBACK
    return status, str(error), "", locals_


def _decompile_functions(
    program, functions: list, timeout: int, workers: int
) -> dict[str, tuple[str, str | None, str, list[dict]]]:
    """Decompile every function, keyed by entry address.

    Each worker owns one `DecompInterface`; an interface is never shared across
    threads. Results are collected into a mapping so the caller can write them
    back in address order, keeping output independent of completion order.
    """
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    local = threading.local()
    opened: list = []
    opened_lock = threading.Lock()

    def interface():
        existing = getattr(local, "decomp", None)
        if existing is None:
            existing = DecompInterface()
            existing.openProgram(program)
            local.decomp = existing
            local.monitor = ConsoleTaskMonitor()
            with opened_lock:
                opened.append(existing)
        return existing, local.monitor

    def work(func):
        decomp, monitor = interface()
        return (
            func.getEntryPoint().toString(),
            _decompile_one(decomp, monitor, func, timeout),
        )

    results: dict[str, tuple[str, str | None, str, list[dict]]] = {}
    try:
        if workers <= 1:
            with click.progressbar(
                functions, label="Decompiling", show_pos=True
            ) as bar:
                for func in bar:
                    address, outcome = work(func)
                    results[address] = outcome
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                pending = [pool.submit(work, func) for func in functions]
                with click.progressbar(
                    length=len(pending), label="Decompiling", show_pos=True
                ) as bar:
                    for future in as_completed(pending):
                        address, outcome = future.result()
                        results[address] = outcome
                        bar.update(1)
    finally:
        for decomp in opened:
            decomp.dispose()
    return results


def _export_all(
    program,
    input_identity: dict,
    output: Path,
    timeout: int,
    *,
    combined: bool = False,
    requested_analysis: dict,
    request_fingerprint: dict,
    pyghidra_version: str,
    workers: int = 1,
    filters: dict,
    gzf: bool = False,
    semgrep_config: str | None = None,
    resume_index: dict[str, dict] | None = None,
    resume_source: Path | None = None,
) -> None:
    """Run all exports against an open Ghidra program."""
    from ghidra.framework import Application

    func_dir = output / "functions"
    assembly_dir = output / "assembly"
    for artifact_dir in (func_dir, assembly_dir):
        artifact_dir.mkdir()

    fm = program.getFunctionManager()
    discovered = list(fm.getFunctions(True))
    include, exclude = compile_filters(filters.get("include"), filters.get("exclude"))
    functions = select_functions(
        discovered,
        include=include,
        exclude=exclude,
        addresses=set(filters.get("function") or ()),
    )
    total = len(functions)
    if total != len(discovered):
        click.echo(f"Filtered to {total} of {len(discovered)} discovered functions")
    strings = _extract_strings(program)
    imports = _extract_imports(program)
    exports = _extract_exports(program)
    symbols = _extract_symbols(program)
    types = _extract_types(program)
    sections = _extract_sections(program)
    string_addresses = {item["address"]: item for item in strings}
    symbol_addresses: dict[str, list[dict]] = {}
    for item in symbols:
        symbol_addresses.setdefault(item["address"], []).append(item)

    click.echo(f"Functions: {total}")
    reusable = resume_index or {}
    if reusable:
        click.echo(f"Reusable functions from the previous corpus: {len(reusable)}")
    records: list[dict] = []
    record_by_address: dict[str, dict] = {}

    pending = [
        func
        for func in functions
        if _artifact_stem(func.getEntryPoint().toString(), func.getName())
        not in reusable
    ]
    outcomes = _decompile_functions(program, pending, timeout, workers)

    # Writing artifacts and reading Ghidra metadata stay serial and in
    # address order, so the corpus is identical for any worker count.
    for func in functions:
        addr = func.getEntryPoint().toString()
        name = func.getName()
        stem = _artifact_stem(addr, name)
        c_path = func_dir / f"{stem}.c"
        assembly_path = assembly_dir / f"{stem}.s"

        reused = reusable.get(stem)
        if reused is not None and resume_source is not None:
            shutil.copyfile(resume_source / reused["artifacts"]["pseudocode"], c_path)
            shutil.copyfile(
                resume_source / reused["artifacts"]["assembly"], assembly_path
            )
            record = dict(reused)
            record["decompilation"] = {
                **record["decompilation"],
                "reused": True,
            }
            # Callers are rebuilt below from this run's call edges, so a
            # stale list must not survive into the new corpus.
            record["called_by"] = []
            records.append(record)
            record_by_address[addr] = record
            continue

        header = _func_header_comment(func)
        assembly = _disassemble_function(program, func)
        atomic_write_text(assembly_path, assembly)

        status: str
        error: str | None
        decompiled_locals: list[dict] = []
        notes: list[dict] = []
        if not assembly:
            # An empty body settles the outcome regardless of what the
            # decompiler reported for it.
            status = STATUS_FALLBACK
            error = "function contains no instructions"
            content = header + _failure_comment(error)
        else:
            status, error, c_code, decompiled_locals = outcomes[addr]
            notes = _decompiler_notes(c_code)
            if status == STATUS_SUCCESS:
                content = header + c_code
            else:
                if status == STATUS_FAILED:
                    click.echo(
                        f"\nWarning: could not decompile {name} at {addr}: {error}",
                        err=True,
                    )
                content = header + _failure_comment(error)

        atomic_write_text(c_path, content)
        references, calls = _extract_function_references(program, func)
        # An empty list means the decompiler produced no variables — for a failed
        # or empty function that is not an answer, so fall back to Ghidra's view
        # rather than discarding what it does know.
        record = _extract_function_record(
            program, func, locals_=decompiled_locals or None
        )
        related_strings = {
            ref["to_address"]: string_addresses[ref["to_address"]]
            for ref in references
            if ref["to_address"] in string_addresses
        }
        related_globals = {
            (
                symbol["address"],
                symbol["name"],
                symbol["namespace"],
                symbol["type"],
            ): symbol
            for ref in references
            for symbol in symbol_addresses.get(ref["to_address"], ())
        }
        record.update(
            {
                "schema_version": SCHEMA_VERSION,
                "calls": calls,
                "called_by": [],
                "references": references,
                "strings": list(related_strings.values()),
                "globals": list(related_globals.values()),
                "artifacts": {
                    "pseudocode": str(c_path.relative_to(output)),
                    "pseudocode_sha256": sha256_file(c_path),
                    "assembly": str(assembly_path.relative_to(output)),
                    "assembly_sha256": sha256_file(assembly_path),
                },
                "decompilation": {
                    "status": status,
                    "error": error,
                    "reused": False,
                    "warnings": notes,
                },
            }
        )
        records.append(record)
        record_by_address[addr] = record

    for caller in records:
        for call in caller["calls"]:
            target = record_by_address.get(
                call["target_function_address"] or call["target_address"]
            )
            if target is not None:
                target["called_by"].append(
                    {
                        "call_site": call["call_site"],
                        "address": caller["address"],
                        "name": caller["name"],
                        "reference_type": call["reference_type"],
                    }
                )

    for record in records:
        record["called_by"] = list(
            {
                (
                    item["call_site"],
                    item["address"],
                    item["reference_type"],
                ): item
                for item in record["called_by"]
            }.values()
        )

    for record in records:
        sidecar_path = (
            output
            / "functions"
            / (f"{_artifact_stem(record['address'], record['name'])}.json")
        )
        record["artifacts"]["sidecar"] = str(sidecar_path.relative_to(output))
        atomic_write_json(sidecar_path, record)
        record["artifacts"]["sidecar_sha256"] = sha256_file(sidecar_path)

    combined_path = output / "all_functions.c"
    separator = "\n" + ("/" * 80) + "\n\n"
    if combined:

        def combined_chunks():
            for index, record in enumerate(records):
                if index:
                    yield separator
                yield (output / record["artifacts"]["pseudocode"]).read_text(
                    encoding="utf-8"
                )

        atomic_write_chunks(combined_path, combined_chunks())
    elif combined_path.exists():
        combined_path.unlink()

    lang = program.getLanguage()
    counts = _summarize_statuses(records)
    metadata = {
        "binary": input_identity["path"],
        "format": program.getExecutableFormat(),
        "architecture": lang.getProcessor().toString(),
        "endian": lang.isBigEndian() and "big" or "little",
        "address_size": lang.getDefaultSpace().getSize(),
        "image_base": program.getImageBase().toString(),
        "num_functions": total,
        "num_successful": counts["successful"],
        "num_fallback": counts["fallback"],
        "num_failed": counts["failed"],
        "num_skipped": counts["skipped"],
        "fallback_functions": _addresses_with_status(records, STATUS_FALLBACK),
        "failed_functions": _addresses_with_status(records, STATUS_FAILED),
        "counts": counts,
    }
    callgraph = {
        record["address"]: {
            "name": record["name"],
            "address": record["address"],
            "calls": record["calls"],
            "called_by": record["called_by"],
        }
        for record in records
    }
    xrefs = [ref for record in records for ref in record["references"]]
    xrefs.extend(_extract_unowned_references(program, xrefs))

    indexes = {
        "types.json": types,
        "functions.json": records,
        "callgraph.json": callgraph,
        "strings.json": strings,
        "imports.json": imports,
        "exports.json": exports,
        "symbols.json": symbols,
        "sections.json": sections,
        "metadata.json": metadata,
    }
    for name, data in indexes.items():
        atomic_write_json(output / name, data)
    atomic_write_chunks(
        output / "xrefs.jsonl",
        (json_line(ref) for ref in xrefs),
    )

    ghidra_version = str(Application.getApplicationVersion())
    actual_analysis = {
        **requested_analysis,
        "language_id": str(program.getLanguageID()),
        "compiler_id": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": program.getImageBase().toString(),
        "loader": program.getExecutableFormat(),
        "entry_points": _extract_entry_points(program),
        "ghidra_version": ghidra_version,
        "pyghidra_version": pyghidra_version,
        "exporter_version": __version__,
    }
    indexed_paths = [output / name for name in indexes] + [output / "xrefs.jsonl"]
    if combined:
        indexed_paths.append(combined_path)

    secondary: dict = {}
    if gzf:
        gzf_path = output / "program.gzf"
        _export_gzf(program, gzf_path)
        indexed_paths.append(gzf_path)
        secondary["gzf"] = str(gzf_path.relative_to(output))
    if semgrep_config:
        sarif_path = output / "semgrep.sarif"
        secondary["semgrep"] = {
            **_run_semgrep(semgrep_config, output, sarif_path),
            "path": str(sarif_path.relative_to(output)),
        }
        indexed_paths.append(sarif_path)
    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "fingerprints": {
            "request": request_fingerprint,
            "resolved": build_fingerprint(input_identity, actual_analysis),
        },
        "input": input_identity,
        "tool": {
            "name": "ghidra-decomp",
            "version": __version__,
            "pyghidra_version": pyghidra_version,
            "ghidra_version": ghidra_version,
        },
        "analysis": actual_analysis,
        "export": {
            "timeout": timeout,
            "workers": workers,
            "combined": combined,
            "resumed": bool(reusable),
            "filters": normalize_filters(filters),
            "discovered_before_filters": len(discovered),
            "secondary_products": secondary,
        },
        "counts": counts,
        "indexes": {
            str(path.relative_to(output)): {
                "path": str(path.relative_to(output)),
                "sha256": sha256_file(path),
            }
            for path in indexed_paths
        },
    }
    run_state_path = output / ".run-state.json"
    run_state_path.unlink()
    fsync_tree(output)
    atomic_write_json(output / "manifest.json", manifest)

    click.echo(
        f"Wrote {counts['successful']} functions, "
        f"{counts['fallback']} fallback, "
        f"{counts['failed']} failed, "
        f"{len(strings)} strings, "
        f"{len(imports)} imports, "
        f"{len(exports)} exports, "
        f"{len(symbols)} symbols, "
        f"{len(sections)} sections"
    )


def _disassemble_function(program, func) -> str:
    """Return addressed assembly with raw instruction bytes."""
    listing = program.getListing()
    lines = []
    for instr in listing.getInstructions(func.getBody(), True):
        addr = instr.getAddress()
        raw_bytes = " ".join(f"{int(value) & 0xFF:02x}" for value in instr.getBytes())
        mnemonic = instr.getMnemonicString()
        num_ops = instr.getNumOperands()
        operands = ", ".join(
            instr.getDefaultOperandRepresentation(i) for i in range(num_ops)
        )
        lines.append(f"{addr}:  {raw_bytes:<24}  {mnemonic:<10} {operands}\n")
    return "".join(lines)


def _extract_function_references(program, func) -> tuple[list[dict], list[dict]]:
    """Extract code/data references originating in a function body."""
    ref_manager = program.getReferenceManager()
    references = []
    calls = []
    seen = set()

    for source_address in ref_manager.getReferenceSourceIterator(func.getBody(), True):
        for ref in ref_manager.getReferencesFrom(source_address):
            from_address = ref.getFromAddress().toString()
            to_address = ref.getToAddress().toString()
            ref_type = ref.getReferenceType()
            key = (from_address, to_address, str(ref_type), ref.getOperandIndex())
            if key in seen:
                continue
            seen.add(key)
            item = _reference_record(program, ref, func)
            references.append(item)
            if ref_type.isCall():
                calls.append(
                    {
                        "call_site": from_address,
                        "target_address": to_address,
                        "target_function_address": item["target_function_address"],
                        "target_name": item["target_function_name"],
                        "reference_type": item["reference_type"],
                        # Compatibility aliases for the original callgraph schema.
                        "address": item["target_function_address"] or to_address,
                        "name": item["target_function_name"],
                    }
                )

    return references, calls


def _reference_record(program, ref, func=None) -> dict:
    """Normalize a Ghidra reference for sidecars and the global index."""
    fm = program.getFunctionManager()
    target = fm.getFunctionAt(ref.getToAddress())
    if target is None:
        target = fm.getFunctionContaining(ref.getToAddress())
    return {
        "from_address": ref.getFromAddress().toString(),
        "to_address": ref.getToAddress().toString(),
        "function_address": func.getEntryPoint().toString() if func else None,
        "function_name": func.getName() if func else None,
        "reference_type": str(ref.getReferenceType()),
        "operand_index": ref.getOperandIndex(),
        "source": str(ref.getSource()),
        "is_primary": ref.isPrimary(),
        "target_function_address": target.getEntryPoint().toString()
        if target
        else None,
        "target_function_name": target.getName() if target else None,
    }


def _extract_unowned_references(program, owned_references: list[dict]) -> list[dict]:
    """Return program references not already represented by function sidecars."""
    min_address = program.getMinAddress()
    if min_address is None:
        return []
    owned = {
        (
            item["from_address"],
            item["to_address"],
            item["reference_type"],
            item["operand_index"],
        )
        for item in owned_references
    }
    result = []
    fm = program.getFunctionManager()
    for ref in program.getReferenceManager().getReferenceIterator(min_address):
        key = (
            ref.getFromAddress().toString(),
            ref.getToAddress().toString(),
            str(ref.getReferenceType()),
            ref.getOperandIndex(),
        )
        if key in owned:
            continue
        func = fm.getFunctionContaining(ref.getFromAddress())
        result.append(_reference_record(program, ref, func))
    return result


def _body_ranges(body) -> list[dict[str, str]]:
    """Represent all ranges in a potentially non-contiguous function body."""
    return [
        {
            "start": address_range.getMinAddress().toString(),
            "end": address_range.getMaxAddress().toString(),
        }
        for address_range in body.getAddressRanges(True)
    ]


def _storage_record(storage) -> dict:
    """Classify where a variable lives, identically for every variable kind."""
    storage_kind = "unassigned"
    register = None
    stack_offset = None
    if storage is not None and not storage.isUnassignedStorage():
        if storage.isStackStorage():
            storage_kind = "stack"
            stack_offset = storage.getStackOffset()
        elif storage.isRegisterStorage():
            storage_kind = "register"
            storage_register = storage.getRegister()
            register = storage_register.getName() if storage_register else None
        elif storage.isMemoryStorage():
            storage_kind = "memory"
        else:
            storage_kind = "compound"

    return {
        "kind": storage_kind,
        "register": register,
        "stack_offset": stack_offset,
        "description": str(storage) if storage is not None else None,
    }


def _high_local_record(symbol) -> dict:
    """Extract one local variable as the decompiler actually modelled it.

    `Function.getLocalVariables()` only reports variables Ghidra materialized on
    the function object, which is empty for most functions. The decompiler's own
    symbol map holds the variables the pseudocode actually names, so this is what
    lets a consumer type the `uVar1` it reads in the C.

    `source` has no equivalent here; the key is kept as null so both variable
    kinds serialize to one shape.
    """
    data_type = symbol.getDataType()
    return {
        "name": symbol.getName(),
        "data_type": data_type.getName() if data_type else "undefined",
        "size": symbol.getSize(),
        "storage": _storage_record(symbol.getStorage()),
        "source": None,
    }


def _high_function_locals(result) -> list[dict]:
    """Collect the decompiler's local variables from a decompilation result.

    Returns an empty list when no high function is available, which is the
    normal outcome for a function that failed or was declined.
    """
    if result is None:
        return []
    high_function = result.getHighFunction()
    if high_function is None:
        return []
    symbol_map = high_function.getLocalSymbolMap()
    if symbol_map is None:
        return []
    return [
        _high_local_record(symbol)
        for symbol in symbol_map.getSymbols()
        # Parameters keep coming from the function object, which carries their
        # ordinal and provenance.
        if not symbol.isParameter()
    ]


def _variable_record(variable) -> dict:
    """Extract a variable's type, storage, size, and provenance."""
    data_type = variable.getDataType()
    storage = variable.getVariableStorage()

    return {
        "name": variable.getName(),
        "data_type": data_type.getName() if data_type else "undefined",
        "size": variable.getLength(),
        "storage": _storage_record(storage),
        "source": str(variable.getSource()),
    }


def _symbols_at(program, address) -> list[dict]:
    """Return every symbol at an address, retaining primary/alias identity."""
    return [
        {
            "name": symbol.getName(),
            "namespace": symbol.getParentNamespace().getName(True),
            "type": symbol.getSymbolType().toString(),
            "is_primary": symbol.isPrimary(),
        }
        for symbol in program.getSymbolTable().getSymbols(address)
    ]


def _function_aliases(function_name: str, symbols: list[dict]) -> list[str]:
    """Return unique alias names, retaining non-primary same-name symbols."""
    return list(
        dict.fromkeys(
            item["name"]
            for item in symbols
            if not item["is_primary"] or item["name"] != function_name
        )
    )


def _extract_function_record(
    program, func, *, locals_: list[dict] | None = None
) -> dict:
    """Build stable function identity, body, signature, and storage metadata."""
    body = func.getBody()
    return_type = func.getReturnType()
    parameters = []
    for parameter in func.getParameters():
        item = _variable_record(parameter)
        item["ordinal"] = parameter.getOrdinal()
        parameters.append(item)

    ranges = _body_ranges(body)
    stack_frame = func.getStackFrame()
    function_symbols = _symbols_at(program, func.getEntryPoint())
    record = {
        "name": func.getName(),
        "address": func.getEntryPoint().toString(),
        "symbols": function_symbols,
        "aliases": _function_aliases(func.getName(), function_symbols),
        "body_ranges": ranges,
        "size": body.getNumAddresses(),
        "signature": {
            "return_type": return_type.getName() if return_type else "void",
            "calling_convention": func.getCallingConventionName() or "unknown",
            "source": str(func.getSignatureSource()),
            "parameters": parameters,
            # The decompiler's own variables when the function was decompiled
            # this run. Ghidra's function object is the fallback, and reports
            # nothing at all for most functions.
            "locals": (
                list(locals_)
                if locals_ is not None
                else [
                    _variable_record(variable) for variable in func.getLocalVariables()
                ]
            ),
        },
        "is_thunk": func.isThunk(),
        "thunk": _thunk_target(func),
        "stack_frame": {
            "frame_size": stack_frame.getFrameSize(),
            "local_size": stack_frame.getLocalSize(),
            "parameter_offset": stack_frame.getParameterOffset(),
            "return_address_offset": stack_frame.getReturnAddressOffset(),
        },
    }
    # Retain the original flat signature fields for existing corpus consumers.
    record.update(
        {
            "end_address": ranges[-1]["end"] if ranges else record["address"],
            "return_type": record["signature"]["return_type"],
            "params": [
                {"type": item["data_type"], "name": item["name"]} for item in parameters
            ],
            "calling_convention": record["signature"]["calling_convention"],
        }
    )
    return record


def json_line(data: dict) -> str:
    """Serialize one deterministic JSON Lines record."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n"


def _extract_strings(program) -> list[dict]:
    """Extract all defined strings with their xrefs."""
    from ghidra.program.model.data import AbstractStringDataType

    ref_manager = program.getReferenceManager()
    fm = program.getFunctionManager()
    listing = program.getListing()
    strings = []

    for data in listing.getDefinedData(True):
        dt = data.getDataType()
        value = data.getValue()
        # DWARF commonly materializes literals as char arrays whose value is already
        # decoded even though their datatype is not AbstractStringDataType.
        if value is None or (
            not isinstance(dt, AbstractStringDataType) and not isinstance(value, str)
        ):
            continue
        addr = data.getAddress()
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="replace")
        else:
            value = str(value)

        # Find xrefs to this string
        xrefs = []
        for ref in ref_manager.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            func = fm.getFunctionContaining(from_addr)
            xrefs.append(
                {
                    "from_address": from_addr.toString(),
                    "function": func.getName() if func else None,
                    "function_address": func.getEntryPoint().toString()
                    if func
                    else None,
                }
            )

        strings.append(
            {
                "address": addr.toString(),
                "value": value,
                "length": data.getLength(),
                "xrefs": xrefs,
            }
        )

    return strings


def _extract_imports(program) -> list[dict]:
    """Extract imported (external) functions."""
    fm = program.getFunctionManager()
    imports = []

    for func in fm.getExternalFunctions():
        ext_loc = func.getExternalLocation()
        external_address = ext_loc.getAddress() if ext_loc else None
        linkage_addresses = func.getFunctionThunkAddresses(True) or ()
        imports.append(
            {
                "name": func.getName(),
                "library": ext_loc.getLibraryName() if ext_loc else None,
                "address": func.getEntryPoint().toString(),
                "external_address": external_address.toString()
                if external_address
                else None,
                "linkage_addresses": sorted(
                    address.toString() for address in linkage_addresses
                ),
            }
        )

    return imports


def _extract_exports(program) -> list[dict]:
    """Extract one primary or global symbol for each exported entry point."""
    symbol_table = program.getSymbolTable()
    exports: dict[str, tuple[bool, bool, dict]] = {}

    for symbol in symbol_table.getAllSymbols(True):
        if not symbol.isExternalEntryPoint():
            continue

        address = symbol.getAddress().toString()
        namespace = symbol.getParentNamespace()
        candidate = (
            namespace.isGlobal(),
            symbol.isPrimary(),
            {
                "name": symbol.getName(),
                "address": address,
                "namespace": namespace.getName(True),
                "is_primary": symbol.isPrimary(),
            },
        )
        current = exports.get(address)
        if current is None or candidate[:2] > current[:2]:
            exports[address] = candidate

    return [candidate[2] for candidate in exports.values()]


def _extract_entry_points(program) -> list[str]:
    """Return exported addresses that resolve to code or a function entry."""
    fm = program.getFunctionManager()
    memory = program.getMemory()
    addresses = set()
    for item in _extract_exports(program):
        address = program.getAddressFactory().getAddress(item["address"])
        block = memory.getBlock(address) if address is not None else None
        if address is not None and (
            fm.getFunctionAt(address) is not None
            or (block is not None and block.isExecute())
        ):
            addresses.add(item["address"])
    return sorted(addresses)


def _extract_symbols(program) -> list[dict]:
    """Extract non-function symbols: globals, labels, data."""
    from ghidra.program.model.symbol import SymbolType

    symbol_table = program.getSymbolTable()
    listing = program.getListing()
    skip_types = {SymbolType.FUNCTION, SymbolType.PARAMETER, SymbolType.LOCAL_VAR}
    symbols = []

    for symbol in symbol_table.getAllSymbols(True):
        sym_type = symbol.getSymbolType()
        if sym_type in skip_types:
            continue
        if symbol.isExternal():
            continue

        addr = symbol.getAddress()
        entry = {
            "name": symbol.getName(),
            "address": addr.toString(),
            "type": sym_type.toString(),
            "namespace": symbol.getParentNamespace().getName(True),
            "is_primary": symbol.isPrimary(),
        }

        # Try to get data type and size for data symbols
        data = listing.getDataAt(addr)
        if data is not None:
            dt = data.getDataType()
            entry["data_type"] = dt.getName() if dt else None
            entry["size"] = data.getLength()

        symbols.append(entry)

    return symbols


def _category_path(dt) -> str:
    """Report where the type manager filed this type.

    A type Ghidra guessed off the binary sits in the program's own categories,
    while one recovered from DWARF or imported from an archive carries that
    origin in its path. Without it a consumer cannot tell evidence from a guess.
    The root category serializes as "/", so this is never empty.
    """
    category = dt.getCategoryPath()
    if category is None:
        return "/"
    return category.getPath()


def _alignment_record(dt, composite) -> dict:
    """Report how the type is aligned.

    `value` is the effective alignment and applies to every kind. How Ghidra
    arrived at it is a question only a composite can answer, so the remaining
    keys are null elsewhere rather than absent.
    """
    record: dict = {"value": dt.getAlignment(), "type": None, "minimum": None}
    if composite is None:
        return record
    record["type"] = str(composite.getAlignmentType())
    if composite.hasExplicitMinimumAlignment():
        record["minimum"] = composite.getExplicitMinimumAlignment()
    return record


def _packing_record(composite) -> dict | None:
    """Report how a composite's members are packed.

    Returns None for a type with no members to pack. `value` is filled only for
    explicit packing, because that is the only case where a number was chosen
    rather than derived.
    """
    if composite is None:
        return None
    record: dict = {"type": str(composite.getPackingType()), "value": None}
    if composite.hasExplicitPackingValue():
        record["value"] = composite.getExplicitPackingValue()
    return record


def _source_archive_record(dt) -> dict | None:
    """Report where the type came from.

    `archive_type` is the provenance answer: PROGRAM means Ghidra recovered the
    type from this binary, while FILE or PROJECT means it was imported and its
    layout is exactly as trustworthy as the archive it came from.
    """
    archive = dt.getSourceArchive()
    if archive is None:
        return None
    return {"name": archive.getName(), "archive_type": str(archive.getArchiveType())}


def _referenced_data_types(declared) -> list[tuple]:
    """Every type a declaration reaches, paired with the declaration itself.

    A global declared `Point *` is a use of `Point`; without unwrapping the
    pointer, the struct would report no users at all. `via` keeps the outer
    declaration, so a pointer use stays distinguishable from a direct one.

    Only wrappers are unwrapped, so the walk terminates at the first real type
    and a self-referencing struct cannot loop.
    """
    from ghidra.program.model.data import Array, Pointer, TypeDef

    if declared is None:
        return []

    via = declared.getName()
    reached: list[tuple] = []
    seen: set[str] = set()
    current = declared
    while current is not None:
        path = current.getPathName()
        if path in seen:
            break
        seen.add(path)
        reached.append((current, via))
        if not isinstance(current, (Pointer, Array, TypeDef)):
            break
        current = current.getDataType()
    return reached


def _type_usage_index(program) -> dict[str, list[dict]]:
    """Map every type to the data and functions that use it.

    Without this a type record is a dead end: a consumer can read a struct's
    layout but has no way to reach the code that touches it. The index covers
    the whole program rather than the exported subset, the way `symbols.json`
    and `strings.json` already do, so a filtered export still describes the
    binary rather than the filter.
    """
    usage: dict[str, list[dict]] = {}

    def record(declared, entry: dict) -> None:
        for dt, via in _referenced_data_types(declared):
            usage.setdefault(dt.getPathName(), []).append({**entry, "via": via})

    for data in program.getListing().getDefinedData(True):
        record(
            data.getDataType(),
            {
                "kind": "data",
                "address": data.getAddress().toString(),
                "name": data.getLabel(),
                "ordinal": None,
            },
        )

    for func in program.getFunctionManager().getFunctions(True):
        entry = {
            "kind": "function_return",
            "address": func.getEntryPoint().toString(),
            "name": func.getName(),
            "ordinal": None,
        }
        record(func.getReturnType(), entry)
        for parameter in func.getParameters():
            record(
                parameter.getDataType(),
                {
                    **entry,
                    "kind": "function_parameter",
                    "ordinal": parameter.getOrdinal(),
                },
            )

    return usage


def _type_usage(entries: list[dict]) -> dict:
    """Bound the recorded user list without hiding how large it really is.

    `types.json` is read whole, and a type like an error struct or a callback
    signature can be used thousands of times. `usage_count` always reports the
    true total, so a truncated list never reads as a small one.
    """
    ordered = sorted(
        entries,
        key=lambda entry: (
            entry["kind"],
            entry["address"],
            -1 if entry["ordinal"] is None else entry["ordinal"],
            entry["via"] or "",
        ),
    )
    return {
        "usage_count": len(ordered),
        "usage_truncated": len(ordered) > TYPE_USAGE_LIMIT,
        "used_by": ordered[:TYPE_USAGE_LIMIT],
    }


def _extract_types(program) -> list[dict]:
    """Extract all recovered types (structs, enums, typedefs, unions, function pointers).

    Every record states where the type came from, how it is laid out, and who
    uses it, so a consumer can decide whether a field layout is evidence or a
    guess before relying on it.
    """
    dtm = program.getDataTypeManager()

    from ghidra.program.model.data import (
        BuiltInDataType,
        Composite,
        Enum,
        FunctionDefinition,
        Structure,
        TypeDef,
        Union,
    )

    usage = _type_usage_index(program)
    result = []

    for dt in dtm.getAllDataTypes():
        # Ghidra's own primitives are not findings about this binary. Matching
        # the type instead of a list of names means a program structure named
        # `string` or `int` is no longer silently dropped along with them.
        if isinstance(dt, BuiltInDataType):
            continue

        if isinstance(dt, Structure):
            specific = {
                "kind": "struct",
                "size": dt.getLength(),
                "fields": [
                    {
                        "name": comp.getFieldName() or f"field_0x{comp.getOffset():x}",
                        "type": comp.getDataType().getName(),
                        "offset": comp.getOffset(),
                        "size": comp.getLength(),
                    }
                    for comp in dt.getComponents()
                ],
            }

        elif isinstance(dt, Union):
            specific = {
                "kind": "union",
                "size": dt.getLength(),
                "fields": [
                    {
                        "name": comp.getFieldName() or f"field_{comp.getOrdinal()}",
                        "type": comp.getDataType().getName(),
                        "size": comp.getLength(),
                    }
                    for comp in dt.getComponents()
                ],
            }

        elif isinstance(dt, Enum):
            specific = {
                "kind": "enum",
                "size": dt.getLength(),
                "members": {name: dt.getValue(name) for name in dt.getNames()},
            }

        elif isinstance(dt, TypeDef):
            base = dt.getBaseDataType()
            specific = {
                "kind": "typedef",
                "base_type": base.getName() if base else "unknown",
            }

        elif isinstance(dt, FunctionDefinition):
            ret = dt.getReturnType()
            specific = {
                "kind": "function_pointer",
                "return_type": ret.getName() if ret else "void",
                "params": [
                    {"type": arg.getDataType().getName(), "name": arg.getName()}
                    for arg in dt.getArguments()
                ],
            }

        else:
            continue

        path = dt.getPathName()
        composite = dt if isinstance(dt, Composite) else None
        result.append(
            {
                **specific,
                "name": dt.getName(),
                "path": path,
                "category_path": _category_path(dt),
                "alignment": _alignment_record(dt, composite),
                "packing": _packing_record(composite),
                "source_archive": _source_archive_record(dt),
                **_type_usage(usage.get(path, [])),
            }
        )

    # `getAllDataTypes()` has no documented ordering, so sort rather than trust
    # it: the types.json hash recorded in the manifest has to be reproducible.
    result.sort(key=lambda record: record["path"])
    return result


def _extract_sections(program) -> list[dict]:
    """Extract memory sections/segments with permissions."""
    memory = program.getMemory()
    sections = []

    for block in memory.getBlocks():
        sections.append(
            {
                "name": block.getName(),
                "start": block.getStart().toString(),
                "end": block.getEnd().toString(),
                "size": block.getSize(),
                "readable": block.isRead(),
                "writable": block.isWrite(),
                "executable": block.isExecute(),
                "volatile": block.isVolatile(),
                "initialized": block.isInitialized(),
                "type": block.getType().toString() if block.getType() else "DEFAULT",
                "source": block.getSourceName(),
            }
        )

    return sections
