"""Core decompilation logic using pyghidra."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import tempfile
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
    validate_destination,
)


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

    requested_analysis = {
        "base_address": base_addr,
        "entry_point": entry,
        "language": language,
        "compiler": compiler,
    }
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=output.parent)
    )
    try:
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
            open_kwargs: dict[str, object] = {
                "analyze": False,
                "project_location": str(project_dir),
                "project_name": "project",
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

                _run_analysis(program, flat_api)
                _export_all(
                    program,
                    input_identity,
                    staging,
                    timeout,
                    combined=combined,
                    requested_analysis=requested_analysis,
                    request_fingerprint=request_fingerprint,
                    pyghidra_version=getattr(pyghidra, "__version__", "unknown"),
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
    finally:
        if staging.exists():
            shutil.rmtree(staging)


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
) -> None:
    """Run all exports against an open Ghidra program."""
    from ghidra.app.decompiler import DecompInterface
    from ghidra.framework import Application
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    func_dir = output / "functions"
    assembly_dir = output / "assembly"
    for artifact_dir in (func_dir, assembly_dir):
        artifact_dir.mkdir()

    fm = program.getFunctionManager()
    functions = list(fm.getFunctions(True))
    total = len(functions)
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
    records: list[dict] = []
    record_by_address: dict[str, dict] = {}

    decomp = DecompInterface()
    try:
        decomp.openProgram(program)
        with click.progressbar(functions, label="Decompiling", show_pos=True) as bar:
            for func in bar:
                addr = func.getEntryPoint().toString()
                name = func.getName()
                stem = _artifact_stem(addr, name)
                c_path = func_dir / f"{stem}.c"
                assembly_path = assembly_dir / f"{stem}.s"
                header = _func_header_comment(func)
                assembly = _disassemble_function(program, func)
                atomic_write_text(assembly_path, assembly)

                status = "fallback"
                error = None
                if not assembly:
                    error = "function contains no instructions"
                    content = header + _failure_comment(error)
                else:
                    try:
                        result = decomp.decompileFunction(func, timeout, monitor)
                        if result and result.decompileCompleted():
                            decomp_func = result.getDecompiledFunction()
                            c_code = decomp_func.getC() if decomp_func else None
                            if c_code:
                                content = header + c_code
                                status = "success"
                            else:
                                error = "decompiler returned no C output"
                                content = header + _failure_comment(error)
                        else:
                            error = (
                                result.getErrorMessage() if result is not None else None
                            ) or "decompilation did not complete"
                            content = header + _failure_comment(error)
                    except Exception as e:  # noqa: BLE001 - isolate function failures
                        click.echo(
                            f"\nWarning: error decompiling {name} at {addr}: {e}",
                            err=True,
                        )
                        error = f"exception: {e}"
                        content = header + _failure_comment(error)

                atomic_write_text(c_path, content)
                references, calls = _extract_function_references(program, func)
                record = _extract_function_record(program, func)
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
                        "decompilation": {"status": status, "error": error},
                    }
                )
                records.append(record)
                record_by_address[addr] = record
    finally:
        decomp.dispose()

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
    fallback_count = sum(
        record["decompilation"]["status"] == "fallback" for record in records
    )
    counts = {
        "discovered": total,
        "successful": total - fallback_count,
        "fallback": fallback_count,
        "failed": 0,
        "skipped": 0,
    }
    metadata = {
        "binary": input_identity["path"],
        "format": program.getExecutableFormat(),
        "architecture": lang.getProcessor().toString(),
        "endian": lang.isBigEndian() and "big" or "little",
        "address_size": lang.getDefaultSpace().getSize(),
        "image_base": program.getImageBase().toString(),
        "num_functions": total,
        "num_successful": counts["successful"],
        "num_fallback": fallback_count,
        "num_failed": 0,
        "fallback_functions": [
            record["address"]
            for record in records
            if record["decompilation"]["status"] == "fallback"
        ],
        "failed_functions": [],
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
        "export": {"timeout": timeout, "workers": 1, "combined": combined},
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
        f"Wrote {total - fallback_count} functions, "
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


def _variable_record(variable) -> dict:
    """Extract a variable's type, storage, size, and provenance."""
    data_type = variable.getDataType()
    storage = variable.getVariableStorage()
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
        "name": variable.getName(),
        "data_type": data_type.getName() if data_type else "undefined",
        "size": variable.getLength(),
        "storage": {
            "kind": storage_kind,
            "register": register,
            "stack_offset": stack_offset,
            "description": str(storage) if storage is not None else None,
        },
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


def _extract_function_record(program, func) -> dict:
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
            "locals": [
                _variable_record(variable) for variable in func.getLocalVariables()
            ],
        },
        "is_thunk": func.isThunk(),
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
        if not isinstance(dt, AbstractStringDataType):
            continue

        addr = data.getAddress()
        value = data.getValue()
        if value is None:
            continue
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
    """Extract exported symbols (entry points)."""
    symbol_table = program.getSymbolTable()
    exports = []

    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint():
            exports.append(
                {
                    "name": symbol.getName(),
                    "address": symbol.getAddress().toString(),
                    "namespace": symbol.getParentNamespace().getName(True),
                    "is_primary": symbol.isPrimary(),
                }
            )

    return exports


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


def _extract_types(program) -> list[dict]:
    """Extract all recovered types (structs, enums, typedefs, unions, function pointers)."""
    dtm = program.getDataTypeManager()

    from ghidra.program.model.data import (
        Enum,
        FunctionDefinition,
        Structure,
        TypeDef,
        Union,
    )

    BUILTIN = {
        "byte",
        "word",
        "dword",
        "qword",
        "void",
        "bool",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "uchar",
        "ushort",
        "uint",
        "ulong",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
        "pointer",
        "string",
    }

    result = []

    for dt in dtm.getAllDataTypes():
        if dt.getName() in BUILTIN:
            continue

        if isinstance(dt, Structure):
            fields = []
            for comp in dt.getComponents():
                fields.append(
                    {
                        "name": comp.getFieldName() or f"field_0x{comp.getOffset():x}",
                        "type": comp.getDataType().getName(),
                        "offset": comp.getOffset(),
                        "size": comp.getLength(),
                    }
                )
            result.append(
                {
                    "kind": "struct",
                    "name": dt.getName(),
                    "size": dt.getLength(),
                    "fields": fields,
                }
            )

        elif isinstance(dt, Union):
            fields = []
            for comp in dt.getComponents():
                fields.append(
                    {
                        "name": comp.getFieldName() or f"field_{comp.getOrdinal()}",
                        "type": comp.getDataType().getName(),
                        "size": comp.getLength(),
                    }
                )
            result.append(
                {
                    "kind": "union",
                    "name": dt.getName(),
                    "size": dt.getLength(),
                    "fields": fields,
                }
            )

        elif isinstance(dt, Enum):
            members = {}
            for name in dt.getNames():
                members[name] = dt.getValue(name)
            result.append(
                {
                    "kind": "enum",
                    "name": dt.getName(),
                    "size": dt.getLength(),
                    "members": members,
                }
            )

        elif isinstance(dt, TypeDef):
            base = dt.getBaseDataType()
            result.append(
                {
                    "kind": "typedef",
                    "name": dt.getName(),
                    "base_type": base.getName() if base else "unknown",
                }
            )

        elif isinstance(dt, FunctionDefinition):
            params = []
            for arg in dt.getArguments():
                params.append(
                    {"type": arg.getDataType().getName(), "name": arg.getName()}
                )
            ret = dt.getReturnType()
            result.append(
                {
                    "kind": "function_pointer",
                    "name": dt.getName(),
                    "return_type": ret.getName() if ret else "void",
                    "params": params,
                }
            )

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
