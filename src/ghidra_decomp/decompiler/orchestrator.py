"""Top-level orchestration: _export_all and decompile_binary."""

from __future__ import annotations

import shutil
import tempfile
from contextlib import ExitStack
from pathlib import Path

import click

from ghidra_decomp import __version__
from ghidra_decomp.alloc_map import load_allocators
from ghidra_decomp.artifacts import (
    SCHEMA_VERSION,
    atomic_write_json,
    build_fingerprint,
    ensure_directory,
    publish_directory,
    recover_destination,
    sha256_file,
    snapshot_input,
    staging_lock,
    staging_prefix,
    validate_destination,
)
from ghidra_decomp.decompiler.constants import PROJECT_NAME
from ghidra_decomp.decompiler.export.artifacts import write_function_artifacts
from ghidra_decomp.decompiler.export.indexes import write_indexes_and_manifest
from ghidra_decomp.decompiler.naming import _artifact_stem
from ghidra_decomp.decompiler.setup.filters import (
    compile_filters,
    default_workers,
    select_functions,
)
from ghidra_decomp.decompiler.setup.ghidra import (
    _apply_gdts,
    _apply_pdb,
    _build_vm_args,
    _default_pdb_cache,
    _mark_entry,
    _rebase_program,
    _run_analysis,
    _start_pyghidra,
)
from ghidra_decomp.decompiler.setup.resume import load_resume_index
from ghidra_decomp.decompiler.worker import _decompile_functions


def _export_all(
    program,
    input_identity: dict,
    output: Path,
    timeout: int,
    *,
    combined: bool = False,
    pcode: bool = False,
    alloc_map: bool = False,
    struct_map: bool = False,
    dump_all_structs: bool = False,
    alloc_map_config: Path | None = None,
    requested_analysis: dict,
    request_fingerprint: dict,
    pyghidra_version: str,
    workers: int = 1,
    filters: dict,
    gzf: bool = False,
    semgrep_config: str | None = None,
    cpp_export: bool = False,
    mermaid: bool = False,
    callgraph_depth: int = 1,
    condense_threshold: int | None = None,
    reachable: tuple[str, str] | None = None,
    polish: bool = True,
    max_payload_mb: int | None = None,
    resume_index: dict[str, dict] | None = None,
    resume_source: Path | None = None,
) -> None:
    """Run all exports against an open Ghidra program."""
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

    allocators = load_allocators(alloc_map_config) if alloc_map else None

    click.echo(f"Functions: {total}")
    reusable = resume_index or {}
    if pcode and reusable:
        reusable = {
            stem: record
            for stem, record in reusable.items()
            if isinstance(record.get("artifacts", {}).get("pcode"), str)
        }
    if reusable:
        click.echo(f"Reusable functions from the previous corpus: {len(reusable)}")

    pending = [
        func
        for func in functions
        if _artifact_stem(func.getEntryPoint().toString(), func.getName())
        not in reusable
    ]
    outcomes = _decompile_functions(
        program,
        pending,
        timeout,
        workers,
        max_payload_mb=max_payload_mb,
        pcode=pcode,
        alloc_map=alloc_map,
        allocators=allocators,
    )

    records, _record_by_address, all_alloc_entries, wrapper_candidates = (
        write_function_artifacts(
            program,
            functions,
            output,
            outcomes,
            pcode=pcode,
            polish=polish,
            reusable=reusable,
            resume_source=resume_source,
        )
    )

    write_indexes_and_manifest(
        program,
        input_identity,
        output,
        timeout,
        records,
        all_alloc_entries,
        wrapper_candidates,
        combined=combined,
        pcode=pcode,
        alloc_map=alloc_map,
        struct_map=struct_map,
        dump_all_structs=dump_all_structs,
        alloc_map_config=alloc_map_config,
        requested_analysis=requested_analysis,
        request_fingerprint=request_fingerprint,
        pyghidra_version=pyghidra_version,
        workers=workers,
        filters=filters,
        gzf=gzf,
        semgrep_config=semgrep_config,
        cpp_export=cpp_export,
        mermaid=mermaid,
        callgraph_depth=callgraph_depth,
        condense_threshold=condense_threshold,
        reachable=reachable,
        max_payload_mb=max_payload_mb,
        reusable=reusable,
        discovered_count=len(discovered),
        total=total,
        allocators=allocators,
    )


def decompile_binary(
    binary: Path,
    output: Path,
    *,
    timeout: int = 60,
    combined: bool = False,
    pcode: bool = False,
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
    pdb: str | None = None,
    gzf: bool = False,
    semgrep_config: str | None = None,
    verbose_analysis: bool = False,
    mermaid: bool = False,
    max_ram_percent: float = 50.0,
    print_jvm_flags: bool = False,
    cpp_export: bool = False,
    callgraph_depth: int = 1,
    condense_threshold: int | None = None,
    reachable: tuple[str, str] | None = None,
    polish: bool = True,
    aggressive: bool = False,
    max_payload_mb: int | None = None,
    alloc_map: bool = False,
    struct_map: bool = False,
    alloc_map_config: Path | None = None,
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

    gdt_identity = []
    for raw in gdt or ():
        path = Path(raw).expanduser().resolve()
        if not path.is_file():
            raise click.BadParameter(
                f"Data type archive not found: {path}", param_hint="'--gdt'"
            )
        gdt_identity.append({"path": str(path), "sha256": sha256_file(path)})

    from ghidra_decomp.pdb import resolve_pdb_option

    pdb_resolved_path, _, pdb_identity_data = resolve_pdb_option(
        binary, pdb, _default_pdb_cache()
    )

    requested_analysis = {
        "base_address": base_addr,
        "entry_point": entry,
        "language": language,
        "compiler": compiler,
        "data_type_archives": gdt_identity,
        "pdb": pdb_identity_data,
        "aggressive": aggressive,
        "max_payload_mb": max_payload_mb,
    }
    filters = {"include": include, "exclude": exclude, "function": function}
    compile_filters(include, exclude)
    staging = Path(tempfile.mkdtemp(prefix=staging_prefix(output), dir=output.parent))
    with ExitStack() as run_stack:
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

            vm_args = _build_vm_args(max_ram_percent, print_jvm_flags)
            pyghidra = _start_pyghidra(ghidra_path, vm_args=vm_args)
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
                        f"Ghidra could not identify {binary.name}. Likely a raw "
                        "or unknown format.\nPass --language (and optionally "
                        "--compiler) to force a spec. Run with --list-languages "
                        "to discover IDs."
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

                if pdb_resolved_path is not None:
                    _apply_pdb(program, pdb_resolved_path)

                _run_analysis(
                    program,
                    flat_api,
                    verbose=verbose_analysis,
                    aggressive=aggressive,
                )
                _export_all(
                    program,
                    input_identity,
                    staging,
                    timeout,
                    combined=combined,
                    pcode=pcode,
                    alloc_map=alloc_map,
                    struct_map=struct_map,
                    dump_all_structs=struct_map and bool(gdt),
                    alloc_map_config=alloc_map_config,
                    requested_analysis=requested_analysis,
                    request_fingerprint=request_fingerprint,
                    pyghidra_version=pyghidra_version,
                    workers=(workers if workers is not None else default_workers()),
                    filters=filters,
                    gzf=gzf,
                    semgrep_config=semgrep_config,
                    cpp_export=cpp_export,
                    mermaid=mermaid,
                    callgraph_depth=callgraph_depth,
                    condense_threshold=condense_threshold,
                    reachable=reachable,
                    polish=polish,
                    max_payload_mb=max_payload_mb,
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
