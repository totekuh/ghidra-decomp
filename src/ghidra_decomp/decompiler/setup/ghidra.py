"""JVM startup, program configuration, and analysis."""

from __future__ import annotations

from pathlib import Path

import click


def _build_vm_args(
    max_ram_percent: float = 50.0, print_jvm_flags: bool = False
) -> list[str]:
    """Build JVM arguments for the PyGhidra launcher."""
    args = [f"-XX:MaxRAMPercentage={max_ram_percent}"]
    if print_jvm_flags:
        args.append("-XX:+PrintFlagsFinal")
    return args


def _start_pyghidra(ghidra_path: Path | None, vm_args: list[str] | None = None):
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
            launcher = pyghidra.HeadlessPyGhidraLauncher(install_dir=ghidra_path)
            if vm_args:
                for arg in vm_args:
                    launcher.add_vmargs(arg)
            launcher.start()
        except Exception as e:  # noqa: BLE001 - Java exceptions have no stable base class
            hint = ""
            if not ghidra_path:
                hint = (
                    "\nSet GHIDRA_INSTALL_DIR or pass --ghidra-path "
                    "to your Ghidra installation."
                )
            raise click.ClickException(f"Failed to start Ghidra: {e}{hint}")
    elif vm_args:
        import logging

        logging.getLogger(__name__).warning(
            "JVM already started; --max-ram-percent and --print-jvm-flags ignored"
        )

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
    """Load archive data types into the program before analysis."""
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
        from ghidra_decomp.artifacts import sha256_file

        applied.append({"path": str(path), "sha256": sha256_file(path)})
    return applied


def _apply_pdb(program, pdb_path: Path) -> None:
    """Register a PDB so Ghidra's built-in analyzer applies it during analysis."""
    from java.io import File as JavaFile

    click.echo(f"Applying PDB: {pdb_path}")
    try:
        from ghidra.app.plugin.core.analysis import PdbUniversalAnalyzer

        PdbUniversalAnalyzer.setPdbFileOption(program, JavaFile(str(pdb_path)))
    except (ImportError, AttributeError):
        import shutil as _shutil

        snapshot_dir = Path(program.getExecutablePath()).parent
        target = snapshot_dir / pdb_path.name
        if not target.exists():
            _shutil.copy2(pdb_path, target)


def _default_pdb_cache() -> Path:
    """Return the PDB cache root under XDG_CACHE_HOME."""
    import os

    configured = os.environ.get("XDG_CACHE_HOME")
    root = Path(configured) if configured else Path.home() / ".cache"
    return root / "ghidra-decomp"


def _run_analysis(
    program, flat_api, *, verbose: bool = False, aggressive: bool = False
) -> None:
    """Run Ghidra's auto-analysis on the program."""
    click.echo("Running auto-analysis...")
    if verbose:
        from ghidra.program.flatapi import FlatProgramAPI
        from ghidra.util.task import ConsoleTaskMonitor

        flat_api = FlatProgramAPI(program, ConsoleTaskMonitor())
    success = False
    tid = program.startTransaction("Auto-analysis")
    try:
        if aggressive:
            from ghidra.program.model.listing import Program

            options = program.getOptions(Program.ANALYSIS_PROPERTIES)
            options.setBoolean("Decompiler Parameter ID", True)
        flat_api.analyzeAll(program)
        success = True
    finally:
        program.endTransaction(tid, success)
