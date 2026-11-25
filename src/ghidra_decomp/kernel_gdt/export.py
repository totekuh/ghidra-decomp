"""Stage 3+4: Parse with CParser and export .gdt archive."""

from __future__ import annotations

from pathlib import Path

import click

from .constants import KernelGdtError


def parse_and_export_gdt(
    preprocessed_path: Path,
    output_path: Path,
    ghidra_path: Path | None = None,
    max_ram_percent: float = 50.0,
) -> dict[str, int]:
    """Feed preprocessed C to Ghidra's CParser and export as .gdt.

    Uses CParserUtils.parseHeaderFiles which parses the header files and
    writes the result directly to a .gdt archive in one step.
    """
    import jpype

    from ..decompiler import _build_vm_args, _start_pyghidra

    vm_args = _build_vm_args(max_ram_percent=max_ram_percent)
    _start_pyghidra(ghidra_path, vm_args=vm_args)

    from ghidra.app.util.cparser.C import CParserUtils
    from ghidra.program.model.data import Enum as GhidraEnum
    from ghidra.program.model.data import Structure, Union
    from ghidra.util.task import ConsoleTaskMonitor

    output_path.parent.mkdir(parents=True, exist_ok=True)
    gdt_file = output_path.with_suffix(".gdt")
    if gdt_file.exists():
        gdt_file.unlink()

    click.echo(f"Parsing types and exporting to {gdt_file}...")

    monitor = ConsoleTaskMonitor()
    JString = jpype.JClass("java.lang.String")
    JStringArray = jpype.JArray(JString)
    DTMArray = jpype.JArray(jpype.JClass("ghidra.program.model.data.DataTypeManager"))

    filenames = JStringArray([str(preprocessed_path)])
    include_dirs = JStringArray([])
    open_archives = DTMArray([])

    try:
        fdtm = CParserUtils.parseHeaderFiles(
            open_archives, filenames, include_dirs, str(gdt_file), monitor
        )
    except Exception as exc:
        raise KernelGdtError(f"CParser failed: {exc}") from exc

    if fdtm is None:
        raise KernelGdtError("CParser returned no results")

    stats = {"types_count": 0, "structs": 0, "unions": 0, "enums": 0}
    try:
        for dt in fdtm.getAllDataTypes():
            stats["types_count"] += 1
            if isinstance(dt, Structure):
                stats["structs"] += 1
            elif isinstance(dt, Union):
                stats["unions"] += 1
            elif isinstance(dt, GhidraEnum):
                stats["enums"] += 1
        fdtm.save()
    finally:
        fdtm.close()

    return stats
