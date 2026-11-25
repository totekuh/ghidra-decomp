"""Orchestrator: full kernel GDT build pipeline."""

from __future__ import annotations

import tempfile
from pathlib import Path

import click

from .constants import ARCH_DEFINES, KernelGdtError
from .discovery import (
    _group_by_subdir,
    build_amalgamation,
    discover_headers,
    discover_tree_headers,
    parse_kconfig,
)
from .export import parse_and_export_gdt
from .preprocess import preprocess_headers


def build_kernel_gdt(
    kernel_src: Path,
    arch: str,
    output: Path,
    *,
    config: Path | None = None,
    ghidra_path: Path | None = None,
    max_ram_percent: float = 50.0,
    scan_tree: bool = True,
) -> dict[str, int]:
    """Full pipeline: discover headers, preprocess, parse, export."""
    if arch not in ARCH_DEFINES:
        supported = ", ".join(sorted(ARCH_DEFINES))
        raise KernelGdtError(
            f"Unsupported architecture: {arch}. Supported: {supported}"
        )

    kernel_src = kernel_src.resolve()
    output = output.resolve()

    click.echo(f"Kernel source: {kernel_src}")
    click.echo(f"Architecture:  {arch}")
    click.echo(f"Output:        {output}")

    click.echo("Discovering kernel headers...")
    headers = discover_headers(kernel_src, arch)
    click.echo(f"Found {len(headers)} priority headers")

    tree_headers: list[Path] = []
    if scan_tree:
        click.echo("Scanning kernel tree for additional headers...")
        tree_headers = discover_tree_headers(kernel_src, arch, headers)
        click.echo(f"Found {len(tree_headers)} tree headers")

    config_defines = None
    config_path = config
    if config_path is None:
        autoconf = kernel_src / "include" / "generated" / "autoconf.h"
        if autoconf.is_file():
            config_path = autoconf
            click.echo(f"Auto-detected kernel config: {config_path}")

    if config_path is not None and not config_path.name.endswith(".h"):
        click.echo(f"Parsing kernel config: {config_path}")
        config_defines = parse_kconfig(config_path)
        click.echo(f"Found {len(config_defines)} CONFIG defines")
    elif config_path is not None:
        click.echo(f"Using kernel config header: {config_path}")

    amalgamation = build_amalgamation(
        kernel_src, arch, headers, config_defines, config_path
    )

    tree_groups: dict[str, list[Path]] | None = None
    preamble = ""
    if tree_headers:
        tree_groups = _group_by_subdir(tree_headers, kernel_src)
        click.echo(
            f"Tree headers split into {len(tree_groups)} directory groups: "
            + ", ".join(sorted(tree_groups))
        )
        preamble_lines = ["#define __KERNEL__", "#define MODULE"]
        for define in ARCH_DEFINES[arch]["gcc_defines"]:
            if "=" in define:
                name, value = define.split("=", 1)
                preamble_lines.append(f"#define {name} {value}")
            else:
                preamble_lines.append(f"#define {define}")
        if config_path is not None and config_path.name.endswith(".h"):
            preamble_lines.append(f'#include "{config_path}"')
        elif config_defines:
            for cfg_name in config_defines:
                preamble_lines.append(f"#define {cfg_name} 1")
        preamble = "\n".join(preamble_lines)

    with tempfile.TemporaryDirectory(prefix="ghidra-kernel-gdt-") as work_dir:
        work_path = Path(work_dir)

        click.echo("Preprocessing headers with gcc...")
        preprocessed_path = preprocess_headers(
            kernel_src,
            arch,
            amalgamation,
            work_path,
            tree_groups=tree_groups,
            preamble=preamble,
        )
        size_mb = preprocessed_path.stat().st_size / (1024 * 1024)
        click.echo(f"Preprocessed output: {size_mb:.1f} MB")

        stats = parse_and_export_gdt(
            preprocessed_path, output, ghidra_path, max_ram_percent
        )

    click.echo(
        f"Exported {stats['types_count']} types "
        f"({stats['structs']} structs, {stats['unions']} unions, "
        f"{stats['enums']} enums)"
    )

    return stats
