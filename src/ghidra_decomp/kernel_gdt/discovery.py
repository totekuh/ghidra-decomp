"""Stage 1: Header discovery for the kernel GDT pipeline."""

from __future__ import annotations

import re
from pathlib import Path

from .constants import (
    ARCH_DEFINES,
    PRIORITY_HEADERS,
    TREE_EXCLUDE_DIRS,
    KernelGdtError,
)


def discover_headers(kernel_src: Path, arch: str) -> list[str]:
    """Return headers from PRIORITY_HEADERS that exist in the kernel tree.

    Only includes curated headers known to work with standalone gcc -E.
    """
    arch_info = ARCH_DEFINES.get(arch)
    if arch_info is None:
        supported = ", ".join(sorted(ARCH_DEFINES))
        raise KernelGdtError(
            f"Unsupported architecture: {arch}. Supported: {supported}"
        )

    kernel_arch = arch_info["kernel_arch"]
    include_base = kernel_src / "include"
    arch_base = kernel_src / "arch" / kernel_arch / "include"

    found: list[str] = []
    for header in PRIORITY_HEADERS:
        if (include_base / header).is_file() or (arch_base / header).is_file():
            found.append(header)

    return found


def discover_tree_headers(
    kernel_src: Path, arch: str, priority_headers: list[str]
) -> list[Path]:
    """Walk the full kernel tree for .h files outside the curated list.

    Returns absolute paths sorted for deterministic amalgamation output.
    Excludes directories unlikely to contain parseable type definitions
    and non-target architecture subdirectories.
    """
    arch_info = ARCH_DEFINES.get(arch)
    if arch_info is None:
        supported = ", ".join(sorted(ARCH_DEFINES))
        raise KernelGdtError(
            f"Unsupported architecture: {arch}. Supported: {supported}"
        )

    kernel_arch = arch_info["kernel_arch"]
    kernel_src = kernel_src.resolve()

    include_base = kernel_src / "include"
    arch_base = kernel_src / "arch" / kernel_arch / "include"
    priority_abs: set[Path] = set()
    for header in priority_headers:
        priority_abs.add((include_base / header).resolve())
        priority_abs.add((arch_base / header).resolve())

    result: list[Path] = []
    for header_path in kernel_src.rglob("*.h"):
        resolved = header_path.resolve()
        if resolved in priority_abs:
            continue

        rel = resolved.relative_to(kernel_src)
        top_dir = rel.parts[0] if rel.parts else ""

        if top_dir in TREE_EXCLUDE_DIRS:
            continue

        if top_dir == "arch" and (len(rel.parts) < 2 or rel.parts[1] != kernel_arch):
            continue

        result.append(resolved)

    result.sort()
    return result


def parse_kconfig(config_path: Path) -> list[str]:
    """Parse a .config or autoconf.h and return CONFIG_* define names.

    For .config: extracts CONFIG_* from lines matching ``CONFIG_*=y`` or
    ``CONFIG_*=m``.
    For autoconf.h: extracts CONFIG_* from ``#define CONFIG_*`` lines.
    """
    text = config_path.read_text(encoding="utf-8", errors="replace")
    defines: list[str] = []

    if config_path.name.endswith(".h"):
        for match in re.finditer(r"^#define\s+(CONFIG_\w+)", text, re.MULTILINE):
            defines.append(match.group(1))
    else:
        for match in re.finditer(r"^(CONFIG_\w+)=[ym]", text, re.MULTILINE):
            defines.append(match.group(1))

    return defines


def build_amalgamation(
    kernel_src: Path,
    arch: str,
    headers: list[str],
    config_defines: list[str] | None = None,
    config_path: Path | None = None,
    tree_headers: list[Path] | None = None,
) -> str:
    """Build the kernel_types.h amalgamation content."""
    arch_info = ARCH_DEFINES[arch]
    lines = [
        "/* Auto-generated kernel type amalgamation for Ghidra CParser */",
        "",
        "#define __KERNEL__",
        "#define MODULE",
    ]

    for define in arch_info["gcc_defines"]:
        if "=" in define:
            name, value = define.split("=", 1)
            lines.append(f"#define {name} {value}")
        else:
            lines.append(f"#define {define}")

    if config_path is not None and config_path.name.endswith(".h"):
        lines.append("")
        lines.append(f'#include "{config_path}"')
    elif config_defines:
        lines.append("")
        for config in config_defines:
            lines.append(f"#define {config} 1")

    lines.append("")
    for header in headers:
        lines.append(f"#include <{header}>")

    if tree_headers:
        lines.append("")
        for header_path in tree_headers:
            lines.append(f'#include "{header_path}"')

    lines.append("")
    return "\n".join(lines)


def _group_by_subdir(
    tree_headers: list[Path], kernel_src: Path
) -> dict[str, list[Path]]:
    """Group tree headers by their top-level directory under kernel_src."""
    groups: dict[str, list[Path]] = {}
    for h in tree_headers:
        rel = h.relative_to(kernel_src)
        key = rel.parts[0]
        groups.setdefault(key, []).append(h)
    return groups
