"""Stage 2: gcc -E preprocessing for the kernel GDT pipeline."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import click

from .constants import ARCH_DEFINES, COMPAT_SHIM, KernelGdtError


def build_gcc_command(
    kernel_src: Path,
    arch: str,
    amalgamation_path: Path,
    compat_shim_path: Path,
) -> list[str]:
    """Build the gcc -E command line for preprocessing kernel headers."""
    arch_info = ARCH_DEFINES[arch]
    kernel_arch = arch_info["kernel_arch"]

    arch_base = kernel_src / "arch" / kernel_arch / "include"

    include_dirs = [
        kernel_src / "include",
        kernel_src / "include" / "uapi",
        arch_base,
        arch_base / "uapi",
        arch_base / "generated",
        arch_base / "generated" / "uapi",
        kernel_src / "include" / "generated",
        kernel_src / "include" / "generated" / "uapi",
        kernel_src / "include" / "asm-generic",
    ]

    gcc_internal = subprocess.run(
        ["gcc", "-print-file-name=include"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()

    cmd = ["gcc", "-E", "-nostdinc", "-P", "-w"]

    for inc in include_dirs:
        cmd.extend(["-I", str(inc)])
    cmd.extend(["-isystem", gcc_internal])

    cmd.extend(["-include", str(compat_shim_path)])
    cmd.append(str(amalgamation_path))

    return cmd


def _run_gcc_e(
    kernel_src: Path,
    arch: str,
    amalgamation: str,
    amalgamation_path: Path,
    compat_path: Path,
) -> subprocess.CompletedProcess:
    """Run gcc -E on a single amalgamation and return the result."""
    amalgamation_path.write_text(amalgamation, encoding="utf-8")
    cmd = build_gcc_command(kernel_src, arch, amalgamation_path, compat_path)
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
    except FileNotFoundError:
        raise KernelGdtError("gcc not found. Install gcc to preprocess kernel headers.")


def preprocess_headers(
    kernel_src: Path,
    arch: str,
    amalgamation: str,
    work_dir: Path,
    *,
    tree_groups: dict[str, list[Path]] | None = None,
    preamble: str = "",
) -> Path:
    """Run gcc -E on the amalgamation and return path to preprocessed output.

    When *tree_groups* is provided, each directory group is preprocessed
    separately so a failure in one group does not block others.  The
    *preamble* (defines and config includes) is prepended to each group's
    amalgamation so types resolve.
    """
    amalgamation_path = work_dir / "kernel_types.h"
    compat_path = work_dir / "ghidra_compat.h"
    compat_path.write_text(COMPAT_SHIM, encoding="utf-8")

    preprocessed_path = work_dir / "preprocessed.h"

    result = _run_gcc_e(kernel_src, arch, amalgamation, amalgamation_path, compat_path)
    if result.returncode != 0:
        stderr_tail = result.stderr.strip()[-500:] if result.stderr else "(no output)"
        raise KernelGdtError(f"gcc preprocessing failed:\n{stderr_tail}")

    parts = [result.stdout]

    for subdir, headers in sorted((tree_groups or {}).items()):
        group_lines = [preamble, ""] if preamble else []
        for h in headers:
            group_lines.append(f'#include "{h}"')
        group_lines.append("")
        group_amalgamation = "\n".join(group_lines)

        group_result = _run_gcc_e(
            kernel_src, arch, group_amalgamation, amalgamation_path, compat_path
        )
        if group_result.returncode != 0:
            stderr_snippet = (
                group_result.stderr.strip()[-200:] if group_result.stderr else ""
            )
            click.echo(
                f"Warning: {subdir}/ headers failed gcc -E, "
                f"skipping {len(headers)} headers ({stderr_snippet})",
                err=True,
            )
            continue
        parts.append(group_result.stdout)

    combined = "\n".join(parts)
    cleaned = _strip_function_bodies(combined)
    cleaned = _simplify_complex_exprs(cleaned)
    preprocessed_path.write_text(cleaned, encoding="utf-8")
    return preprocessed_path


def _strip_function_bodies(text: str) -> str:
    """Remove function bodies (balanced {...} blocks) from preprocessed C.

    CParser only handles declarations; inline function bodies from kernel
    headers cause parse errors.  Replaces top-level ``{ ... }`` with ``;``
    while preserving struct/union/enum bodies.
    """
    out: list[str] = []
    depth = 0
    i = 0
    in_struct = False
    length = len(text)

    while i < length:
        ch = text[i]

        if ch == "{":
            if depth == 0:
                preceding = text[max(0, i - 200) : i].rstrip()
                if re.search(
                    r"\b(struct|union|enum)\s*(\w+\s*)?\Z",
                    preceding,
                ):
                    in_struct = True
                    out.append(ch)
                else:
                    in_struct = False
            else:
                if in_struct:
                    out.append(ch)
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                if in_struct:
                    out.append(ch)
                else:
                    out.append(";")
                in_struct = False
            elif in_struct:
                out.append(ch)
        elif depth == 0 or in_struct:
            out.append(ch)

        i += 1

    return "".join(out)


_TYPE_START_RE = re.compile(
    r"(?:(?:extern|static|const|volatile|inline)\s+)*"
    r"(?:typedef|struct|union|enum)\b"
)
_FORWARD_DECL_RE = re.compile(
    r"^(?:(?:extern|static|const|volatile|inline)\s+)*"
    r"(?:struct|union|enum)\s+\w+\s*;$"
)


def _strip_non_type_statements(text: str) -> str:
    """Keep only type definitions; drop all other top-level statements.

    Scans character-by-character to identify statement boundaries
    (top-level ``;``) while tracking brace depth for struct/enum bodies.
    Each top-level statement is kept only if it starts with a type
    keyword (typedef/struct/union/enum, with optional qualifiers).
    Preprocessor directives (``#``) are always kept.
    """
    result: list[str] = []
    stmt_start = 0
    brace_depth = 0
    i = 0
    length = len(text)

    while i < length:
        ch = text[i]
        if ch == "{":
            brace_depth += 1
        elif ch == "}":
            brace_depth -= 1
            if brace_depth == 0:
                close_semi = text.find(";", i)
                if close_semi == -1:
                    close_semi = length - 1
                stmt = text[stmt_start : close_semi + 1]
                leading = stmt.lstrip()
                if _TYPE_START_RE.match(leading) or leading.startswith(("}", "#")):
                    result.append(stmt)
                stmt_start = close_semi + 1
                i = stmt_start
                continue
        elif ch == ";" and brace_depth == 0:
            stmt = text[stmt_start : i + 1]
            leading = stmt.lstrip()
            if leading.startswith(("typedef ", "#")) or _FORWARD_DECL_RE.match(
                leading.strip()
            ):
                result.append(stmt)
            stmt_start = i + 1
        i += 1

    tail = text[stmt_start:]
    if tail.strip():
        leading = tail.lstrip()
        if _TYPE_START_RE.match(leading) or leading.startswith("#"):
            result.append(tail)

    return "".join(result)


def _simplify_complex_exprs(text: str) -> str:
    """Clean preprocessed C for Ghidra's CParser.

    1. Keep only type definitions (typedef/struct/union/enum).
    2. Simplify complex array dimensions.
    3. Normalize integer literal suffixes.
    """
    text = _strip_non_type_statements(text)
    text = _simplify_array_dims(text)
    text = re.sub(r"\b(\d+)LU\b", r"\1UL", text)
    text = re.sub(r"\b(\d+)LLU\b", r"\1ULL", text)
    return text


def _simplify_array_dims(text: str) -> str:
    """Replace complex array dimensions with [1].

    Handles nested parentheses that a simple regex cannot match.
    Any [...] containing a '(' is replaced with [1].
    """
    result: list[str] = []
    i = 0
    length = len(text)
    while i < length:
        if text[i] == "[":
            j = i + 1
            depth = 1
            has_paren = False
            while j < length and depth > 0:
                if text[j] == "[":
                    depth += 1
                elif text[j] == "]":
                    depth -= 1
                elif text[j] == "(":
                    has_paren = True
                j += 1
            if has_paren and depth == 0:
                result.append("[1]")
            else:
                result.append(text[i:j])
            i = j
        else:
            result.append(text[i])
            i += 1
    return "".join(result)
