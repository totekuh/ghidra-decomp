"""Function selection and filtering."""

from __future__ import annotations

import os
import re

import click


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
    """Narrow the discovered functions to those the run asked for."""
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
    """Choose a conservative worker count."""
    return min(4, os.cpu_count() or 1)
