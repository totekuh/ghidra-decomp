"""Post-decompilation transforms that improve C readability without changing semantics."""

from __future__ import annotations

import logging
from collections.abc import Callable

from ._parser import has_error, parse
from .prelude import inject_prelude, strip_prelude

logger = logging.getLogger(__name__)

_TRANSFORMS: list[tuple[str, Callable[[str], str]]] = []


def _register_transforms() -> list[tuple[str, Callable[[str], str]]]:
    if _TRANSFORMS:
        return _TRANSFORMS
    from .bool_simplify import simplify_booleans
    from .compound_assign import simplify_compound_assignments
    from .dead_vars import eliminate_dead_variables
    from .goto_reduce import reduce_gotos
    from .loop_normalize import normalize_loops
    from .nested_if_flatten import flatten_nested_ifs
    from .return_simplify import simplify_returns
    from .struct_fields import synthesize_struct_fields
    from .ternary_synthesis import synthesize_ternaries
    from .vtable_synthesis import synthesize_vtables

    _TRANSFORMS.extend(
        [
            ("dead_vars", eliminate_dead_variables),
            ("bool_simplify", simplify_booleans),
            ("loop_normalize", normalize_loops),
            ("struct_fields", synthesize_struct_fields),
            ("compound_assign", simplify_compound_assignments),
            ("return_simplify", simplify_returns),
            ("ternary_synthesis", synthesize_ternaries),
            ("goto_reduce", reduce_gotos),
            ("nested_if_flatten", flatten_nested_ifs),
            ("vtable_synthesis", synthesize_vtables),
        ]
    )
    return _TRANSFORMS


def polish(c_code: str, *, skip: bool = False) -> tuple[str, bool]:
    """Apply all polish transforms to decompiled C code.

    Returns (transformed_code, polished_flag).
    """
    if skip or not c_code.strip():
        return c_code, False

    transforms = _register_transforms()
    with_prelude = inject_prelude(c_code)

    current = with_prelude
    any_changed = False

    for name, transform in transforms:
        try:
            result = transform(current)
        except Exception:
            logger.debug("polish transform %s raised, skipping", name, exc_info=True)
            continue

        tree = parse(result)
        if has_error(tree.root_node):
            logger.debug(
                "polish transform %s produced unparseable output, reverting", name
            )
            continue

        if result != current:
            any_changed = True
        current = result

    stripped = strip_prelude(current)

    if not any_changed:
        return c_code, False

    tree = parse(inject_prelude(stripped))
    if has_error(tree.root_node):
        logger.debug("polished output fails final parse check, returning original")
        return c_code, False

    return stripped, True
