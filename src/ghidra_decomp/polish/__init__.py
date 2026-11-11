"""Post-decompilation transforms that improve C readability without changing semantics."""

from __future__ import annotations

import logging

from ._parser import has_error, parse
from .prelude import inject_prelude, strip_prelude

logger = logging.getLogger(__name__)

_TRANSFORMS: list[tuple[str, callable]] = []


def _register_transforms() -> list[tuple[str, callable]]:
    if _TRANSFORMS:
        return _TRANSFORMS
    from .bool_simplify import simplify_booleans
    from .cast_cleanup import remove_redundant_casts
    from .dead_vars import eliminate_dead_variables

    _TRANSFORMS.extend(
        [
            ("dead_vars", eliminate_dead_variables),
            ("bool_simplify", simplify_booleans),
            ("cast_cleanup", remove_redundant_casts),
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
