"""Serialize a Ghidra ``HighFunction`` to a plain-dict pcode fact set."""

from .serialize import serialize_high_function, serialize_high_function_with_context
from .varnodes import (
    CALL_OPS,
    VarnodeNamer,
    _varnode_key,
    op_inputs,
    space_name,
    varnode_ref,
)

__all__ = [
    "CALL_OPS",
    "VarnodeNamer",
    "_varnode_key",
    "op_inputs",
    "serialize_high_function",
    "serialize_high_function_with_context",
    "space_name",
    "varnode_ref",
]
