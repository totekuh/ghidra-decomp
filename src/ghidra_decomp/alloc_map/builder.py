"""Per-function allocation analysis and serialization."""

from __future__ import annotations

from typing import Any

from ..pcode import (
    CALL_OPS,
    VarnodeNamer,
    op_inputs,
)
from .catalog import ALLOC_MAP_SCHEMA_VERSION
from .tracing import (
    _extract_struct_type,
    _follow_output,
    _resolve_callee,
    _resolve_size,
    _serialize_call_args,
)
from .wrappers import _alloc_reaches_return_register


def build_alloc_entries(
    high_function,
    func,
    program,
    namer: VarnodeNamer,
    allocators: dict[str, dict[str, Any] | None],
    ops_raw: list,
) -> list[dict[str, Any]]:
    """Analyze one function and return allocation map entries.

    Each entry records one allocation call site: the allocator, its size,
    where the result pointer is stored, and how it is forwarded.
    """
    function_manager = getattr(program, "getFunctionManager", None)
    fm = function_manager() if function_manager is not None else None

    func_name = func.getName()
    func_addr = str(func.getEntryPoint().toString())
    entries: list[dict[str, Any]] = []

    for seq, op in enumerate(ops_raw):
        mnemonic = str(op.getMnemonic())
        if mnemonic not in CALL_OPS:
            continue

        callee_name, callee_addr = _resolve_callee(op, program, fm)

        # Look up allocator spec: exact match first, then fallback heuristic
        size_spec: dict[str, Any] | None = None
        is_allocator = False
        if callee_name is not None:
            if callee_name in allocators:
                is_allocator = True
                size_spec = allocators[callee_name]
            elif "alloc" in callee_name.lower():
                is_allocator = True
                size_spec = None

        if not is_allocator:
            continue

        inputs = op_inputs(op)
        size_info = _resolve_size(inputs, size_spec, namer)

        output_vn = op.getOutput()
        output_vn_id: str | None = None
        stores: list[dict[str, Any]] = []
        p_to: list[dict[str, Any]] = []
        returned = False
        struct_type: str | None = None

        if output_vn is not None:
            output_vn_id = namer.id_for(output_vn)
            struct_type = _extract_struct_type(output_vn)
            stores, p_to, returned = _follow_output(
                output_vn, ops_raw, namer, program, fm, seq
            )

        call_seq = -1
        try:
            call_seq = op.getSeqnum().getTime()
        except Exception:  # noqa: BLE001, S110
            pass

        # For heuristic-matched callees, stash serialized args so the
        # wrapper post-pass can resolve the size without live Ghidra objects.
        call_args: list[dict[str, Any]] | None = None
        if is_allocator and callee_name not in allocators:
            call_args = _serialize_call_args(inputs, namer)

        entry: dict[str, Any] = {
            "function": func_name,
            "function_addr": func_addr,
            "callee": callee_name,
            "callee_addr": callee_addr,
            "call_seq": call_seq,
            **size_info,
            "struct_type": struct_type,
            "unwrapped_via": None,
            "stores": stores,
            "returns": {
                "output_vn": output_vn_id,
                "passed_to": p_to,
                "returned": returned,
            },
        }
        if (
            not returned
            and output_vn is not None
            and _alloc_reaches_return_register(entry, ops_raw)
        ):
            entry["returns"]["returned"] = True
        if call_args is not None:
            entry["_call_args"] = call_args
        entries.append(entry)

    return entries


def serialize_alloc_map(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap entries in the alloc-map schema envelope."""
    return {
        "schema_version": ALLOC_MAP_SCHEMA_VERSION,
        "entries": entries,
    }
