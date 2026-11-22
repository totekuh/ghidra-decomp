"""Build a binary-wide allocation map from high pcode.

Records every allocation call site, where its result pointer is stored, and how
it flows forward to other calls or the function's return.  The output is a fact
file — it records what Ghidra sees in the pcode, not opinions about bugs.

Must stay importable without Ghidra: every function takes already-live objects
and only calls methods on them, so unit tests can drive it with fakes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .pcode import (
    CALL_OPS,
    VarnodeNamer,
    op_inputs,
    space_name,
    varnode_ref,
)

ALLOC_MAP_SCHEMA_VERSION = 1

# ── allocator catalogue ──────────────────────────────────────────────────
#
# Each value is a size-argument spec:
#   {"index": N}          — single argument at position N is the byte count
#   {"product": [A, B]}   — two arguments whose product is the byte count
#   None                  — size is implicit or unknown (strdup, cache allocs)

DEFAULT_ALLOCATORS: dict[str, dict[str, Any] | None] = {
    # Standard libc
    "malloc": {"index": 0},
    "calloc": {"product": [0, 1]},
    "realloc": {"index": 1},
    "reallocarray": {"product": [1, 2]},
    "aligned_alloc": {"index": 1},
    "posix_memalign": {"index": 2},
    "memalign": {"index": 1},
    "pvalloc": {"index": 0},
    "valloc": {"index": 0},
    "strdup": None,
    "strndup": {"index": 1},
    # Linux kernel
    "kmalloc": {"index": 0},
    "kzalloc": {"index": 0},
    "kcalloc": {"product": [0, 1]},
    "krealloc": {"index": 1},
    "kvmalloc": {"index": 0},
    "kvzalloc": {"index": 0},
    "kvcalloc": {"product": [0, 1]},
    "vmalloc": {"index": 0},
    "vzalloc": {"index": 0},
    "kmalloc_array": {"product": [0, 1]},
    "devm_kmalloc": {"index": 1},
    "devm_kzalloc": {"index": 1},
    "devm_kcalloc": {"product": [1, 2]},
    "kmem_cache_alloc": None,
    "kmem_cache_zalloc": None,
    "__kmalloc": {"index": 0},
    "kmalloc_node": {"index": 0},
    "kzalloc_node": {"index": 0},
    "alloc_skb": {"index": 0},
    "__alloc_skb": {"index": 0},
    "netdev_alloc_skb": {"index": 1},
    "dev_alloc_skb": {"index": 0},
    "skb_copy": None,
    "skb_clone": None,
}


def load_allocators(config_path: Path | None = None) -> dict[str, dict[str, Any] | None]:
    """Return the allocator catalogue, optionally extended by a JSON config."""
    allocators = dict(DEFAULT_ALLOCATORS)
    if config_path is not None:
        with open(config_path, encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            allocators.update(user)
    return allocators


# ── per-function analysis ─────────────────────────────────────────────────


def _resolve_callee(op, program, fm) -> tuple[str | None, str | None]:
    """Resolve callee name and address from a CALL op."""
    inputs = op_inputs(op)
    callee_name: str | None = None
    callee_addr: str | None = None
    mnemonic = str(op.getMnemonic())
    if inputs and mnemonic == "CALL":
        target = inputs[0]
        try:
            addr = target.getAddress()
            callee_addr = str(addr.toString())
            if fm is not None:
                func = fm.getFunctionAt(addr)
                if func is None:
                    func = fm.getFunctionContaining(addr)
                if func is not None:
                    callee_name = func.getName()
        except Exception:  # noqa: BLE001, S110
            pass
    return callee_name, callee_addr


def _resolve_size(
    call_inputs: list, size_spec: dict[str, Any] | None, namer: VarnodeNamer
) -> dict[str, Any]:
    """Extract size/size_expr/size_vn from a CALL's arguments."""
    if size_spec is None:
        return {"size": None, "size_expr": "unknown", "size_vn": None}

    args = call_inputs[1:]  # inputs[0] is the call target

    if "index" in size_spec:
        idx = size_spec["index"]
        if idx >= len(args):
            return {"size": None, "size_expr": "unknown", "size_vn": None}
        arg = args[idx]
        if arg.isConstant():
            return {
                "size": int(arg.getOffset()),
                "size_expr": "const",
                "size_vn": None,
            }
        return {
            "size": None,
            "size_expr": "variable",
            "size_vn": namer.id_for(arg),
        }

    if "product" in size_spec:
        idx_a, idx_b = size_spec["product"]
        if idx_a >= len(args) or idx_b >= len(args):
            return {"size": None, "size_expr": "unknown", "size_vn": None}
        arg_a, arg_b = args[idx_a], args[idx_b]
        if arg_a.isConstant() and arg_b.isConstant():
            return {
                "size": int(arg_a.getOffset()) * int(arg_b.getOffset()),
                "size_expr": "product",
                "size_vn": None,
            }
        return {"size": None, "size_expr": "variable", "size_vn": None}

    return {"size": None, "size_expr": "unknown", "size_vn": None}


def _classify_store(
    store_op, matched_input_index: int, namer: VarnodeNamer, program
) -> dict[str, Any] | None:
    """Classify a STORE target as field, global, or array.

    A STORE op has inputs: [space_id, address, value].  The address varnode
    determines the store kind.  When the address was computed by a PTRADD the
    defining op gives the struct base and field offset.
    """
    inputs = op_inputs(store_op)
    if len(inputs) < 3:
        return None

    addr_vn = inputs[1]
    store_seq = -1
    try:
        store_seq = store_op.getSeqnum().getTime()
    except Exception:  # noqa: BLE001, S110
        pass

    stored_vn = inputs[2]
    store_vn_id = namer.id_for(stored_vn) if not stored_vn.isConstant() else None

    # Check if the address was produced by a PTRADD (struct field access)
    defop = addr_vn.getDef() if not addr_vn.isConstant() else None
    if defop is not None and str(defop.getMnemonic()) == "PTRADD":
        ptradd_inputs = op_inputs(defop)
        if len(ptradd_inputs) >= 3:
            base_vn = ptradd_inputs[0]
            index_vn = ptradd_inputs[1]
            elem_size_vn = ptradd_inputs[2]

            field_offset = None
            if index_vn.isConstant() and elem_size_vn.isConstant():
                field_offset = int(index_vn.getOffset()) * int(elem_size_vn.getOffset())

            base_type = None
            field_name = None
            try:
                high = base_vn.getHigh()
                if high is not None:
                    dt = high.getDataType()
                    if dt is not None:
                        type_name = dt.getName()
                        if type_name.endswith("*"):
                            type_name = type_name[:-1].rstrip()
                        base_type = type_name
            except Exception:  # noqa: BLE001, S110
                pass

            return {
                "kind": "field",
                "base_type": base_type,
                "field_offset": field_offset,
                "field_name": field_name,
                "store_seq": store_seq,
                "store_vn": store_vn_id,
            }

    # Ram-space address → global store
    if space_name(addr_vn) == "ram":
        global_addr = None
        try:
            global_addr = int(addr_vn.getOffset())
        except Exception:  # noqa: BLE001, S110
            pass
        return {
            "kind": "global",
            "base_type": None,
            "field_offset": global_addr,
            "field_name": None,
            "store_seq": store_seq,
            "store_vn": store_vn_id,
        }

    # Fallback: some other computed address
    return {
        "kind": "array",
        "base_type": None,
        "field_offset": None,
        "field_name": None,
        "store_seq": store_seq,
        "store_vn": store_vn_id,
    }


_FORWARDING_OPS = frozenset({
    "COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "PTRADD", "PTRSUB",
    "INT_ADD",
})


def _follow_output(
    alloc_output_vn,
    ops_raw: list,
    namer: VarnodeNamer,
    program,
    fm,
    start_seq: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Follow an allocation output forward through the function's pcode.

    Returns (stores, passed_to, returned).
    """
    output_id = namer.id_for(alloc_output_vn)
    traced_ids: set[str] = {output_id}
    stores: list[dict[str, Any]] = []
    passed_to: list[dict[str, Any]] = []
    returned = False

    for seq, op in enumerate(ops_raw):
        if seq <= start_seq:
            continue
        mnemonic = str(op.getMnemonic())
        inputs = op_inputs(op)

        input_matches: list[tuple[int, Any]] = []
        for i, inp in enumerate(inputs):
            if inp is not None and not inp.isConstant():
                try:
                    if namer.id_for(inp) in traced_ids:
                        input_matches.append((i, inp))
                except Exception:  # noqa: BLE001, S110
                    pass

        if not input_matches:
            continue

        if mnemonic in _FORWARDING_OPS:
            out = op.getOutput()
            if out is not None:
                traced_ids.add(namer.id_for(out))
        elif mnemonic == "STORE":
            store = _classify_store(op, input_matches[0][0], namer, program)
            if store is not None:
                stores.append(store)
        elif mnemonic in CALL_OPS:
            for i, _inp in input_matches:
                arg_index = i - 1
                if arg_index < 0:
                    continue
                callee_name, callee_addr = _resolve_callee(op, program, fm)
                call_seq = -1
                try:
                    call_seq = op.getSeqnum().getTime()
                except Exception:  # noqa: BLE001, S110
                    pass
                passed_to.append({
                    "callee": callee_name,
                    "callee_addr": callee_addr,
                    "call_seq": call_seq,
                    "arg_index": arg_index,
                })
        elif mnemonic == "RETURN":
            returned = True

    return stores, passed_to, returned


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

        if output_vn is not None:
            output_vn_id = namer.id_for(output_vn)
            stores, p_to, returned = _follow_output(
                output_vn, ops_raw, namer, program, fm, seq
            )

        call_seq = -1
        try:
            call_seq = op.getSeqnum().getTime()
        except Exception:  # noqa: BLE001, S110
            pass

        entry: dict[str, Any] = {
            "function": func_name,
            "function_addr": func_addr,
            "callee": callee_name,
            "callee_addr": callee_addr,
            "call_seq": call_seq,
            **size_info,
            "stores": stores,
            "returns": {
                "output_vn": output_vn_id,
                "passed_to": p_to,
                "returned": returned,
            },
        }
        entries.append(entry)

    return entries


def serialize_alloc_map(entries: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap entries in the alloc-map schema envelope."""
    return {
        "schema_version": ALLOC_MAP_SCHEMA_VERSION,
        "entries": entries,
    }
