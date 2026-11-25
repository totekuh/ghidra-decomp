"""Allocator wrapper candidate building from live pcode objects."""

from __future__ import annotations

from typing import Any

from ..pcode import op_inputs, space_name
from .tracing import _varnode_key

_PASSTHROUGH_OPS = frozenset(
    {"COPY", "CAST", "INT_ZEXT", "INT_SEXT", "SUBPIECE", "MULTIEQUAL"}
)


def _trace_backward(varnode):  # type: ignore[no-untyped-def]
    """Walk backward through COPY/CAST-only chains to the origin varnode.

    Returns the origin varnode.  Stops at the first non-passthrough defining
    op or at a varnode with no def (a function input or constant).
    """
    current = varnode
    seen: set[tuple] = set()
    while True:
        try:
            key = _varnode_key(current)
        except Exception:  # noqa: BLE001
            return current
        if key in seen:
            return current
        seen.add(key)
        defop = current.getDef() if not current.isConstant() else None
        if defop is None:
            return current
        mnemonic = str(defop.getMnemonic())
        if mnemonic not in _PASSTHROUGH_OPS:
            return current
        inputs = op_inputs(defop)
        if not inputs:
            return current
        current = inputs[0]


def _collect_param_varnodes(ops_raw: list) -> list[tuple]:
    """Identify the function's input parameter varnodes from the pcode.

    In Ghidra's high pcode, function parameters are varnodes with no defining
    op (getDef() returns None) in register or stack space.  Ram-space varnodes
    (CALL targets, globals) are excluded.  Returns a list of varnode keys.
    """
    seen: set[tuple] = set()
    params: list[tuple] = []
    for op in ops_raw:
        for inp in op_inputs(op):
            if inp is None or inp.isConstant():
                continue
            try:
                key = _varnode_key(inp)
            except Exception:  # noqa: BLE001, S112
                continue
            if key in seen:
                continue
            seen.add(key)
            if inp.getDef() is None and space_name(inp) != "ram":
                params.append(key)
    return params


def _param_index_of(varnode, params: list[tuple]) -> int | None:
    """Return the positional index of a varnode among the function's parameters."""
    try:
        key = _varnode_key(varnode)
    except Exception:  # noqa: BLE001
        return None
    for i, p in enumerate(params):
        if p == key:
            return i
    return None


def _alloc_reaches_return_register(entry: dict[str, Any], ops_raw: list) -> bool:
    """Check if the alloc output reaches a register-space varnode via COPY/CAST.

    On MIPS/ARM, the return value ends up in a register without an explicit
    RETURN op consuming it in the high pcode.  This catches that pattern.
    """
    call_seq = entry.get("call_seq", -1)
    call_op = _find_alloc_call_op(ops_raw, call_seq)
    if call_op is None:
        return False
    output_vn = call_op.getOutput()
    if output_vn is None:
        return False
    current = output_vn
    seen: set[tuple] = set()
    for op in ops_raw:
        try:
            if op.getSeqnum().getTime() <= call_seq:
                continue
        except Exception:  # noqa: BLE001, S112
            continue
        mnemonic = str(op.getMnemonic())
        if mnemonic not in _PASSTHROUGH_OPS:
            continue
        inputs = op_inputs(op)
        if not inputs:
            continue
        try:
            inp_key = _varnode_key(inputs[0])
            cur_key = _varnode_key(current)
        except Exception:  # noqa: BLE001, S112
            continue
        if inp_key == cur_key or inp_key in seen:
            out = op.getOutput()
            if out is not None:
                try:
                    seen.add(_varnode_key(out))
                except Exception:  # noqa: BLE001, S110
                    pass
                if space_name(out) == "register":
                    return True
                current = out
    return False


def _find_alloc_call_op(ops_raw: list, call_seq: int):
    """Find the CALL op at a given sequence number."""
    for op in ops_raw:
        try:
            if op.getSeqnum().getTime() == call_seq:
                return op
        except Exception:  # noqa: BLE001, S110
            pass
    return None


# Upper bound on allocator call sites inside one multi-path wrapper.  Two is
# the common shape (branch around two wrappers, like dnsmasq's opt_malloc);
# the bound just keeps sprawling alloc-heavy functions out of detection.
_MAX_WRAPPER_CALLS = 4


def build_wrapper_candidate(
    entries: list[dict[str, Any]],
    ops_raw: list,
    allocators: dict[str, dict[str, Any] | None],
) -> dict[str, Any] | None:
    """Extract lightweight wrapper candidate data from a function's alloc entries.

    Returns a candidate dict if the function might be a wrapper: every alloc
    call site is store-free and returns its result, and there are at most
    _MAX_WRAPPER_CALLS of them.  Multi-path wrappers (branch around two
    wrappers, e.g. ``if (f) return safe_malloc(n); return whine_malloc(n);``)
    produce one call record per site; detect_wrappers_from_candidates accepts
    them only when every site derives the same size spec.  The candidate
    carries all data needed for iterative detection without live Ghidra
    objects.
    """
    if not 1 <= len(entries) <= _MAX_WRAPPER_CALLS:
        return None

    params = _collect_param_varnodes(ops_raw)
    if not params:
        return None

    calls: list[dict[str, Any]] = []
    for entry in entries:
        if entry["stores"]:
            return None
        callee = entry["callee"]
        if callee is None:
            return None
        if not entry["returns"]["returned"] and not _alloc_reaches_return_register(
            entry, ops_raw
        ):
            return None

        call_op = _find_alloc_call_op(ops_raw, entry["call_seq"])
        if call_op is None:
            return None
        call_inputs = op_inputs(call_op)
        args = call_inputs[1:]

        param_mapping: dict[int, int] = {}
        const_args: dict[int, int] = {}
        for i, arg in enumerate(args):
            origin = _trace_backward(arg)
            if origin.isConstant():
                const_args[i] = int(origin.getOffset())
                continue
            pidx = _param_index_of(origin, params)
            if pidx is not None:
                param_mapping[i] = pidx

        calls.append(
            {
                "callee": callee,
                "param_mapping": param_mapping,
                "const_args": const_args,
                "num_args": len(args),
            }
        )

    return {
        # Flat view of the first call keeps single-site candidates unchanged.
        **calls[0],
        "calls": calls,
    }
