"""Build a binary-wide allocation map from high pcode.

Records every allocation call site, where its result pointer is stored, and how
it flows forward to other calls or the function's return.  The output is a fact
file — it records what Ghidra sees in the pcode, not opinions about bugs.

Wrapper unwrapping: when a call site targets a simple allocator wrapper (a
function that calls exactly one known allocator, returns its result, and passes
a parameter as the size without arithmetic), the entry resolves the size through
the wrapper chain (up to 2 levels deep).

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
)

# Re-use the pcode module's identity key so two Java objects referencing the
# same SSA varnode compare equal.
try:
    from .pcode import _varnode_key
except ImportError:  # pragma: no cover – fallback for older installs

    def _varnode_key(vn):  # type: ignore[misc]
        defop = vn.getDef()
        def_time = defop.getSeqnum().getTime() if defop is not None else -1
        return (space_name(vn), int(vn.getOffset()), int(vn.getSize()), def_time)


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


def load_allocators(
    config_path: Path | None = None,
) -> dict[str, dict[str, Any] | None]:
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

    # PTRSUB: Ghidra 12.x struct field access — PTRSUB(base, byte_offset)
    if defop is not None and str(defop.getMnemonic()) == "PTRSUB":
        ptrsub_inputs = op_inputs(defop)
        if len(ptrsub_inputs) >= 2:
            base_vn = ptrsub_inputs[0]
            offset_vn = ptrsub_inputs[1]

            field_offset = None
            if offset_vn.isConstant():
                field_offset = int(offset_vn.getOffset())

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

    # Constant address (no defining op) → global store
    if addr_vn.isConstant():
        return {
            "kind": "global",
            "base_type": None,
            "field_offset": int(addr_vn.getOffset()),
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


_FORWARDING_OPS = frozenset(
    {
        "COPY",
        "CAST",
        "INT_ZEXT",
        "INT_SEXT",
        "SUBPIECE",
        "PTRADD",
        "PTRSUB",
        "INT_ADD",
        "MULTIEQUAL",
    }
)


def _follow_output(
    alloc_output_vn,
    ops_raw: list,
    namer: VarnodeNamer,
    program,
    fm,
    start_seq: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Follow an allocation output forward through the function's pcode.

    Returns (stores, passed_to, returned).  Uses a fixpoint loop because
    Ghidra's high-pcode seq order does not guarantee def-before-use
    (MULTIEQUAL outputs can precede their consuming COPYs).
    """
    output_id = namer.id_for(alloc_output_vn)
    traced_ids: set[str] = {output_id}
    stores: list[dict[str, Any]] = []
    passed_to: list[dict[str, Any]] = []
    returned = False
    handled_seqs: set[int] = set()

    changed = True
    while changed:
        changed = False
        for seq, op in enumerate(ops_raw):
            if seq <= start_seq or seq in handled_seqs:
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

            handled_seqs.add(seq)
            if mnemonic in _FORWARDING_OPS:
                out = op.getOutput()
                if out is not None:
                    new_id = namer.id_for(out)
                    if new_id not in traced_ids:
                        traced_ids.add(new_id)
                        changed = True
                    if mnemonic == "COPY" and space_name(out) == "ram":
                        global_addr = None
                        try:
                            global_addr = int(out.getOffset())
                        except Exception:  # noqa: BLE001, S110
                            pass
                        store_seq = -1
                        try:
                            store_seq = op.getSeqnum().getTime()
                        except Exception:  # noqa: BLE001, S110
                            pass
                        stores.append(
                            {
                                "kind": "global",
                                "base_type": None,
                                "field_offset": global_addr,
                                "field_name": None,
                                "store_seq": store_seq,
                                "store_vn": namer.id_for(out),
                            }
                        )
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
                    passed_to.append(
                        {
                            "callee": callee_name,
                            "callee_addr": callee_addr,
                            "call_seq": call_seq,
                            "arg_index": arg_index,
                        }
                    )
            elif mnemonic == "RETURN":
                returned = True

    return stores, passed_to, returned


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


def _serialize_call_args(
    call_inputs: list, namer: VarnodeNamer
) -> list[dict[str, Any]]:
    """Serialize CALL arguments (inputs[1:]) for the wrapper post-pass."""
    args = call_inputs[1:]
    result: list[dict[str, Any]] = []
    for arg in args:
        if arg.isConstant():
            result.append({"const": int(arg.getOffset())})
        else:
            result.append({"vn": namer.id_for(arg)})
    return result


def resolve_wrappers(
    entries: list[dict[str, Any]],
    wrapper_db: dict[str, dict[str, Any]],
    allocators: dict[str, dict[str, Any] | None],
) -> list[dict[str, Any]]:
    """Post-pass: resolve heuristic-matched entries through detected wrappers.

    Modifies entries in place and returns them.  Strips transient ``_call_args``.
    """
    for entry in entries:
        call_args = entry.pop("_call_args", None)
        if entry.get("unwrapped_via") is not None:
            continue
        if entry["callee"] is None:
            continue
        if entry["callee"] in allocators:
            continue
        if call_args is None:
            continue

        chain: list[str] = []
        current_callee = entry["callee"]
        current_args = call_args
        resolved = False

        seen_callees: set[str] = set()
        while current_callee not in seen_callees:
            seen_callees.add(current_callee)
            info = wrapper_db.get(current_callee)
            if info is None:
                break
            chain.append(current_callee)
            wrapper_spec = info["size_spec"]
            inner_chain = info["chain"]

            size_info = _resolve_call_args(current_args, wrapper_spec)
            if size_info is not None and inner_chain:
                final_allocator = inner_chain[-1]
                if final_allocator in allocators:
                    entry["size"] = size_info["size"]
                    entry["size_expr"] = size_info["size_expr"]
                    entry["size_vn"] = size_info["size_vn"]
                    entry["unwrapped_via"] = " -> ".join(chain + inner_chain)
                    resolved = True
                    break
                next_callee = inner_chain[0]
                if next_callee in wrapper_db:
                    next_args = _build_forwarded_args(current_args, wrapper_spec)
                    if next_args is None:
                        break
                    current_callee = next_callee
                    current_args = next_args
                    continue
            break

        if not resolved:
            entry.setdefault("unwrapped_via", None)

    return entries


def _resolve_call_args(
    args: list[dict[str, Any]], spec: dict[str, Any]
) -> dict[str, Any] | None:
    """Resolve size from serialized call arguments and a size spec."""
    if "index" in spec:
        idx = spec["index"]
        if idx >= len(args):
            return None
        arg = args[idx]
        if "const" in arg:
            return {"size": arg["const"], "size_expr": "const", "size_vn": None}
        return {"size": None, "size_expr": "variable", "size_vn": arg.get("vn")}

    if "product" in spec:
        idx_a, idx_b = spec["product"]
        if idx_a >= len(args) or idx_b >= len(args):
            return None
        arg_a, arg_b = args[idx_a], args[idx_b]
        if "const" in arg_a and "const" in arg_b:
            return {
                "size": arg_a["const"] * arg_b["const"],
                "size_expr": "product",
                "size_vn": None,
            }
        return {"size": None, "size_expr": "variable", "size_vn": None}

    return None


def _build_forwarded_args(
    caller_args: list[dict[str, Any]], wrapper_spec: dict[str, Any]
) -> list[dict[str, Any]] | None:
    """Build the argument list for the next level of wrapper chain."""
    if "index" in wrapper_spec:
        idx = wrapper_spec["index"]
        if idx >= len(caller_args):
            return None
        return [caller_args[idx]]
    if "product" in wrapper_spec:
        idx_a, idx_b = wrapper_spec["product"]
        if idx_a >= len(caller_args) or idx_b >= len(caller_args):
            return None
        return [caller_args[idx_a], caller_args[idx_b]]
    return None


# Upper bound on allocator call sites inside one multi-path wrapper.  Two is
# the common shape (branch around two wrappers, like dnsmasq\'s opt_malloc);
# the bound just keeps sprawling alloc-heavy functions out of detection.
_MAX_WRAPPER_CALLS = 4


def build_wrapper_candidate(
    entries: list[dict[str, Any]],
    ops_raw: list,
    allocators: dict[str, dict[str, Any] | None],
) -> dict[str, Any] | None:
    """Extract lightweight wrapper candidate data from a function\'s alloc entries.

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


def detect_wrappers_from_candidates(
    candidates: dict[str, dict[str, Any]],
    allocators: dict[str, dict[str, Any] | None],
) -> dict[str, dict[str, Any]]:
    """Iteratively detect wrappers from candidate data until no new wrappers found.

    Returns wrapper_db mapping function name to wrapper info.
    """
    wrapper_db: dict[str, dict[str, Any]] = {}

    changed = True
    while changed:
        changed = False
        for func_name, cand in candidates.items():
            if func_name in wrapper_db:
                continue
            # A candidate may carry several allocator call sites (a
            # multi-path wrapper); every site must derive the same size
            # spec or the function is not treated as a wrapper.
            call_records = cand.get("calls") or [cand]

            wrapper_spec: dict[str, Any] | None = None
            first_spec: dict[str, Any] | None = None
            chain_prefix: list[str] = []

            for record in call_records:
                callee = record["callee"]
                spec: dict[str, Any] | None = None
                if callee in allocators:
                    spec = allocators[callee]
                    record_chain = [callee]
                elif callee in wrapper_db:
                    w = wrapper_db[callee]
                    spec = w["size_spec"]
                    record_chain = [callee] + w["chain"]
                else:
                    wrapper_spec = None
                    break

                if spec is None:
                    wrapper_spec = None
                    break

                record_spec = _derive_wrapper_spec(record, spec)
                if record_spec is None:
                    wrapper_spec = None
                    break
                if wrapper_spec is None:
                    wrapper_spec = record_spec
                    first_spec = spec
                    chain_prefix = record_chain
                elif not _specs_equivalent(wrapper_spec, record_spec):
                    wrapper_spec = None
                    break

            if wrapper_spec is None or first_spec is None:
                continue

            wrapper_db[func_name] = {
                "inner_allocator": cand["callee"],
                "inner_spec": first_spec,
                "size_spec": wrapper_spec,
                "chain": chain_prefix,
            }
            changed = True

    return wrapper_db


def _derive_wrapper_spec(
    cand: dict[str, Any], inner_spec: dict[str, Any]
) -> dict[str, Any] | None:
    """Derive the wrapper's size spec from its candidate data and inner spec."""
    param_mapping = cand["param_mapping"]
    const_args = cand["const_args"]

    if "index" in inner_spec:
        idx = inner_spec["index"]
        if idx in param_mapping:
            return {"index": param_mapping[idx]}
        if idx in const_args:
            return inner_spec
        return None

    if "product" in inner_spec:
        idx_a, idx_b = inner_spec["product"]
        a_param = param_mapping.get(idx_a)
        b_param = param_mapping.get(idx_b)
        a_const = const_args.get(idx_a)
        b_const = const_args.get(idx_b)

        if a_const == 1 and b_param is not None:
            return {"index": b_param}
        if b_const == 1 and a_param is not None:
            return {"index": a_param}
        if a_param is not None and b_param is not None:
            return {"product": [a_param, b_param]}
        if a_const is not None and b_const is not None:
            return inner_spec
        return None

    return None


def _specs_equivalent(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Whether two derived size specs describe the same sizing.

    Product specs compare order-insensitively: ``product(0, 1)`` and
    ``product(1, 0)`` both mean "the product of both params".
    """
    if a == b:
        return True
    if "product" in a and "product" in b:
        return sorted(a["product"]) == sorted(b["product"])
    return False


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
