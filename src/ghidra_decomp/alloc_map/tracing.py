"""Forward tracing from allocation call sites through pcode ops."""

from __future__ import annotations

from typing import Any

from ..pcode import (
    CALL_OPS,
    VarnodeNamer,
    op_inputs,
    space_name,
)

# Re-use the pcode module's identity key so two Java objects referencing the
# same SSA varnode compare equal.
try:
    from ..pcode import _varnode_key
except ImportError:  # pragma: no cover – fallback for older installs

    def _varnode_key(vn):  # type: ignore[misc]
        defop = vn.getDef()
        def_time = defop.getSeqnum().getTime() if defop is not None else -1
        return (space_name(vn), int(vn.getOffset()), int(vn.getSize()), def_time)


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


def _extract_struct_type(output_vn) -> str | None:
    """Extract struct type name when an allocation output is typed as pointer-to-struct."""
    try:
        high = output_vn.getHigh()
        if high is None:
            return None
        dt = high.getDataType()
        if dt is None:
            return None
        type_name = dt.getName()
        if type_name.endswith(" *"):
            return type_name[:-2]
        if type_name.endswith("*"):
            return type_name[:-1].rstrip()
    except Exception:  # noqa: BLE001, S110
        pass
    return None
