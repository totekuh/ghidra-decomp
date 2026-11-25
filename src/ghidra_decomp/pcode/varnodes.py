"""Varnode identity, naming, serialization, and variable storage classification."""

from __future__ import annotations

from typing import Any

_CALL_OPS = frozenset({"CALL", "CALLIND"})
CALL_OPS = _CALL_OPS


def _space_name(varnode) -> str:
    """Name the address space a varnode lives in (register/unique/stack/ram/const)."""
    try:
        return str(varnode.getAddress().getAddressSpace().getName())
    except Exception:  # noqa: BLE001 - a malformed varnode must not abort the export
        return "unknown"


def _varnode_key(varnode) -> tuple:
    """A within-function stable identity for one SSA varnode.

    Two reads of the same SSA value share storage and defining op, so they share
    this key and therefore one id — which is exactly what makes def-use resolve.
    ``SequenceNumber.getTime()`` is unique per op within a function; -1 marks a
    varnode with no defining op (a function input or raw storage).
    """
    defop = varnode.getDef()
    def_time = defop.getSeqnum().getTime() if defop is not None else -1
    return (
        _space_name(varnode),
        int(varnode.getOffset()),
        int(varnode.getSize()),
        def_time,
    )


class _VarnodeNamer:
    """Assign ``v0, v1, …`` ids to varnodes in first-seen program order."""

    def __init__(self) -> None:
        self._ids: dict[tuple, str] = {}

    def id_for(self, varnode) -> str:
        key = _varnode_key(varnode)
        existing = self._ids.get(key)
        if existing is None:
            existing = f"v{len(self._ids)}"
            self._ids[key] = existing
        return existing


VarnodeNamer = _VarnodeNamer


def _varnode_ref(varnode, namer: _VarnodeNamer) -> dict[str, Any]:
    """Serialize one varnode as it appears in an op's inputs/output.

    A constant is inlined with its value; signedness never lives here — it is
    carried by the opcode (``INT_LESS`` vs ``INT_SLESS``). A ram-space varnode
    additionally carries its address so a read-only value can be joined from the
    function-level ``rodata`` map.
    """
    if varnode.isConstant():
        return {"const": int(varnode.getOffset()), "size": int(varnode.getSize())}
    space = _space_name(varnode)
    ref: dict[str, Any] = {
        "vn": namer.id_for(varnode),
        "size": int(varnode.getSize()),
        "space": space,
    }
    if space == "ram":
        try:
            ref["addr"] = str(varnode.getAddress().toString())
        except Exception:  # noqa: BLE001, S110 - a varnode without a resolvable address omits it
            pass
    return ref


def _op_inputs(op) -> list:
    """Return an op's input varnodes in exact operand order."""
    try:
        return list(op.getInputs())
    except Exception:  # noqa: BLE001 - fall back to the indexed accessors
        return [op.getInput(i) for i in range(op.getNumInputs())]


space_name = _space_name
varnode_ref = _varnode_ref
op_inputs = _op_inputs


def _storage_record(storage) -> dict[str, Any]:
    """Classify where a high variable lives. Mirrors the decompiler's own shape."""
    kind = "unassigned"
    register = None
    stack_offset = None
    if storage is not None and not storage.isUnassignedStorage():
        if storage.isStackStorage():
            kind = "stack"
            stack_offset = int(storage.getStackOffset())
        elif storage.isRegisterStorage():
            kind = "register"
            reg = storage.getRegister()
            register = reg.getName() if reg is not None else None
        elif storage.isMemoryStorage():
            kind = "memory"
        else:
            kind = "compound"
    return {
        "kind": kind,
        "register": register,
        "stack_offset": stack_offset,
        "description": str(storage) if storage is not None else None,
    }


def _array_extent(data_type) -> dict[str, int] | None:
    """Decompose an array type into element size and count, or None if not an array."""
    num = getattr(data_type, "getNumElements", None)
    elem_len = getattr(data_type, "getElementLength", None)
    if num is None or elem_len is None:
        return None
    try:
        return {"elem_size": int(elem_len()), "count": int(num())}
    except Exception:  # noqa: BLE001
        return None


def _program_register(program, varnode) -> str | None:
    """Resolve the architectural register a varnode occupies, if any."""
    if program is None:
        return None
    try:
        register = program.getRegister(varnode)
    except Exception:  # noqa: BLE001
        return None
    return register.getName() if register is not None else None


def _high_storage(high, varnode, program) -> dict[str, Any]:
    """Resolve where a high variable lives.

    Storage hangs off the variable's ``HighSymbol``, not the ``HighVariable``
    itself. When a varnode has no symbol (an unnamed temporary) its raw register
    is the next best binding for a downstream symbolic tool, so fall back to it.
    """
    symbol = high.getSymbol() if hasattr(high, "getSymbol") else None
    storage = symbol.getStorage() if symbol is not None else None
    record = _storage_record(storage)
    if record["kind"] in ("unassigned", "unknown"):
        register = _program_register(program, varnode)
        if register is not None:
            return {
                "kind": "register",
                "register": register,
                "stack_offset": None,
                "description": register,
            }
    return record


def _high_name(high) -> str:
    """Prefer the symbol's name; unnamed temporaries keep the variable's label."""
    symbol = high.getSymbol() if hasattr(high, "getSymbol") else None
    if symbol is not None:
        name = symbol.getName()
        if name and name != "UNNAMED":
            return name
    return high.getName()
