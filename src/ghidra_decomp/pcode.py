"""Serialize a Ghidra ``HighFunction`` to a plain-dict pcode fact set.

This module holds no opinion about what the facts mean: no sink list, no slice,
no overflow logic. It emits the SSA pcode spine, the varnode-to-variable map, the
basic-block CFG, pre-resolved call arguments, and capacity-relevant extents, and
leaves every judgement to the consumer (see ``HANDOFF_pcode_export.md``).

It must stay importable without Ghidra: every function takes already-live Ghidra
objects and only calls methods on them, so unit tests can drive it with fakes.
The serializer runs inside the decompiler worker, where the ``HighFunction`` is
alive, and returns JSON-ready dicts that outlive the worker — the same discipline
``_high_function_locals`` uses for locals.
"""

from __future__ import annotations

from typing import Any

# Opcodes that transfer control to a callee; their inputs carry the arguments
# Ghidra's own parameter analysis already recovered, so we never redo
# calling-convention recovery by hand.
_CALL_OPS = frozenset({"CALL", "CALLIND"})


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


def _varnode_map(ops: list, namer: _VarnodeNamer, program) -> list[dict[str, Any]]:
    """One entry per varnode that resolves to a recovered ``HighVariable``.

    Merged SSA varnodes can share a ``highvar`` name; that is kept, not collapsed,
    because it is what lets a consumer bind a varnode to the variable the
    pseudocode names.
    """
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for op in ops:
        varnodes = list(_op_inputs(op))
        output = op.getOutput()
        if output is not None:
            varnodes.append(output)
        for varnode in varnodes:
            if varnode is None or varnode.isConstant():
                continue
            high = varnode.getHigh()
            if high is None:
                continue
            vid = namer.id_for(varnode)
            if vid in seen:
                continue
            seen.add(vid)
            data_type = high.getDataType()
            entry: dict[str, Any] = {
                "vn": vid,
                "highvar": _high_name(high),
                "type": data_type.getName() if data_type is not None else "undefined",
                "size": int(varnode.getSize()),
                "storage": _high_storage(high, varnode, program),
            }
            extent = _array_extent(data_type) if data_type is not None else None
            if extent is not None:
                entry["array"] = extent
            out.append(entry)
    return out


def _blocks(high_function, time_to_seq: dict[int, int]) -> list[dict[str, Any]]:
    """Serialize the pcode basic-block CFG and mark loop back-edges.

    A back-edge is an edge whose head is still on the DFS recursion stack when the
    edge is walked (an edge into an ancestor). ``loop_header`` marks any block that
    is the head of such an edge.
    """
    basic_blocks = list(high_function.getBasicBlocks())

    def block_index(block, position=None) -> int:
        # A block's own index is authoritative. Never key by object identity:
        # Jpype hands back a fresh Python proxy for every getOut/getIn call, so
        # id() of a neighbor never matches the block in getBasicBlocks().
        try:
            return int(block.getIndex())
        except Exception:  # noqa: BLE001 - fall back to enumeration order
            return position if position is not None else -1

    serialized: list[dict[str, Any]] = []
    adjacency: dict[int, list[int]] = {}
    for position, block in enumerate(basic_blocks):
        succ = [block_index(block.getOut(i)) for i in range(block.getOutSize())]
        pred = [block_index(block.getIn(i)) for i in range(block.getInSize())]
        ops_seq = []
        for op in list(block.getIterator()):
            seq = time_to_seq.get(op.getSeqnum().getTime())
            if seq is not None:
                ops_seq.append(seq)
        idx = block_index(block, position)
        adjacency[idx] = succ
        serialized.append(
            {
                "block": idx,
                "start": str(block.getStart().toString()),
                "end": str(block.getStop().toString()),
                "ops": ops_seq,
                "succ": succ,
                "pred": pred,
                "loop_header": False,
                "back_edges": [],
            }
        )

    back_edges = _find_back_edges(adjacency)
    by_index = {entry["block"]: entry for entry in serialized}
    headers: set[int] = set()
    for src, dst in back_edges:
        headers.add(dst)
        node = by_index.get(src)
        if node is not None:
            node["back_edges"].append([src, dst])
    for dst in headers:
        node = by_index.get(dst)
        if node is not None:
            node["loop_header"] = True
    return serialized


def _find_back_edges(adjacency: dict[int, list[int]]) -> list[tuple[int, int]]:
    """Detect back-edges by iterative DFS over the block graph."""
    WHITE, GREY, BLACK = 0, 1, 2
    color: dict[int, int] = {node: WHITE for node in adjacency}
    back: list[tuple[int, int]] = []
    for root in adjacency:
        if color[root] != WHITE:
            continue
        # (node, index-into-its-successor-list); GREY while on the stack.
        stack: list[list[int]] = [[root, 0]]
        color[root] = GREY
        while stack:
            node, cursor = stack[-1]
            successors = adjacency.get(node, [])
            if cursor >= len(successors):
                color[node] = BLACK
                stack.pop()
                continue
            stack[-1][1] += 1
            nxt = successors[cursor]
            if nxt not in color:
                continue
            if color[nxt] == GREY:
                back.append((node, nxt))
            elif color[nxt] == WHITE:
                color[nxt] = GREY
                stack.append([nxt, 0])
    return back


def _calls(ops: list, program, namer: _VarnodeNamer) -> list[dict[str, Any]]:
    """Pre-resolve each CALL/CALLIND: callee plus positional argument varnodes.

    A high-pcode CALL's inputs are already the recovered arguments (input[0] is
    the call target), so argument order comes straight from Ghidra's own
    parameter analysis rather than per-architecture register math.
    """
    function_manager = getattr(program, "getFunctionManager", None)
    fm = function_manager() if function_manager is not None else None
    out: list[dict[str, Any]] = []
    for seq, op in enumerate(ops):
        mnemonic = str(op.getMnemonic())
        if mnemonic not in _CALL_OPS:
            continue
        inputs = _op_inputs(op)
        callee_name: str | None = None
        callee_addr: str | None = None
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
            except Exception:  # noqa: BLE001, S110 - an unresolved callee stays null
                pass
        args = [_varnode_ref(vn, namer) for vn in inputs[1:]]
        out.append(
            {
                "seq": seq,
                "op": mnemonic,
                "callee": callee_name,
                "callee_addr": callee_addr,
                "args": args,
            }
        )
    return out


def _stack_locals(high_function) -> list[dict[str, Any]]:
    """Stack/typed-buffer extents: the alloc side for stack overflows.

    Emits base offset, byte size, and for arrays the element size and count, so a
    consumer gets stack-buffer capacity directly without reconstructing the frame.
    """
    symbol_map = high_function.getLocalSymbolMap()
    if symbol_map is None:
        return []
    out: list[dict[str, Any]] = []
    for symbol in symbol_map.getSymbols():
        storage = symbol.getStorage() if hasattr(symbol, "getStorage") else None
        storage_record = _storage_record(storage)
        if storage_record["kind"] != "stack":
            continue
        data_type = symbol.getDataType()
        entry: dict[str, Any] = {
            "name": symbol.getName(),
            "storage": storage_record,
            "type": data_type.getName() if data_type is not None else "undefined",
            "size": int(symbol.getSize()),
        }
        extent = _array_extent(data_type) if data_type is not None else None
        if extent is not None:
            entry["array"] = extent
        out.append(entry)
    return out


def _rodata_reads(ops: list, program) -> list[dict[str, Any]]:
    """Resolve ram-space operands that live in provably read-only memory.

    Guards frequently compare against a global maximum rather than an immediate;
    resolving it keeps the number instead of losing it to "compares against
    something". Only read-only (non-writable) blocks are resolved — mutable
    globals are never guessed at.
    """
    memory = getattr(program, "getMemory", None)
    mem = memory() if memory is not None else None
    if mem is None:
        return []
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for op in ops:
        for varnode in _op_inputs(op):
            if varnode is None or varnode.isConstant():
                continue
            if _space_name(varnode) != "ram":
                continue
            try:
                addr = varnode.getAddress()
                addr_str = str(addr.toString())
                if addr_str in seen:
                    continue
                block = mem.getBlock(addr)
                if block is None or block.isWrite():
                    continue
                size = int(varnode.getSize())
                value = _read_unsigned(mem, addr, size)
                if value is None:
                    continue
                seen.add(addr_str)
                out.append({"addr": addr_str, "size": size, "value": value})
            except Exception:  # noqa: BLE001, S112 - an unreadable address is simply skipped
                continue
    return out


def _read_unsigned(mem, addr, size: int) -> int | None:
    """Read ``size`` little-/big-endian-agnostic bytes as an unsigned int."""
    if size <= 0 or size > 8:
        return None
    try:
        raw = bytearray(size)
        mem.getBytes(addr, raw)
    except Exception:  # noqa: BLE001
        return None
    big_endian = True
    try:
        big_endian = bool(mem.isBigEndian())
    except Exception:  # noqa: BLE001, S110 - endianness defaults to big if unknown
        pass
    order = raw if big_endian else bytes(reversed(raw))
    value = 0
    for byte in order:
        value = (value << 8) | (byte & 0xFF)
    return value


def _arch(program) -> str | None:
    """Ghidra language id, e.g. ``MIPS:LE:32:default``."""
    try:
        return str(program.getLanguageID().toString())
    except Exception:  # noqa: BLE001
        try:
            return str(program.getLanguage().getLanguageID().toString())
        except Exception:  # noqa: BLE001
            return None


def serialize_high_function(
    high_function, func, program, *, schema_version: int
) -> dict[str, Any] | None:
    """Serialize one ``HighFunction`` to the pcode fact envelope.

    Returns ``None`` when no high function is available (a thunk or a decompiler
    error), which the writer turns into an ``{"function", "error"}`` record the
    way the sidecar reports ``decompilation.status``.
    """
    if high_function is None:
        return None

    ops_raw = list(high_function.getPcodeOps())
    namer = _VarnodeNamer()

    time_to_seq: dict[int, int] = {}
    ops: list[dict[str, Any]] = []
    for seq, op in enumerate(ops_raw):
        time_to_seq[op.getSeqnum().getTime()] = seq
        output = op.getOutput()
        ops.append(
            {
                "seq": seq,
                "addr": str(op.getSeqnum().getTarget().toString()),
                "op": str(op.getMnemonic()),
                "output": _varnode_ref(output, namer) if output is not None else None,
                "inputs": [_varnode_ref(vn, namer) for vn in _op_inputs(op)],
            }
        )

    entry = str(func.getEntryPoint().toString())
    body_ranges = [
        {
            "start": str(address_range.getMinAddress().toString()),
            "end": str(address_range.getMaxAddress().toString()),
        }
        for address_range in func.getBody().getAddressRanges(True)
    ]

    return {
        "schema_version": schema_version,
        "function": func.getName(),
        "entry": entry,
        "body_ranges": body_ranges,
        "arch": _arch(program),
        "ops": ops,
        "varnodes": _varnode_map(ops_raw, namer, program),
        "blocks": _blocks(high_function, time_to_seq),
        "calls": _calls(ops_raw, program, namer),
        "locals": _stack_locals(high_function),
        "rodata": _rodata_reads(ops_raw, program),
    }
