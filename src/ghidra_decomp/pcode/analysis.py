"""CFG serialization, call extraction, stack locals, and read-only memory resolution."""

from __future__ import annotations

from typing import Any

from .varnodes import (
    CALL_OPS,
    _array_extent,
    _dwarf_param_types,
    _high_name,
    _high_storage,
    _is_generic_pointer,
    _op_inputs,
    _space_name,
    _storage_record,
    _varnode_ref,
    _VarnodeNamer,
)

_CALL_OPS = CALL_OPS


def _varnode_map(
    ops: list, namer: _VarnodeNamer, program, func=None
) -> list[dict[str, Any]]:
    """One entry per varnode that resolves to a recovered ``HighVariable``.

    Merged SSA varnodes can share a ``highvar`` name; that is kept, not collapsed,
    because it is what lets a consumer bind a varnode to the variable the
    pseudocode names.
    """
    param_types = _dwarf_param_types(func)
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
            type_name = (
                data_type.getDisplayName() if data_type is not None else "undefined"
            )
            name = _high_name(high)
            if (
                param_types
                and name in param_types
                and _is_generic_pointer(type_name)
                and not _is_generic_pointer(param_types[name])
            ):
                type_name = param_types[name]
            entry: dict[str, Any] = {
                "vn": vid,
                "highvar": name,
                "type": type_name,
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
    """Pre-resolve each CALL/CALLIND: callee plus positional argument varnodes."""
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
    """Stack/typed-buffer extents: the alloc side for stack overflows."""
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
            "type": data_type.getDisplayName()
            if data_type is not None
            else "undefined",
            "size": int(symbol.getSize()),
        }
        extent = _array_extent(data_type) if data_type is not None else None
        if extent is not None:
            entry["array"] = extent
        out.append(entry)
    return out


def _rodata_reads(ops: list, program) -> list[dict[str, Any]]:
    """Resolve ram-space operands that live in provably read-only memory."""
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
