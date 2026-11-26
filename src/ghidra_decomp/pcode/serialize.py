"""Top-level pcode serialization entry points."""

from __future__ import annotations

from typing import Any

from .analysis import _arch, _blocks, _calls, _rodata_reads, _stack_locals, _varnode_map
from .varnodes import _op_inputs, _varnode_ref, _VarnodeNamer


def serialize_high_function_with_context(
    high_function, func, program, *, schema_version: int
) -> tuple[dict[str, Any] | None, _VarnodeNamer | None, list | None]:
    """Like :func:`serialize_high_function` but also returns the namer and raw ops.

    Callers that need to run further analysis with consistent varnode IDs (e.g.
    the alloc-map builder) use this variant to share the namer that assigned the
    ``v0, v1, …`` identifiers during serialization.
    """
    if high_function is None:
        return None, None, None

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

    payload = {
        "schema_version": schema_version,
        "function": func.getName(),
        "entry": entry,
        "body_ranges": body_ranges,
        "arch": _arch(program),
        "ops": ops,
        "varnodes": _varnode_map(ops_raw, namer, program, func),
        "blocks": _blocks(high_function, time_to_seq),
        "calls": _calls(ops_raw, program, namer),
        "locals": _stack_locals(high_function),
        "rodata": _rodata_reads(ops_raw, program),
    }
    return payload, namer, ops_raw


def serialize_high_function(
    high_function, func, program, *, schema_version: int
) -> dict[str, Any] | None:
    """Serialize one ``HighFunction`` to the pcode fact envelope.

    Returns ``None`` when no high function is available (a thunk or a decompiler
    error), which the writer turns into an ``{"function", "error"}`` record the
    way the sidecar reports ``decompilation.status``.
    """
    payload, _, _ = serialize_high_function_with_context(
        high_function, func, program, schema_version=schema_version
    )
    return payload
