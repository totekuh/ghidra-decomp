"""Per-function decompilation worker and helpers."""

from __future__ import annotations

import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

import click

from ghidra_decomp.alloc_map import build_alloc_entries, build_wrapper_candidate
from ghidra_decomp.artifacts import SCHEMA_VERSION
from ghidra_decomp.decompiler.constants import (
    STATUS_FAILED,
    STATUS_FALLBACK,
    STATUS_SUCCESS,
)
from ghidra_decomp.pcode import serialize_high_function_with_context


def _failure_comment(error: object) -> str:
    """Render every fallback error line as valid C++-style commentary."""
    lines = str(error).splitlines() or ["decompilation failed"]
    return "".join(f"// DECOMPILATION FAILED: {line}\n" for line in lines)


def _is_timeout_error(error: object) -> bool:
    """Detect the decompiler's timeout message without matching other failures."""
    text = str(error).lower()
    return "timeout" in text or "timed out" in text


def _summarize_statuses(records: list[dict]) -> dict:
    """Summarize per-function outcomes into the manifest's counts block."""
    tally = dict.fromkeys((STATUS_SUCCESS, STATUS_FALLBACK, STATUS_FAILED), 0)
    skipped = 0
    for record in records:
        decompilation = record.get("decompilation", {})
        status = decompilation.get("status")
        if status in tally:
            tally[status] += 1
        else:
            tally[STATUS_FAILED] += 1
        if decompilation.get("reused"):
            skipped += 1
    return {
        "discovered": len(records),
        "successful": tally[STATUS_SUCCESS],
        "fallback": tally[STATUS_FALLBACK],
        "failed": tally[STATUS_FAILED],
        "skipped": skipped,
    }


def _addresses_with_status(records: list[dict], status: str) -> list[str]:
    """List the addresses of every function that ended in one status."""
    return [
        record["address"]
        for record in records
        if record.get("decompilation", {}).get("status") == status
    ]


def _thunk_target(func) -> dict | None:
    """Resolve what a thunk forwards to."""
    if not func.isThunk():
        return None
    thunked = func.getThunkedFunction(True)
    if thunked is None:
        return {"name": None, "address": None}
    return {
        "name": thunked.getName(),
        "address": thunked.getEntryPoint().toString(),
    }


def _decompiler_notes(c_code: str) -> list[dict]:
    """Extract the decompiler's own block comments as structured records."""
    notes = []
    for block in re.findall(r"/\*(.*?)\*/", c_code, re.DOTALL):
        text = " ".join(block.split())
        if not text:
            continue
        for prefix, kind in (
            ("WARNING:", "warning"),
            ("Unresolved local var:", "unresolved_local"),
        ):
            if text.startswith(prefix):
                notes.append({"kind": kind, "text": text[len(prefix) :].strip()})
                break
        else:
            notes.append({"kind": "note", "text": text})
    return notes


def _func_header_comment(func) -> str:
    """Build a metadata header comment for a decompiled function."""
    addr = func.getEntryPoint().toString()
    name = func.getName()
    body = func.getBody()
    size = body.getNumAddresses()
    convention = func.getCallingConventionName() or "unknown"
    param_count = func.getParameterCount()
    is_thunk = func.isThunk()

    lines = [
        f"// Function: {name}",
        f"// Address:  {addr}",
        f"// Size:     {size} bytes",
        f"// Calling:  {convention}",
        f"// Params:   {param_count}",
    ]
    if is_thunk:
        thunked = func.getThunkedFunction(True)
        thunk_name = thunked.getName() if thunked else "unknown"
        lines.append(f"// Thunk:    -> {thunk_name}")
    lines.append("")
    return "\n".join(lines)


def _decompile_one(
    decomp,
    monitor,
    func,
    timeout: int,
    program=None,
    pcode: bool = False,
    alloc_map: bool = False,
    allocators: dict | None = None,
) -> tuple[
    str, str | None, str, list[dict], dict | None, list[dict] | None, dict | None
]:
    """Decompile one function: outcome, error, C output, locals, pcode, alloc entries, wrapper info."""
    try:
        result = decomp.decompileFunction(func, timeout, monitor)
    except Exception as e:  # noqa: BLE001 - isolate function failures
        return STATUS_FAILED, f"exception: {e}", "", [], None, None, None

    locals_ = _high_function_locals(result)
    pcode_payload: dict | None = None
    alloc_entries: list[dict] | None = None
    wrapper_info: dict | None = None
    if pcode:
        pcode_payload, alloc_entries, wrapper_info = _serialize_pcode(
            result, func, program, alloc_map=alloc_map, allocators=allocators
        )

    if result and result.decompileCompleted():
        decomp_func = result.getDecompiledFunction()
        c_code = decomp_func.getC() if decomp_func else None
        if c_code:
            return (
                STATUS_SUCCESS,
                None,
                str(c_code),
                locals_,
                pcode_payload,
                alloc_entries,
                wrapper_info,
            )
        return (
            STATUS_FALLBACK,
            "decompiler returned no C output",
            "",
            locals_,
            pcode_payload,
            alloc_entries,
            wrapper_info,
        )

    error = (
        result.getErrorMessage() if result is not None else None
    ) or "decompilation did not complete"
    status = STATUS_FAILED if _is_timeout_error(error) else STATUS_FALLBACK
    return status, str(error), "", locals_, pcode_payload, alloc_entries, wrapper_info


def _serialize_pcode(
    result, func, program, *, alloc_map: bool = False, allocators: dict | None = None
) -> tuple[dict | None, list[dict] | None, dict | None]:
    """Serialize high pcode and optionally build alloc-map entries."""
    if result is None or program is None:
        return None, None, None
    try:
        high_function = result.getHighFunction()
    except Exception:  # noqa: BLE001
        return None, None, None
    try:
        payload, namer, ops_raw = serialize_high_function_with_context(
            high_function, func, program, schema_version=SCHEMA_VERSION
        )
    except Exception as e:  # noqa: BLE001 - one function must not sink the run
        return (
            {
                "function": func.getName(),
                "error": f"pcode serialization failed: {e}",
            },
            None,
            None,
        )

    alloc_entries: list[dict] | None = None
    wrapper_candidate: dict | None = None
    if alloc_map and namer is not None and ops_raw is not None:
        try:
            alloc_entries = build_alloc_entries(
                high_function, func, program, namer, allocators or {}, ops_raw
            )
        except Exception:  # noqa: BLE001
            alloc_entries = None
        if alloc_entries:
            try:
                wrapper_candidate = build_wrapper_candidate(
                    alloc_entries, ops_raw, allocators or {}
                )
            except Exception:  # noqa: BLE001
                wrapper_candidate = None

    return payload, alloc_entries, wrapper_candidate


def _high_function_locals(result) -> list[dict]:
    """Collect the decompiler's local variables from a decompilation result."""
    if result is None:
        return []
    high_function = result.getHighFunction()
    if high_function is None:
        return []
    symbol_map = high_function.getLocalSymbolMap()
    if symbol_map is None:
        return []
    return [
        _high_local_record(symbol)
        for symbol in symbol_map.getSymbols()
        if not symbol.isParameter()
    ]


def _high_local_record(symbol) -> dict:
    """Extract one local variable as the decompiler actually modelled it."""
    data_type = symbol.getDataType()
    from ghidra_decomp.decompiler.extract.functions import _storage_record

    return {
        "name": symbol.getName(),
        "data_type": data_type.getName() if data_type else "undefined",
        "size": symbol.getSize(),
        "storage": _storage_record(symbol.getStorage()),
        "source": None,
    }


def _decompile_functions(
    program,
    functions: list,
    timeout: int,
    workers: int,
    *,
    max_payload_mb: int | None = None,
    pcode: bool = False,
    alloc_map: bool = False,
    allocators: dict | None = None,
) -> dict[
    str,
    tuple[
        str, str | None, str, list[dict], dict | None, list[dict] | None, dict | None
    ],
]:
    """Decompile every function, keyed by entry address."""
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    local = threading.local()
    opened: list = []
    opened_lock = threading.Lock()

    def interface():
        existing = getattr(local, "decomp", None)
        if existing is None:
            existing = DecompInterface()
            existing.openProgram(program)
            options = DecompileOptions()
            options.grabFromProgram(program)
            if max_payload_mb is not None:
                options.setMaxPayloadMBytes(max_payload_mb)
            existing.setOptions(options)
            local.decomp = existing
            local.monitor = ConsoleTaskMonitor()
            with opened_lock:
                opened.append(existing)
        return existing, local.monitor

    def work(func):
        decomp, monitor = interface()
        return (
            func.getEntryPoint().toString(),
            _decompile_one(
                decomp,
                monitor,
                func,
                timeout,
                program,
                pcode,
                alloc_map=alloc_map,
                allocators=allocators,
            ),
        )

    results: dict[
        str,
        tuple[
            str,
            str | None,
            str,
            list[dict],
            dict | None,
            list[dict] | None,
            dict | None,
        ],
    ] = {}
    try:
        if workers <= 1:
            with click.progressbar(
                functions, label="Decompiling", show_pos=True
            ) as bar:
                for func in bar:
                    address, outcome = work(func)
                    results[address] = outcome
        else:
            with ThreadPoolExecutor(max_workers=workers) as pool:
                pending = [pool.submit(work, func) for func in functions]
                with click.progressbar(
                    length=len(pending), label="Decompiling", show_pos=True
                ) as bar:
                    for future in as_completed(pending):
                        address, outcome = future.result()
                        results[address] = outcome
                        bar.update(1)
    finally:
        for decomp in opened:
            decomp.dispose()
    return results
