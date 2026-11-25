"""Ghidra metadata extraction: per-function references, variables, records."""

from __future__ import annotations

from ghidra_decomp.decompiler.worker import _thunk_target


def _disassemble_function(program, func) -> str:
    """Return addressed assembly with raw instruction bytes."""
    listing = program.getListing()
    lines = []
    for instr in listing.getInstructions(func.getBody(), True):
        addr = instr.getAddress()
        raw_bytes = " ".join(f"{int(value) & 0xFF:02x}" for value in instr.getBytes())
        mnemonic = instr.getMnemonicString()
        num_ops = instr.getNumOperands()
        operands = ", ".join(
            instr.getDefaultOperandRepresentation(i) for i in range(num_ops)
        )
        lines.append(f"{addr}:  {raw_bytes:<24}  {mnemonic:<10} {operands}\n")
    return "".join(lines)


def _extract_function_references(program, func) -> tuple[list[dict], list[dict]]:
    """Extract code/data references originating in a function body."""
    ref_manager = program.getReferenceManager()
    references = []
    calls = []
    seen = set()

    for source_address in ref_manager.getReferenceSourceIterator(func.getBody(), True):
        for ref in ref_manager.getReferencesFrom(source_address):
            from_address = ref.getFromAddress().toString()
            to_address = ref.getToAddress().toString()
            ref_type = ref.getReferenceType()
            key = (from_address, to_address, str(ref_type), ref.getOperandIndex())
            if key in seen:
                continue
            seen.add(key)
            item = _reference_record(program, ref, func)
            references.append(item)
            if ref_type.isCall():
                calls.append(
                    {
                        "call_site": from_address,
                        "target_address": to_address,
                        "target_function_address": item["target_function_address"],
                        "target_name": item["target_function_name"],
                        "reference_type": item["reference_type"],
                        "address": item["target_function_address"] or to_address,
                        "name": item["target_function_name"],
                    }
                )

    return references, calls


def _reference_record(program, ref, func=None) -> dict:
    """Normalize a Ghidra reference for sidecars and the global index."""
    fm = program.getFunctionManager()
    target = fm.getFunctionAt(ref.getToAddress())
    if target is None:
        target = fm.getFunctionContaining(ref.getToAddress())
    return {
        "from_address": ref.getFromAddress().toString(),
        "to_address": ref.getToAddress().toString(),
        "function_address": func.getEntryPoint().toString() if func else None,
        "function_name": func.getName() if func else None,
        "reference_type": str(ref.getReferenceType()),
        "operand_index": ref.getOperandIndex(),
        "source": str(ref.getSource()),
        "is_primary": ref.isPrimary(),
        "target_function_address": target.getEntryPoint().toString()
        if target
        else None,
        "target_function_name": target.getName() if target else None,
    }


def _extract_unowned_references(program, owned_references: list[dict]) -> list[dict]:
    """Return program references not already represented by function sidecars."""
    min_address = program.getMinAddress()
    if min_address is None:
        return []
    owned = {
        (
            item["from_address"],
            item["to_address"],
            item["reference_type"],
            item["operand_index"],
        )
        for item in owned_references
    }
    result = []
    fm = program.getFunctionManager()
    for ref in program.getReferenceManager().getReferenceIterator(min_address):
        key = (
            ref.getFromAddress().toString(),
            ref.getToAddress().toString(),
            str(ref.getReferenceType()),
            ref.getOperandIndex(),
        )
        if key in owned:
            continue
        func = fm.getFunctionContaining(ref.getFromAddress())
        result.append(_reference_record(program, ref, func))
    return result


def _body_ranges(body) -> list[dict[str, str]]:
    """Represent all ranges in a potentially non-contiguous function body."""
    return [
        {
            "start": address_range.getMinAddress().toString(),
            "end": address_range.getMaxAddress().toString(),
        }
        for address_range in body.getAddressRanges(True)
    ]


def _storage_record(storage) -> dict:
    """Classify where a variable lives."""
    storage_kind = "unassigned"
    register = None
    stack_offset = None
    if storage is not None and not storage.isUnassignedStorage():
        if storage.isStackStorage():
            storage_kind = "stack"
            stack_offset = storage.getStackOffset()
        elif storage.isRegisterStorage():
            storage_kind = "register"
            storage_register = storage.getRegister()
            register = storage_register.getName() if storage_register else None
        elif storage.isMemoryStorage():
            storage_kind = "memory"
        else:
            storage_kind = "compound"

    return {
        "kind": storage_kind,
        "register": register,
        "stack_offset": stack_offset,
        "description": str(storage) if storage is not None else None,
    }


def _variable_record(variable) -> dict:
    """Extract a variable's type, storage, size, and provenance."""
    data_type = variable.getDataType()
    storage = variable.getVariableStorage()

    return {
        "name": variable.getName(),
        "data_type": data_type.getName() if data_type else "undefined",
        "size": variable.getLength(),
        "storage": _storage_record(storage),
        "source": str(variable.getSource()),
    }


def _symbols_at(program, address) -> list[dict]:
    """Return every symbol at an address, retaining primary/alias identity."""
    return [
        {
            "name": symbol.getName(),
            "namespace": symbol.getParentNamespace().getName(True),
            "type": symbol.getSymbolType().toString(),
            "is_primary": symbol.isPrimary(),
        }
        for symbol in program.getSymbolTable().getSymbols(address)
    ]


def _function_aliases(function_name: str, symbols: list[dict]) -> list[str]:
    """Return unique alias names, retaining non-primary same-name symbols."""
    return list(
        dict.fromkeys(
            item["name"]
            for item in symbols
            if not item["is_primary"] or item["name"] != function_name
        )
    )


def _extract_function_record(
    program, func, *, locals_: list[dict] | None = None
) -> dict:
    """Build stable function identity, body, signature, and storage metadata."""
    body = func.getBody()
    return_type = func.getReturnType()
    parameters = []
    for parameter in func.getParameters():
        item = _variable_record(parameter)
        item["ordinal"] = parameter.getOrdinal()
        parameters.append(item)

    ranges = _body_ranges(body)
    stack_frame = func.getStackFrame()
    function_symbols = _symbols_at(program, func.getEntryPoint())
    record = {
        "name": func.getName(),
        "address": func.getEntryPoint().toString(),
        "symbols": function_symbols,
        "aliases": _function_aliases(func.getName(), function_symbols),
        "body_ranges": ranges,
        "size": body.getNumAddresses(),
        "signature": {
            "return_type": return_type.getName() if return_type else "void",
            "calling_convention": func.getCallingConventionName() or "unknown",
            "source": str(func.getSignatureSource()),
            "parameters": parameters,
            "locals": (
                list(locals_)
                if locals_ is not None
                else [
                    _variable_record(variable) for variable in func.getLocalVariables()
                ]
            ),
        },
        "is_thunk": func.isThunk(),
        "thunk": _thunk_target(func),
        "stack_frame": {
            "frame_size": stack_frame.getFrameSize(),
            "local_size": stack_frame.getLocalSize(),
            "parameter_offset": stack_frame.getParameterOffset(),
            "return_address_offset": stack_frame.getReturnAddressOffset(),
        },
    }
    record.update(
        {
            "end_address": ranges[-1]["end"] if ranges else record["address"],
            "return_type": record["signature"]["return_type"],
            "params": [
                {"type": item["data_type"], "name": item["name"]} for item in parameters
            ],
            "calling_convention": record["signature"]["calling_convention"],
        }
    )
    return record


from ghidra_decomp.decompiler.extract.program import (
    _extract_entry_points,
    _extract_exports,
    _extract_imports,
    _extract_sections,
    _extract_strings,
    _extract_symbols,
    json_line,
)

__all__ = [
    "_extract_entry_points",
    "_extract_exports",
    "_extract_imports",
    "_extract_sections",
    "_extract_strings",
    "_extract_symbols",
    "json_line",
]
