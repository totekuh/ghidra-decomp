"""Program-wide extraction: strings, imports, exports, symbols, sections."""

from __future__ import annotations

import json


def json_line(data: dict) -> str:
    """Serialize one deterministic JSON Lines record."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n"


def _extract_strings(program) -> list[dict]:
    """Extract all defined strings with their xrefs."""
    from ghidra.program.model.data import AbstractStringDataType

    ref_manager = program.getReferenceManager()
    fm = program.getFunctionManager()
    listing = program.getListing()
    strings = []

    for data in listing.getDefinedData(True):
        dt = data.getDataType()
        value = data.getValue()
        if value is None or (
            not isinstance(dt, AbstractStringDataType) and not isinstance(value, str)
        ):
            continue
        addr = data.getAddress()
        if isinstance(value, (bytes, bytearray)):
            value = value.decode("utf-8", errors="replace")
        else:
            value = str(value)

        xrefs = []
        for ref in ref_manager.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            func = fm.getFunctionContaining(from_addr)
            xrefs.append(
                {
                    "from_address": from_addr.toString(),
                    "function": func.getName() if func else None,
                    "function_address": func.getEntryPoint().toString()
                    if func
                    else None,
                }
            )

        strings.append(
            {
                "address": addr.toString(),
                "value": value,
                "length": data.getLength(),
                "xrefs": xrefs,
            }
        )

    return strings


def _extract_imports(program) -> list[dict]:
    """Extract imported (external) functions."""
    fm = program.getFunctionManager()
    imports = []

    for func in fm.getExternalFunctions():
        ext_loc = func.getExternalLocation()
        external_address = ext_loc.getAddress() if ext_loc else None
        linkage_addresses = func.getFunctionThunkAddresses(True) or ()
        imports.append(
            {
                "name": func.getName(),
                "library": ext_loc.getLibraryName() if ext_loc else None,
                "address": func.getEntryPoint().toString(),
                "external_address": external_address.toString()
                if external_address
                else None,
                "linkage_addresses": sorted(
                    address.toString() for address in linkage_addresses
                ),
            }
        )

    return imports


def _extract_exports(program) -> list[dict]:
    """Extract one primary or global symbol for each exported entry point."""
    symbol_table = program.getSymbolTable()
    exports: dict[str, tuple[bool, bool, dict]] = {}

    for symbol in symbol_table.getAllSymbols(True):
        if not symbol.isExternalEntryPoint():
            continue

        address = symbol.getAddress().toString()
        namespace = symbol.getParentNamespace()
        candidate = (
            namespace.isGlobal(),
            symbol.isPrimary(),
            {
                "name": symbol.getName(),
                "address": address,
                "namespace": namespace.getName(True),
                "is_primary": symbol.isPrimary(),
            },
        )
        current = exports.get(address)
        if current is None or candidate[:2] > current[:2]:
            exports[address] = candidate

    return [candidate[2] for candidate in exports.values()]


def _extract_entry_points(program) -> list[str]:
    """Return exported addresses that resolve to code or a function entry."""
    fm = program.getFunctionManager()
    memory = program.getMemory()
    addresses = set()
    for item in _extract_exports(program):
        address = program.getAddressFactory().getAddress(item["address"])
        block = memory.getBlock(address) if address is not None else None
        if address is not None and (
            fm.getFunctionAt(address) is not None
            or (block is not None and block.isExecute())
        ):
            addresses.add(item["address"])
    return sorted(addresses)


def _extract_symbols(program) -> list[dict]:
    """Extract non-function symbols: globals, labels, data."""
    from ghidra.program.model.symbol import SymbolType

    symbol_table = program.getSymbolTable()
    listing = program.getListing()
    skip_types = {SymbolType.FUNCTION, SymbolType.PARAMETER, SymbolType.LOCAL_VAR}
    symbols = []

    for symbol in symbol_table.getAllSymbols(True):
        sym_type = symbol.getSymbolType()
        if sym_type in skip_types:
            continue
        if symbol.isExternal():
            continue

        addr = symbol.getAddress()
        entry = {
            "name": symbol.getName(),
            "address": addr.toString(),
            "type": sym_type.toString(),
            "namespace": symbol.getParentNamespace().getName(True),
            "is_primary": symbol.isPrimary(),
        }

        data = listing.getDataAt(addr)
        if data is not None:
            dt = data.getDataType()
            entry["data_type"] = dt.getName() if dt else None
            entry["size"] = data.getLength()

        symbols.append(entry)

    return symbols


def _extract_sections(program) -> list[dict]:
    """Extract memory sections/segments with permissions."""
    memory = program.getMemory()
    sections = []

    for block in memory.getBlocks():
        sections.append(
            {
                "name": block.getName(),
                "start": block.getStart().toString(),
                "end": block.getEnd().toString(),
                "size": block.getSize(),
                "readable": block.isRead(),
                "writable": block.isWrite(),
                "executable": block.isExecute(),
                "volatile": block.isVolatile(),
                "initialized": block.isInitialized(),
                "type": block.getType().toString() if block.getType() else "DEFAULT",
                "source": block.getSourceName(),
            }
        )

    return sections
