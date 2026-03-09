"""Core decompilation logic using pyghidra."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

import click


def _sanitize_name(name: str) -> str:
    """Turn a function name into a safe filename component."""
    return re.sub(r"[^\w\-.]", "_", name)


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
        lines.append(f"// Thunk:    -> {func.getThunkedFunction(True).getName()}")
    lines.append("")
    return "\n".join(lines)


def decompile_binary(
    binary: Path,
    output: Path,
    *,
    timeout: int = 60,
    ghidra_path: Path | None = None,
    base_addr: str | None = None,
) -> None:
    """Decompile a binary and write structured output."""
    import pyghidra

    if ghidra_path:
        pyghidra.start(install_dir=str(ghidra_path))
    else:
        pyghidra.start()

    project_dir = binary.parent / f"{binary.stem}_ghidra"

    with pyghidra.open_program(str(binary)) as flat_api:
        program = flat_api.getCurrentProgram()

        if base_addr is not None:
            _rebase_program(program, base_addr)

        _export_all(program, output, timeout)

    # Clean up Ghidra project cache so runs are always atomic
    if project_dir.is_dir():
        shutil.rmtree(project_dir)


def _rebase_program(program, base_addr: str) -> None:
    """Rebase the program to a new image base address."""
    addr_value = int(base_addr, 0)  # supports 0x hex, decimal, 0o octal
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    new_base = addr_space.getAddress(addr_value)

    old_base = program.getImageBase()
    click.echo(f"Rebasing: {old_base} -> {new_base}")

    tid = program.startTransaction("Rebase image")
    try:
        program.setImageBase(new_base, True)
    finally:
        program.endTransaction(tid, True)


def _export_all(program, output: Path, timeout: int) -> None:
    """Run all exports against an open Ghidra program."""
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()

    # Set up decompiler
    decomp = DecompInterface()
    decomp.openProgram(program)

    func_dir = output / "functions"
    func_dir.mkdir(parents=True, exist_ok=True)

    fm = program.getFunctionManager()
    functions = list(fm.getFunctions(True))
    total = len(functions)

    click.echo(f"Functions: {total}")

    # ---- Decompile all functions ----
    callgraph: dict[str, dict] = {}
    failed = []
    all_chunks: list[str] = []  # for combined file

    with click.progressbar(functions, label="Decompiling", show_pos=True) as bar:
        for func in bar:
            addr = func.getEntryPoint().toString()
            name = func.getName()
            key = f"{addr}_{name}"
            safe_name = _sanitize_name(name)
            filename = f"{addr}_{safe_name}.c"

            header = _func_header_comment(func)

            # Decompile
            results = decomp.decompileFunction(func, timeout, monitor)
            if results.decompileCompleted():
                c_code = results.getDecompiledFunction().getC()
                content = header + c_code
                (func_dir / filename).write_text(content, encoding="utf-8")
                all_chunks.append(content)
            else:
                failed.append(key)
                error_msg = results.getErrorMessage() or "unknown error"
                content = header + f"// DECOMPILATION FAILED: {error_msg}\n"
                (func_dir / filename).write_text(content, encoding="utf-8")
                all_chunks.append(content)

            # Call graph entry
            called_funcs = []
            for called in func.getCalledFunctions(None):
                called_funcs.append({
                    "address": called.getEntryPoint().toString(),
                    "name": called.getName(),
                })

            calling_funcs = []
            for caller in func.getCallingFunctions(None):
                calling_funcs.append({
                    "address": caller.getEntryPoint().toString(),
                    "name": caller.getName(),
                })

            callgraph[addr] = {
                "name": name,
                "address": addr,
                "calls": called_funcs,
                "called_by": calling_funcs,
            }

    decomp.dispose()

    # ---- Combined file ----
    combined = output / "all_functions.c"
    separator = "\n" + ("/" * 80) + "\n\n"
    combined.write_text(separator.join(all_chunks), encoding="utf-8")

    if failed:
        click.echo(f"Failed to decompile {len(failed)} functions")

    # ---- Strings ----
    click.echo("Extracting strings...")
    strings = _extract_strings(program)

    # ---- Imports / Exports ----
    click.echo("Extracting imports & exports...")
    imports = _extract_imports(program)
    exports = _extract_exports(program)

    # ---- Symbols (globals, labels, data) ----
    click.echo("Extracting symbols...")
    symbols = _extract_symbols(program)

    # ---- Types ----
    click.echo("Extracting types...")
    types_content = _extract_types(program)
    (output / "types.h").write_text(types_content, encoding="utf-8")

    # ---- Function index ----
    click.echo("Writing function index...")
    func_index = _extract_functions(functions)

    # ---- Sections ----
    click.echo("Extracting sections...")
    sections = _extract_sections(program)

    # ---- Metadata ----
    lang = program.getLanguage()
    metadata = {
        "binary": program.getExecutablePath(),
        "format": program.getExecutableFormat(),
        "architecture": lang.getProcessor().toString(),
        "endian": lang.isBigEndian() and "big" or "little",
        "address_size": lang.getDefaultSpace().getSize(),
        "image_base": program.getImageBase().toString(),
        "num_functions": total,
        "num_failed": len(failed),
        "failed_functions": failed,
    }

    # ---- Write JSON files ----
    _write_json(output / "functions.json", func_index)
    _write_json(output / "callgraph.json", callgraph)
    _write_json(output / "strings.json", strings)
    _write_json(output / "imports.json", imports)
    _write_json(output / "exports.json", exports)
    _write_json(output / "symbols.json", symbols)
    _write_json(output / "sections.json", sections)
    _write_json(output / "metadata.json", metadata)

    click.echo(
        f"Wrote {total - len(failed)} functions, "
        f"{len(strings)} strings, "
        f"{len(imports)} imports, "
        f"{len(exports)} exports, "
        f"{len(symbols)} symbols, "
        f"{len(sections)} sections"
    )


def _extract_strings(program) -> list[dict]:
    """Extract all defined strings with their xrefs."""
    from ghidra.program.model.data import StringDataType

    ref_manager = program.getReferenceManager()
    fm = program.getFunctionManager()
    listing = program.getListing()
    strings = []

    for data in listing.getDefinedData(True):
        dt = data.getDataType()
        if not isinstance(dt, StringDataType) and "string" not in dt.getName().lower():
            continue

        addr = data.getAddress()
        value = data.getValue()
        if value is None:
            continue
        if isinstance(value, (bytes, bytearray)):
            try:
                value = value.decode("utf-8", errors="replace")
            except Exception:
                value = repr(value)
        else:
            value = str(value)

        # Find xrefs to this string
        xrefs = []
        for ref in ref_manager.getReferencesTo(addr):
            from_addr = ref.getFromAddress()
            func = fm.getFunctionContaining(from_addr)
            xrefs.append({
                "from_address": from_addr.toString(),
                "function": func.getName() if func else None,
                "function_address": func.getEntryPoint().toString() if func else None,
            })

        strings.append({
            "address": addr.toString(),
            "value": value,
            "length": data.getLength(),
            "xrefs": xrefs,
        })

    return strings


def _extract_imports(program) -> list[dict]:
    """Extract imported (external) functions."""
    fm = program.getFunctionManager()
    symbol_table = program.getSymbolTable()
    imports = []

    for func in fm.getExternalFunctions():
        ext_loc = func.getExternalLocation()
        imports.append({
            "name": func.getName(),
            "library": ext_loc.getLibraryName() if ext_loc else None,
            "address": func.getEntryPoint().toString(),
        })

    return imports


def _extract_exports(program) -> list[dict]:
    """Extract exported symbols (entry points)."""
    symbol_table = program.getSymbolTable()
    exports = []

    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint():
            exports.append({
                "name": symbol.getName(),
                "address": symbol.getAddress().toString(),
            })

    return exports


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

        # Try to get data type and size for data symbols
        data = listing.getDataAt(addr)
        if data is not None:
            dt = data.getDataType()
            entry["data_type"] = dt.getName() if dt else None
            entry["size"] = data.getLength()

        symbols.append(entry)

    return symbols


def _extract_types(program) -> str:
    """Extract all recovered types (structs, enums, typedefs) as a C header."""
    dtm = program.getDataTypeManager()
    lines = [
        "// Auto-generated type definitions recovered by Ghidra",
        f"// Binary: {program.getExecutablePath()}",
        "",
    ]

    from ghidra.program.model.data import (
        Structure,
        Union,
        Enum,
        TypeDef,
        FunctionDefinition,
    )

    # Collect types by category for organized output
    structs = []
    unions = []
    enums = []
    typedefs = []
    func_defs = []

    for dt in dtm.getAllDataTypes():
        # Skip built-in types
        path = dt.getCategoryPath().getPath()
        if path.startswith("/") and dt.getName() in (
            "byte", "word", "dword", "qword", "void", "bool",
            "char", "short", "int", "long", "float", "double",
            "uchar", "ushort", "uint", "ulong",
            "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
            "pointer", "string",
        ):
            continue

        if isinstance(dt, Structure):
            structs.append(dt)
        elif isinstance(dt, Union):
            unions.append(dt)
        elif isinstance(dt, Enum):
            enums.append(dt)
        elif isinstance(dt, TypeDef):
            typedefs.append(dt)
        elif isinstance(dt, FunctionDefinition):
            func_defs.append(dt)

    # Enums
    if enums:
        lines.append("// " + "=" * 70)
        lines.append("// ENUMS")
        lines.append("// " + "=" * 70)
        lines.append("")
        for e in sorted(enums, key=lambda x: x.getName()):
            lines.append(f"typedef enum {e.getName()} {{")
            for name in e.getNames():
                val = e.getValue(name)
                lines.append(f"    {name} = {val},")
            lines.append(f"}} {e.getName()};")
            lines.append("")

    # Typedefs
    if typedefs:
        lines.append("// " + "=" * 70)
        lines.append("// TYPEDEFS")
        lines.append("// " + "=" * 70)
        lines.append("")
        for td in sorted(typedefs, key=lambda x: x.getName()):
            base = td.getBaseDataType()
            lines.append(f"typedef {base.getName()} {td.getName()};")
        lines.append("")

    # Structs
    if structs:
        lines.append("// " + "=" * 70)
        lines.append("// STRUCTS")
        lines.append("// " + "=" * 70)
        lines.append("")
        for s in sorted(structs, key=lambda x: x.getName()):
            size = s.getLength()
            lines.append(f"struct {s.getName()} {{ // size: 0x{size:x}")
            for comp in s.getComponents():
                offset = comp.getOffset()
                dt_name = comp.getDataType().getName()
                fname = comp.getFieldName() or f"field_0x{offset:x}"
                comp_size = comp.getLength()
                lines.append(
                    f"    {dt_name} {fname}; "
                    f"// offset: 0x{offset:x}, size: 0x{comp_size:x}"
                )
            lines.append("};")
            lines.append("")

    # Unions
    if unions:
        lines.append("// " + "=" * 70)
        lines.append("// UNIONS")
        lines.append("// " + "=" * 70)
        lines.append("")
        for u in sorted(unions, key=lambda x: x.getName()):
            size = u.getLength()
            lines.append(f"union {u.getName()} {{ // size: 0x{size:x}")
            for comp in u.getComponents():
                dt_name = comp.getDataType().getName()
                fname = comp.getFieldName() or f"field_{comp.getOrdinal()}"
                lines.append(f"    {dt_name} {fname};")
            lines.append("};")
            lines.append("")

    # Function pointer types
    if func_defs:
        lines.append("// " + "=" * 70)
        lines.append("// FUNCTION POINTER TYPES")
        lines.append("// " + "=" * 70)
        lines.append("")
        for fd in sorted(func_defs, key=lambda x: x.getName()):
            ret = fd.getReturnType().getName()
            params = []
            for arg in fd.getArguments():
                params.append(f"{arg.getDataType().getName()} {arg.getName()}")
            param_str = ", ".join(params) if params else "void"
            lines.append(f"typedef {ret} (*{fd.getName()})({param_str});")
        lines.append("")

    return "\n".join(lines) + "\n"


def _extract_functions(functions) -> list[dict]:
    """Extract function index with address ranges and signatures."""
    result = []
    for func in functions:
        entry = func.getEntryPoint()
        body = func.getBody()
        size = body.getNumAddresses()
        ret_type = func.getReturnType().getName() if func.getReturnType() else "void"

        params = []
        for p in func.getParameters():
            dt = p.getDataType().getName() if p.getDataType() else "undefined"
            pname = p.getName() or f"param_{p.getOrdinal()}"
            params.append({"type": dt, "name": pname})

        result.append({
            "name": func.getName(),
            "address": entry.toString(),
            "end_address": body.getMaxAddress().toString(),
            "size": size,
            "return_type": ret_type,
            "params": params,
            "calling_convention": func.getCallingConventionName() or "unknown",
            "is_thunk": func.isThunk(),
        })
    return result


def _extract_sections(program) -> list[dict]:
    """Extract memory sections/segments with permissions."""
    memory = program.getMemory()
    sections = []

    for block in memory.getBlocks():
        sections.append({
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
        })

    return sections


def _write_json(path: Path, data) -> None:
    """Write data as formatted JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
