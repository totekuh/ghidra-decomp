"""Core decompilation logic using pyghidra."""

from __future__ import annotations

import json
import re
import shutil
from contextlib import ExitStack
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
        thunked = func.getThunkedFunction(True)
        thunk_name = thunked.getName() if thunked else "unknown"
        lines.append(f"// Thunk:    -> {thunk_name}")
    lines.append("")
    return "\n".join(lines)


def _start_pyghidra(ghidra_path: Path | None):
    """Import and start pyghidra, returning the module."""
    try:
        import pyghidra
    except ImportError:
        raise click.ClickException(
            "pyghidra is not installed. Install it with: pip install pyghidra\n"
            "pyghidra is bundled with Ghidra 11+."
        )

    if not pyghidra.started():
        install_dir = str(ghidra_path) if ghidra_path else None
        try:
            pyghidra.start(install_dir=install_dir) if install_dir else pyghidra.start()
        except Exception as e:
            hint = ""
            if not ghidra_path:
                hint = (
                    "\nSet GHIDRA_INSTALL_DIR or pass --ghidra-path "
                    "to your Ghidra installation."
                )
            raise click.ClickException(f"Failed to start Ghidra: {e}{hint}")

    return pyghidra


def list_languages(*, ghidra_path: Path | None = None) -> None:
    """Print all Ghidra language IDs with their available compiler specs."""
    _start_pyghidra(ghidra_path)

    from ghidra.program.util import DefaultLanguageService

    svc = DefaultLanguageService.getLanguageService()
    descs = list(svc.getLanguageDescriptions(False))
    descs.sort(key=lambda d: str(d.getLanguageID()))

    for d in descs:
        lang_id = str(d.getLanguageID())
        processor = str(d.getProcessor())
        endian = str(d.getEndian())
        size = d.getSize()
        cspecs = [
            str(c.getCompilerSpecID())
            for c in d.getCompatibleCompilerSpecDescriptions()
        ]
        click.echo(
            f"{lang_id}  [{processor} {endian} {size}]  cspec: {', '.join(cspecs) or '-'}"
        )

    click.echo(f"\n{len(descs)} language(s).")


def decompile_binary(
    binary: Path,
    output: Path,
    *,
    timeout: int = 60,
    ghidra_path: Path | None = None,
    base_addr: str | None = None,
    language: str | None = None,
    compiler: str | None = None,
    entry: str | None = None,
) -> None:
    """Decompile a binary and write structured output."""
    pyghidra = _start_pyghidra(ghidra_path)

    open_kwargs: dict[str, object] = {"analyze": False}
    if language is not None:
        open_kwargs["language"] = language
    if compiler is not None:
        open_kwargs["compiler"] = compiler

    stack = ExitStack()
    try:
        flat_api = stack.enter_context(
            pyghidra.open_program(str(binary), **open_kwargs)
        )
    except Exception as e:
        msg = str(e)
        if "No load spec found" in msg:
            hint = (
                f"Ghidra could not identify {binary.name}. Likely a raw or unknown "
                "format.\nPass --language (and optionally --compiler) to force a "
                "spec. Run with --list-languages to discover IDs."
            )
        elif language is not None:
            hint = (
                f"Failed to load with --language {language}"
                + (f" --compiler {compiler}" if compiler else "")
                + f": {msg}"
            )
        else:
            hint = f"Failed to open program: {msg}"
        raise click.ClickException(hint)

    with stack:
        program = flat_api.getCurrentProgram()

        # Grab the project directory so we can clean it up after closing
        project_loc = program.getDomainFile().getProjectLocator()
        project_dir = Path(str(project_loc.getProjectDir())) if project_loc else None

        if base_addr is not None:
            _rebase_program(program, base_addr)

        if entry is not None:
            _mark_entry(program, flat_api, entry)

        _run_analysis(program, flat_api)

        _export_all(program, output, timeout)

    # Clean up Ghidra project cache so runs are always atomic
    if project_dir and project_dir.is_dir():
        try:
            shutil.rmtree(project_dir)
        except OSError as e:
            click.echo(f"Warning: could not clean up Ghidra cache: {e}", err=True)
    # Also clean siblings (.gpr file, or .rep directory)
    if project_dir:
        if project_dir.name.endswith(".rep"):
            # Clean the .gpr project file
            gpr_file = project_dir.parent / (project_dir.name[:-4] + ".gpr")
            if gpr_file.is_file():
                try:
                    gpr_file.unlink()
                except OSError:
                    pass
        else:
            # Clean the .rep repository directory
            rep_dir = project_dir.parent / (project_dir.name + ".rep")
            if rep_dir.is_dir() and rep_dir != project_dir:
                try:
                    shutil.rmtree(rep_dir)
                except OSError:
                    pass


def _rebase_program(program, base_addr: str) -> None:
    """Rebase the program to a new image base address."""
    try:
        addr_value = int(base_addr, 0)  # supports 0x hex, decimal, 0o octal
    except ValueError:
        raise click.BadParameter(
            f"Invalid base address: {base_addr!r}. "
            "Use hex (0x80000000), decimal, or octal (0o...) format.",
            param_hint="'--base-addr'",
        )
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    new_base = addr_space.getAddress(addr_value)

    old_base = program.getImageBase()
    click.echo(f"Rebasing: {old_base} -> {new_base}")

    success = False
    tid = program.startTransaction("Rebase image")
    try:
        program.setImageBase(new_base, True)
        success = True
    finally:
        program.endTransaction(tid, success)


def _mark_entry(program, flat_api, entry: str) -> None:
    """Disassemble from entry, create a function there, mark as program entry."""
    try:
        addr_value = int(entry, 0)
    except ValueError:
        raise click.BadParameter(
            f"Invalid entry address: {entry!r}. "
            "Use hex (0x31000), decimal, or octal (0o...) format.",
            param_hint="'--entry'",
        )
    addr_space = program.getAddressFactory().getDefaultAddressSpace()
    entry_addr = addr_space.getAddress(addr_value)
    click.echo(f"Entry:   {entry_addr}")

    success = False
    tid = program.startTransaction("Mark entry point")
    try:
        program.getSymbolTable().addExternalEntryPoint(entry_addr)
        flat_api.disassemble(entry_addr)
        if flat_api.getFunctionAt(entry_addr) is None:
            flat_api.createFunction(entry_addr, "entry")
        success = True
    finally:
        program.endTransaction(tid, success)


def _run_analysis(program, flat_api) -> None:
    """Run Ghidra's auto-analysis on the program."""
    click.echo("Running auto-analysis...")
    success = False
    tid = program.startTransaction("Auto-analysis")
    try:
        flat_api.analyzeAll(program)
        success = True
    finally:
        program.endTransaction(tid, success)


def _export_all(program, output: Path, timeout: int) -> None:
    """Run all exports against an open Ghidra program."""
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()

    # Set up decompiler
    decomp = DecompInterface()
    decomp.openProgram(program)

    func_dir = output / "functions"
    if func_dir.exists():
        shutil.rmtree(func_dir)
    func_dir.mkdir(parents=True, exist_ok=True)

    fm = program.getFunctionManager()
    total = fm.getFunctionCount()
    functions = list(fm.getFunctions(True))

    click.echo(f"Functions: {total}")

    # ---- Decompile all functions ----
    callgraph: dict[str, dict] = {}
    failed: list[tuple] = []  # (func, key, filename) for retry
    results_map: dict[
        str, str | None
    ] = {}  # key -> content, preserves order for combined file

    try:
        with click.progressbar(functions, label="Decompiling", show_pos=True) as bar:
            for func in bar:
                addr = func.getEntryPoint().toString()
                name = func.getName()
                key = f"{addr}_{name}"
                safe_name = _sanitize_name(name)
                filename = f"{addr}_{safe_name}.c"

                try:
                    header = _func_header_comment(func)

                    # Decompile
                    result = decomp.decompileFunction(func, timeout, monitor)
                    if result and result.decompileCompleted():
                        decomp_func = result.getDecompiledFunction()
                        c_code = decomp_func.getC() if decomp_func else None
                        if c_code is not None:
                            content = header + c_code
                            (func_dir / filename).write_text(content, encoding="utf-8")
                            results_map[key] = content
                        else:
                            failed.append((func, key, filename))
                            results_map[key] = None
                    else:
                        failed.append((func, key, filename))
                        results_map[key] = None
                except Exception as e:
                    click.echo(
                        f"\nWarning: error decompiling {name} at {addr}: {e}", err=True
                    )
                    results_map[key] = None
                    if (func, key, filename) not in failed:
                        failed.append((func, key, filename))

                # Call graph entry (independent of decompilation success)
                try:
                    called_funcs = []
                    for called in func.getCalledFunctions(None):
                        called_funcs.append(
                            {
                                "address": called.getEntryPoint().toString(),
                                "name": called.getName(),
                            }
                        )

                    calling_funcs = []
                    for caller in func.getCallingFunctions(None):
                        calling_funcs.append(
                            {
                                "address": caller.getEntryPoint().toString(),
                                "name": caller.getName(),
                            }
                        )

                    callgraph[addr] = {
                        "name": name,
                        "address": addr,
                        "calls": called_funcs,
                        "called_by": calling_funcs,
                    }
                except Exception as e:
                    click.echo(
                        f"\nWarning: error extracting call graph for {name} at {addr}: {e}",
                        err=True,
                    )

        # ---- Retry failed functions with escalated timeout ----
        if failed:
            retry_timeout = timeout * 3
            click.echo(
                f"Retrying {len(failed)} failed functions "
                f"with {retry_timeout}s timeout..."
            )
            still_failed = []
            with click.progressbar(failed, label="Retrying", show_pos=True) as bar:
                for func, key, filename in bar:
                    try:
                        header = _func_header_comment(func)
                        result = decomp.decompileFunction(func, retry_timeout, monitor)
                        decomp_func = (
                            result.getDecompiledFunction()
                            if result and result.decompileCompleted()
                            else None
                        )
                        c_code = decomp_func.getC() if decomp_func else None
                        if c_code is not None:
                            content = header + c_code
                        else:
                            still_failed.append(key)
                            error_msg = (
                                result.getErrorMessage() if result else None
                            ) or "unknown error"
                            asm = _disassemble_function(program, func)
                            content = (
                                header + f"// DECOMPILATION FAILED: {error_msg}\n" + asm
                            )
                        (func_dir / filename).write_text(content, encoding="utf-8")
                        results_map[key] = content
                    except Exception as e:
                        click.echo(f"\nWarning: error retrying {key}: {e}", err=True)
                        still_failed.append(key)
                        # Write a minimal fallback file
                        fallback = (
                            f"// DECOMPILATION FAILED: exception during retry: {e}\n"
                        )
                        (func_dir / filename).write_text(fallback, encoding="utf-8")
                        results_map[key] = fallback
            failed = still_failed
    finally:
        decomp.dispose()

    # ---- Combined file ----
    all_chunks = [c for c in results_map.values() if c is not None]
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
    types = _extract_types(program)

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
    _write_json(output / "types.json", types)
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


def _disassemble_function(program, func) -> str:
    """Return the assembly listing for a function as commented C lines."""
    listing = program.getListing()
    lines = ["// Assembly listing:\n"]
    for instr in listing.getInstructions(func.getBody(), True):
        addr = instr.getAddress()
        mnemonic = instr.getMnemonicString()
        num_ops = instr.getNumOperands()
        operands = ", ".join(
            instr.getDefaultOperandRepresentation(i) for i in range(num_ops)
        )
        lines.append(f"//   {addr}  {mnemonic}  {operands}\n")
    return "".join(lines)


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
        imports.append(
            {
                "name": func.getName(),
                "library": ext_loc.getLibraryName() if ext_loc else None,
                "address": func.getEntryPoint().toString(),
            }
        )

    return imports


def _extract_exports(program) -> list[dict]:
    """Extract exported symbols (entry points)."""
    symbol_table = program.getSymbolTable()
    exports = []

    for symbol in symbol_table.getAllSymbols(True):
        if symbol.isExternalEntryPoint():
            exports.append(
                {
                    "name": symbol.getName(),
                    "address": symbol.getAddress().toString(),
                }
            )

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


def _extract_types(program) -> list[dict]:
    """Extract all recovered types (structs, enums, typedefs, unions, function pointers)."""
    dtm = program.getDataTypeManager()

    from ghidra.program.model.data import (
        Structure,
        Union,
        Enum,
        TypeDef,
        FunctionDefinition,
    )

    BUILTIN = {
        "byte",
        "word",
        "dword",
        "qword",
        "void",
        "bool",
        "char",
        "short",
        "int",
        "long",
        "float",
        "double",
        "uchar",
        "ushort",
        "uint",
        "ulong",
        "undefined",
        "undefined1",
        "undefined2",
        "undefined4",
        "undefined8",
        "pointer",
        "string",
    }

    result = []

    for dt in dtm.getAllDataTypes():
        if dt.getName() in BUILTIN:
            continue

        if isinstance(dt, Structure):
            fields = []
            for comp in dt.getComponents():
                fields.append(
                    {
                        "name": comp.getFieldName() or f"field_0x{comp.getOffset():x}",
                        "type": comp.getDataType().getName(),
                        "offset": comp.getOffset(),
                        "size": comp.getLength(),
                    }
                )
            result.append(
                {
                    "kind": "struct",
                    "name": dt.getName(),
                    "size": dt.getLength(),
                    "fields": fields,
                }
            )

        elif isinstance(dt, Union):
            fields = []
            for comp in dt.getComponents():
                fields.append(
                    {
                        "name": comp.getFieldName() or f"field_{comp.getOrdinal()}",
                        "type": comp.getDataType().getName(),
                        "size": comp.getLength(),
                    }
                )
            result.append(
                {
                    "kind": "union",
                    "name": dt.getName(),
                    "size": dt.getLength(),
                    "fields": fields,
                }
            )

        elif isinstance(dt, Enum):
            members = {}
            for name in dt.getNames():
                members[name] = dt.getValue(name)
            result.append(
                {
                    "kind": "enum",
                    "name": dt.getName(),
                    "size": dt.getLength(),
                    "members": members,
                }
            )

        elif isinstance(dt, TypeDef):
            base = dt.getBaseDataType()
            result.append(
                {
                    "kind": "typedef",
                    "name": dt.getName(),
                    "base_type": base.getName() if base else "unknown",
                }
            )

        elif isinstance(dt, FunctionDefinition):
            params = []
            for arg in dt.getArguments():
                params.append(
                    {"type": arg.getDataType().getName(), "name": arg.getName()}
                )
            ret = dt.getReturnType()
            result.append(
                {
                    "kind": "function_pointer",
                    "name": dt.getName(),
                    "return_type": ret.getName() if ret else "void",
                    "params": params,
                }
            )

    return result


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

        result.append(
            {
                "name": func.getName(),
                "address": entry.toString(),
                "end_address": body.getMaxAddress().toString(),
                "size": size,
                "return_type": ret_type,
                "params": params,
                "calling_convention": func.getCallingConventionName() or "unknown",
                "is_thunk": func.isThunk(),
            }
        )
    return result


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


def _write_json(path: Path, data) -> None:
    """Write data as formatted JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
