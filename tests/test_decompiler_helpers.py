"""Focused unit tests for Ghidra extraction helpers."""

import sys
from types import ModuleType, SimpleNamespace

import click
import pytest

from ghidra_decomp.decompiler import (
    STATUS_FAILED,
    STATUS_FALLBACK,
    STATUS_SUCCESS,
    _addresses_with_status,
    _artifact_stem,
    _body_ranges,
    _decompiler_notes,
    _extract_entry_points,
    _extract_exports,
    _extract_function_references,
    _extract_imports,
    _extract_strings,
    _failure_comment,
    _func_header_comment,
    _function_aliases,
    _high_function_locals,
    _high_local_record,
    _mark_entry,
    _parse_address,
    _sanitize_name,
    _summarize_statuses,
    _symbols_at,
    _thunk_target,
    _variable_record,
    decompile_binary,
)


class Address:
    def __init__(self, value):
        self.value = value

    def toString(self):
        return self.value

    def __str__(self):
        return self.value


def test_artifact_stem_is_bounded_ascii_portable_and_collision_resistant():
    first = _artifact_stem("overlay:8000", "CON/" + "\N{SNOWMAN}" * 200)
    second = _artifact_stem("overlay:8000", "CON?" + "\N{SNOWMAN}" * 200)

    assert len(first) <= 120
    assert first.isascii()
    assert all(char.isalnum() or char in "._-" for char in first)
    assert first != second
    assert _sanitize_name("NUL") == "_NUL"


def test_multiline_failure_is_fully_commented():
    content = _failure_comment("first line\nsecond line")

    assert content.splitlines() == [
        "// DECOMPILATION FAILED: first line",
        "// DECOMPILATION FAILED: second line",
    ]


def test_parse_address_uses_string_overload_for_unsigned_high_half():
    space = SimpleNamespace(getSize=lambda: 64)
    received = []
    space.getAddress = lambda value: received.append(value) or Address(value)
    program = SimpleNamespace(
        getAddressFactory=lambda: SimpleNamespace(getDefaultAddressSpace=lambda: space)
    )

    address = _parse_address(
        program, "0xffff800000000000", label="entry", param_hint="'--entry'"
    )

    assert address.toString() == "ffff800000000000"
    assert received == ["ffff800000000000"]


def test_parse_address_rejects_out_of_range_value():
    space = SimpleNamespace(getSize=lambda: 32)
    program = SimpleNamespace(
        getAddressFactory=lambda: SimpleNamespace(getDefaultAddressSpace=lambda: space)
    )

    with pytest.raises(click.BadParameter, match="outside the 32-bit address space"):
        _parse_address(program, "0x100000000", label="entry", param_hint="'--entry'")


def test_mark_entry_rejects_address_outside_memory_before_transaction():
    address = Address("1000")
    space = SimpleNamespace(getSize=lambda: 32, getAddress=lambda value: address)
    program = SimpleNamespace(
        getAddressFactory=lambda: SimpleNamespace(getDefaultAddressSpace=lambda: space),
        getMemory=lambda: SimpleNamespace(contains=lambda candidate: False),
    )

    with pytest.raises(click.ClickException, match="not in program memory"):
        _mark_entry(program, object(), "0x1000")


def test_mark_entry_rolls_back_when_disassembly_produces_no_instruction():
    address = Address("1000")
    transactions = []
    space = SimpleNamespace(getSize=lambda: 32, getAddress=lambda value: address)
    program = SimpleNamespace(
        getAddressFactory=lambda: SimpleNamespace(getDefaultAddressSpace=lambda: space),
        getMemory=lambda: SimpleNamespace(contains=lambda candidate: True),
        getListing=lambda: SimpleNamespace(getInstructionAt=lambda candidate: None),
        startTransaction=lambda name: 7,
        endTransaction=lambda transaction, commit: transactions.append(
            (transaction, commit)
        ),
    )
    flat_api = SimpleNamespace(disassemble=lambda candidate: False)

    with pytest.raises(click.ClickException, match="could not disassemble"):
        _mark_entry(program, flat_api, "0x1000")

    assert transactions == [(7, False)]


def test_empty_input_is_rejected_before_ghidra_start(tmp_path):
    binary = tmp_path / "empty.bin"
    binary.touch()

    with pytest.raises(click.ClickException, match="Input file is empty"):
        decompile_binary(binary, tmp_path / "output")

    assert not (tmp_path / "output").exists()


def test_function_references_include_offcut_sources():
    source = Address("1001")
    target = Address("2000")
    ref_type = SimpleNamespace(
        isCall=lambda: True, __str__=lambda self: "UNCONDITIONAL_CALL"
    )
    ref = SimpleNamespace(
        getFromAddress=lambda: source,
        getToAddress=lambda: target,
        getReferenceType=lambda: ref_type,
        getOperandIndex=lambda: 0,
        getSource=lambda: "ANALYSIS",
        isPrimary=lambda: True,
    )
    ref_manager = SimpleNamespace(
        getReferenceSourceIterator=lambda body, forward: [source],
        getReferencesFrom=lambda address: [ref],
    )
    function_manager = SimpleNamespace(
        getFunctionAt=lambda address: None,
        getFunctionContaining=lambda address: None,
    )
    program = SimpleNamespace(
        getReferenceManager=lambda: ref_manager,
        getFunctionManager=lambda: function_manager,
    )
    function = SimpleNamespace(
        getBody=lambda: object(),
        getEntryPoint=lambda: Address("1000"),
        getName=lambda: "offcut_caller",
    )

    references, calls = _extract_function_references(program, function)

    assert references[0]["from_address"] == "1001"
    assert calls[0]["call_site"] == "1001"


def test_imports_include_external_and_linkage_addresses():
    external = Address("EXTERNAL:1")
    external_location = SimpleNamespace(
        getAddress=lambda: Address("other:1234"),
        getLibraryName=lambda: "library",
    )
    function = SimpleNamespace(
        getName=lambda: "imported",
        getEntryPoint=lambda: external,
        getExternalLocation=lambda: external_location,
        getFunctionThunkAddresses=lambda recursive: [Address("2000"), Address("1000")],
    )
    program = SimpleNamespace(
        getFunctionManager=lambda: SimpleNamespace(
            getExternalFunctions=lambda: [function]
        )
    )

    assert _extract_imports(program) == [
        {
            "name": "imported",
            "library": "library",
            "address": "EXTERNAL:1",
            "external_address": "other:1234",
            "linkage_addresses": ["1000", "2000"],
        }
    ]


def test_strings_skip_none_and_retain_string_valued_char_arrays(monkeypatch):
    data_module = ModuleType("ghidra.program.model.data")

    class AbstractStringDataType:
        pass

    data_module.AbstractStringDataType = AbstractStringDataType
    monkeypatch.setitem(sys.modules, "ghidra.program.model.data", data_module)

    def defined_data(data_type, value, address):
        return SimpleNamespace(
            getDataType=lambda: data_type,
            getValue=lambda: value,
            getAddress=lambda: Address(address),
            getLength=lambda: 8,
        )

    items = [
        defined_data(AbstractStringDataType(), None, "1000"),
        defined_data(object(), "char array", "2000"),
        defined_data(object(), None, "3000"),
    ]
    program = SimpleNamespace(
        getReferenceManager=lambda: SimpleNamespace(getReferencesTo=lambda address: []),
        getFunctionManager=lambda: object(),
        getListing=lambda: SimpleNamespace(getDefinedData=lambda forward: items),
    )

    assert _extract_strings(program) == [
        {"address": "2000", "value": "char array", "length": 8, "xrefs": []}
    ]


def test_exports_select_one_global_primary_symbol_per_address():
    global_namespace = SimpleNamespace(
        isGlobal=lambda: True, getName=lambda qualified: "Global"
    )
    local_namespace = SimpleNamespace(
        isGlobal=lambda: False, getName=lambda qualified: "function"
    )

    def symbol(name, address, namespace, primary):
        return SimpleNamespace(
            getName=lambda: name,
            getAddress=lambda: Address(address),
            getParentNamespace=lambda: namespace,
            isPrimary=lambda: primary,
            isExternalEntryPoint=lambda: True,
        )

    symbols = [
        symbol("$x", "1000", local_namespace, False),
        symbol("exported", "1000", global_namespace, True),
        symbol("exported_alias", "1000", global_namespace, False),
        symbol(".L0", "2000", local_namespace, True),
        symbol("global_fallback", "2000", global_namespace, False),
    ]
    program = SimpleNamespace(
        getSymbolTable=lambda: SimpleNamespace(getAllSymbols=lambda forward: symbols)
    )

    assert _extract_exports(program) == [
        {
            "name": "exported",
            "address": "1000",
            "namespace": "Global",
            "is_primary": True,
        },
        {
            "name": "global_fallback",
            "address": "2000",
            "namespace": "Global",
            "is_primary": False,
        },
    ]


def test_symbols_at_preserves_primary_and_alias_symbols():
    namespace = SimpleNamespace(getName=lambda include_namespace: "global")
    symbol_type = SimpleNamespace(toString=lambda: "Label")

    def symbol(name, primary):
        return SimpleNamespace(
            getName=lambda: name,
            getParentNamespace=lambda: namespace,
            getSymbolType=lambda: symbol_type,
            isPrimary=lambda: primary,
        )

    symbols = [symbol("primary", True), symbol("alias", False)]
    program = SimpleNamespace(
        getSymbolTable=lambda: SimpleNamespace(getSymbols=lambda address: symbols)
    )

    assert _symbols_at(program, Address("1000")) == [
        {
            "name": "primary",
            "namespace": "global",
            "type": "Label",
            "is_primary": True,
        },
        {
            "name": "alias",
            "namespace": "global",
            "type": "Label",
            "is_primary": False,
        },
    ]


def test_function_aliases_are_unique_and_retain_nonprimary_same_name():
    symbols = [
        {"name": "function", "is_primary": True},
        {"name": "function", "is_primary": False},
        {"name": "alias", "is_primary": False},
        {"name": "alias", "is_primary": False},
    ]

    assert _function_aliases("function", symbols) == ["function", "alias"]


def test_manifest_entry_points_exclude_non_executable_data_exports(monkeypatch):
    exports = [{"address": value} for value in ("1000", "2000", "3000")]
    monkeypatch.setattr(
        "ghidra_decomp.decompiler._extract_exports", lambda program: exports
    )
    blocks = {
        "1000": SimpleNamespace(isExecute=lambda: False),
        "2000": SimpleNamespace(isExecute=lambda: True),
        "3000": SimpleNamespace(isExecute=lambda: False),
    }
    program = SimpleNamespace(
        getAddressFactory=lambda: SimpleNamespace(
            getAddress=lambda value: Address(value)
        ),
        getFunctionManager=lambda: SimpleNamespace(
            getFunctionAt=lambda address: object() if address.value == "1000" else None
        ),
        getMemory=lambda: SimpleNamespace(
            getBlock=lambda address: blocks[address.value]
        ),
    )

    assert _extract_entry_points(program) == ["1000", "2000"]


def _range(start, end):
    return SimpleNamespace(
        getMinAddress=lambda: Address(start), getMaxAddress=lambda: Address(end)
    )


def test_body_ranges_preserves_every_range_of_a_noncontiguous_function():
    body = SimpleNamespace(
        getAddressRanges=lambda forward: [
            _range("00100234", "0010028f"),
            _range("00100400", "0010043f"),
        ]
    )

    assert _body_ranges(body) == [
        {"start": "00100234", "end": "0010028f"},
        {"start": "00100400", "end": "0010043f"},
    ]


def test_body_ranges_is_empty_for_a_function_without_addresses():
    assert _body_ranges(SimpleNamespace(getAddressRanges=lambda forward: [])) == []


def _status_record(address, status, reused=False):
    return {
        "address": address,
        "decompilation": {"status": status, "error": None, "reused": reused},
    }


def test_status_summary_counts_every_decompilation_outcome():
    records = [
        _status_record("1000", STATUS_SUCCESS),
        _status_record("2000", STATUS_SUCCESS, reused=True),
        _status_record("3000", STATUS_FALLBACK),
        _status_record("4000", STATUS_FAILED),
    ]

    counts = _summarize_statuses(records)

    assert counts == {
        "discovered": 4,
        "successful": 2,
        "fallback": 1,
        "failed": 1,
        "skipped": 1,
    }
    # Outcomes partition the corpus; reuse is a separate dimension that overlaps
    # them, so it is deliberately excluded from this identity.
    assert counts["discovered"] == (
        counts["successful"] + counts["fallback"] + counts["failed"]
    )
    assert counts["skipped"] <= counts["discovered"]
    assert _addresses_with_status(records, STATUS_FAILED) == ["4000"]
    assert _addresses_with_status(records, STATUS_FALLBACK) == ["3000"]


def test_status_summary_counts_reuse_independently_of_outcome():
    records = [
        _status_record("1000", STATUS_SUCCESS, reused=True),
        _status_record("2000", STATUS_FALLBACK, reused=True),
    ]

    counts = _summarize_statuses(records)

    assert counts["skipped"] == 2
    assert counts["successful"] == 1
    assert counts["fallback"] == 1


def test_status_summary_counts_an_unknown_status_as_failed():
    counts = _summarize_statuses([_status_record("1000", "bogus")])

    assert counts["failed"] == 1
    assert counts["discovered"] == 1


def test_status_summary_of_an_empty_corpus_is_all_zero():
    assert _summarize_statuses([]) == {
        "discovered": 0,
        "successful": 0,
        "fallback": 0,
        "failed": 0,
        "skipped": 0,
    }


def _thunk(target=None, is_thunk=True):
    return SimpleNamespace(
        isThunk=lambda: is_thunk,
        getThunkedFunction=lambda recursive: target,
    )


def test_a_thunk_records_its_target_name_and_address():
    target = SimpleNamespace(
        getName=lambda: "getenv", getEntryPoint=lambda: Address("EXTERNAL:00000001")
    )

    assert _thunk_target(_thunk(target)) == {
        "name": "getenv",
        "address": "EXTERNAL:00000001",
    }


def test_a_thunk_with_an_unresolvable_target_still_records_the_keys():
    # The shape stays stable so a consumer never has to test for a missing block.
    assert _thunk_target(_thunk(None)) == {"name": None, "address": None}


def test_a_plain_function_records_no_thunk_target():
    assert _thunk_target(_thunk(None, is_thunk=False)) is None


def test_a_thunk_is_followed_to_its_final_target():
    seen = []
    target = SimpleNamespace(
        getName=lambda: "final", getEntryPoint=lambda: Address("2000")
    )
    func = SimpleNamespace(
        isThunk=lambda: True,
        getThunkedFunction=lambda recursive: seen.append(recursive) or target,
    )

    _thunk_target(func)

    assert seen == [True], "a thunk chain must be followed to the end"


def test_decompiler_warnings_are_extracted_from_the_pseudocode():
    c_code = (
        "/* WARNING: Subroutine does not return */\n"
        "void abort_wrapper(void)\n{\n  abort();\n}\n"
    )

    assert _decompiler_notes(c_code) == [
        {"kind": "warning", "text": "Subroutine does not return"}
    ]


def test_every_warning_in_one_function_is_kept():
    c_code = (
        "/* WARNING: Subroutine does not return */\n"
        "/* WARNING: Removing unreachable block (ram,0x00102874) */\n"
        "void f(void) { }\n"
    )

    notes = _decompiler_notes(c_code)

    assert [note["text"] for note in notes] == [
        "Subroutine does not return",
        "Removing unreachable block (ram,0x00102874)",
    ]


def test_a_multiline_warning_block_is_collapsed_into_one_note():
    # The x86-32 fixture emits exactly this shape.
    c_code = (
        "u32 f(void)\n{\n    /* Unresolved local var: u32 total@[???]\n     */\n}\n"
    )

    assert _decompiler_notes(c_code) == [
        {"kind": "unresolved_local", "text": "u32 total@[???]"}
    ]


def test_an_unresolved_local_is_classified_apart_from_a_warning():
    c_code = (
        "/* WARNING: Unknown calling convention */\n"
        "u32 f(void)\n{\n  /* Unresolved local var: u32 mixed@[???] */\n}\n"
    )

    assert [note["kind"] for note in _decompiler_notes(c_code)] == [
        "warning",
        "unresolved_local",
    ]


def test_an_unrecognized_comment_is_kept_verbatim_as_a_note():
    notes = _decompiler_notes("/* Something Ghidra has not said before */\nvoid f(){}")

    assert notes == [{"kind": "note", "text": "Something Ghidra has not said before"}]


def test_the_tools_own_header_is_never_parsed_as_a_warning():
    # The header and failure comments are `//`, so they cannot be picked up.
    header = _func_header_comment(
        SimpleNamespace(
            getEntryPoint=lambda: Address("1000"),
            getName=lambda: "f",
            getBody=lambda: SimpleNamespace(getNumAddresses=lambda: 4),
            getCallingConventionName=lambda: "__cdecl",
            getParameterCount=lambda: 0,
            isThunk=lambda: False,
        )
    )

    assert _decompiler_notes(header) == []
    assert _decompiler_notes(_failure_comment("boom")) == []


def test_pseudocode_without_comments_yields_no_warnings():
    assert _decompiler_notes("int f(void) { return 0; }") == []
    assert _decompiler_notes("") == []


def test_an_empty_comment_block_is_not_recorded():
    assert _decompiler_notes("/*  */\nvoid f(){}") == []


class Storage:
    """A real class, because `str(storage)` must reach a `__str__` on the type."""

    def __init__(self, kind="register", register="EAX", offset=None):
        self.kind = kind
        self.register = register
        self.offset = offset

    def isUnassignedStorage(self):
        return self.kind == "unassigned"

    def isStackStorage(self):
        return self.kind == "stack"

    def isRegisterStorage(self):
        return self.kind == "register"

    def isMemoryStorage(self):
        return self.kind == "memory"

    def getStackOffset(self):
        return self.offset

    def getRegister(self):
        return SimpleNamespace(getName=lambda: self.register)

    def __str__(self):
        return f"{self.register or 'Stack'}:4"


def _storage(kind="register", register="EAX", offset=None):
    return Storage(kind, register, offset)


def _high_symbol(name, type_name, storage, is_parameter=False, size=4):
    return SimpleNamespace(
        getName=lambda: name,
        getDataType=lambda: SimpleNamespace(getName=lambda: type_name),
        getSize=lambda: size,
        getStorage=lambda: storage,
        isParameter=lambda: is_parameter,
    )


def _decompile_result(symbols):
    return SimpleNamespace(
        getHighFunction=lambda: SimpleNamespace(
            getLocalSymbolMap=lambda: SimpleNamespace(getSymbols=lambda: symbols)
        )
    )


def test_a_high_local_records_its_register_storage():
    symbol = _high_symbol("uVar1", "u32", _storage("register", "EAX"))

    assert _high_local_record(symbol) == {
        "name": "uVar1",
        "data_type": "u32",
        "size": 4,
        "storage": {
            "kind": "register",
            "register": "EAX",
            "stack_offset": None,
            "description": "EAX:4",
        },
        "source": None,
    }


def test_a_high_local_records_its_stack_offset():
    symbol = _high_symbol("local_10", "int", _storage("stack", None, -16))

    record = _high_local_record(symbol)

    assert record["storage"]["kind"] == "stack"
    assert record["storage"]["stack_offset"] == -16
    assert record["storage"]["register"] is None


def test_storage_records_are_identical_for_both_variable_kinds():
    # A register local and a register parameter must serialize the same way, or
    # a consumer has to special-case where the variable came from.
    storage = _storage("register", "EBX")
    high = _high_local_record(_high_symbol("uVar1", "u32", storage))
    plain = _variable_record(
        SimpleNamespace(
            getName=lambda: "uVar1",
            getDataType=lambda: SimpleNamespace(getName=lambda: "u32"),
            getLength=lambda: 4,
            getVariableStorage=lambda: storage,
            getSource=lambda: "USER_DEFINED",
        )
    )

    assert high["storage"] == plain["storage"]
    assert set(high) == set(plain)


def test_high_function_parameters_are_excluded_from_locals():
    symbols = [
        _high_symbol("values", "int *", _storage("stack", None, 4), is_parameter=True),
        _high_symbol("uVar1", "u32", _storage("register", "EAX")),
    ]

    locals_ = _high_function_locals(_decompile_result(symbols))

    assert [item["name"] for item in locals_] == ["uVar1"]


def test_locals_are_empty_when_the_decompiler_produced_no_high_function():
    assert _high_function_locals(None) == []
    assert _high_function_locals(SimpleNamespace(getHighFunction=lambda: None)) == []
    assert (
        _high_function_locals(
            SimpleNamespace(
                getHighFunction=lambda: SimpleNamespace(getLocalSymbolMap=lambda: None)
            )
        )
        == []
    )


def test_a_high_local_without_a_data_type_is_still_recorded():
    symbol = SimpleNamespace(
        getName=lambda: "unnamed",
        getDataType=lambda: None,
        getSize=lambda: 0,
        getStorage=lambda: None,
        isParameter=lambda: False,
    )

    record = _high_local_record(symbol)

    assert record["data_type"] == "undefined"
    assert record["storage"]["kind"] == "unassigned"
