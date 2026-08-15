"""Focused unit tests for Ghidra extraction helpers."""

from types import SimpleNamespace

import click
import pytest

from ghidra_decomp.decompiler import (
    _artifact_stem,
    _extract_entry_points,
    _extract_function_references,
    _extract_imports,
    _failure_comment,
    _function_aliases,
    _mark_entry,
    _parse_address,
    _sanitize_name,
    _symbols_at,
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
