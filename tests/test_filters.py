"""Unit tests for function selection filters."""

from types import SimpleNamespace

import click
import pytest

from ghidra_decomp.decompiler import (
    compile_filters,
    normalize_filters,
    select_functions,
)


def _function(address, name):
    return SimpleNamespace(
        getEntryPoint=lambda: SimpleNamespace(toString=lambda: address),
        getName=lambda: name,
    )


FUNCTIONS = [
    _function("1000", "parse_config"),
    _function("2000", "parse_header"),
    _function("3000", "main"),
    _function("4000", "_start"),
]


def _names(selected):
    return [func.getName() for func in selected]


def _select(include=(), exclude=(), addresses=()):
    compiled_include, compiled_exclude = compile_filters(include, exclude)
    return _names(
        select_functions(
            FUNCTIONS,
            include=compiled_include,
            exclude=compiled_exclude,
            addresses=set(addresses),
        )
    )


def test_no_filters_keeps_every_function():
    assert _select() == ["parse_config", "parse_header", "main", "_start"]


def test_include_keeps_only_matching_names():
    assert _select(include=("^parse_",)) == ["parse_config", "parse_header"]


def test_include_is_a_union_of_its_patterns():
    assert _select(include=("^main$", "^_start$")) == ["main", "_start"]


def test_exclude_removes_matching_names():
    assert _select(exclude=("^parse_",)) == ["main", "_start"]


def test_exclude_is_applied_after_include():
    assert _select(include=("^parse_",), exclude=("header",)) == ["parse_config"]


def test_an_explicit_address_survives_the_name_filters():
    assert _select(include=("^nothing_matches$",), addresses=("3000",)) == ["main"]


def test_an_explicit_address_is_kept_even_when_excluded():
    # The operator named this function directly; that is more specific than a
    # pattern and must win.
    assert _select(exclude=("^main$",), addresses=("3000",)) == [
        "parse_config",
        "parse_header",
        "main",
        "_start",
    ]


def test_filters_that_match_nothing_produce_an_empty_selection():
    assert _select(include=("^no_such_function$",)) == []


def test_selection_preserves_discovery_order():
    assert _select(include=("a",)) == _names(
        [func for func in FUNCTIONS if "a" in func.getName()]
    )


@pytest.mark.parametrize("option", ["include", "exclude"])
def test_an_invalid_pattern_is_reported_against_its_own_option(option):
    with pytest.raises(click.BadParameter) as error:
        compile_filters(
            ("[unclosed",) if option == "include" else (),
            ("[unclosed",) if option == "exclude" else (),
        )

    message = error.value.format_message()
    assert f"--{option}" in message
    assert "[unclosed" in message


def test_normalized_filters_are_order_independent():
    assert normalize_filters(
        {"include": ("b", "a"), "exclude": (), "function": ()}
    ) == (normalize_filters({"include": ("a", "b"), "exclude": (), "function": ()}))


def test_normalized_filters_have_a_stable_empty_shape():
    assert normalize_filters(None) == {"include": [], "exclude": [], "function": []}
    assert normalize_filters({}) == normalize_filters(None)


def test_normalized_filters_distinguish_a_filtered_run():
    assert normalize_filters({"include": ("^main$",)}) != normalize_filters(None)
