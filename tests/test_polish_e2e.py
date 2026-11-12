"""End-to-end tests for the decompilation polish pipeline.

Decompiles real cross-compiled binaries with and without --no-polish,
then asserts transforms fired and sidecar metadata is correct.
"""

import json
from pathlib import Path

import pytest
from conftest import FIXTURES, require_ghidra, run_export

POLISH_ARCHITECTURES = [
    ("polish_x86_32", "x86:LE:32:default", "gcc"),
]

EXPECTED_FUNCTIONS = {
    "dead_var_test",
    "bool_test",
    "cast_test",
    "combined_test",
    "compound_assign_test",
    "return_simple_test",
    "ternary_test",
    "nested_if_test",
    "entry",
}


@pytest.fixture(scope="module")
def ghidra_path() -> Path:
    return require_ghidra()


@pytest.fixture(
    scope="module",
    params=POLISH_ARCHITECTURES,
    ids=[a[0] for a in POLISH_ARCHITECTURES],
)
def polish_corpus(request, tmp_path_factory, ghidra_path):
    name, language, compiler = request.param
    binary = FIXTURES / name
    if not binary.is_file():
        pytest.skip(f"fixture {name} not built (run build_polish.sh)")
    output = tmp_path_factory.mktemp(f"{name}_polished")
    run_export(
        binary,
        output,
        "--language",
        language,
        "--compiler",
        compiler,
        "--timeout",
        "60",
        ghidra_path=ghidra_path,
        timeout=600,
    )
    return name, output


@pytest.fixture(
    scope="module",
    params=POLISH_ARCHITECTURES,
    ids=[a[0] for a in POLISH_ARCHITECTURES],
)
def raw_corpus(request, tmp_path_factory, ghidra_path):
    name, language, compiler = request.param
    binary = FIXTURES / name
    if not binary.is_file():
        pytest.skip(f"fixture {name} not built (run build_polish.sh)")
    output = tmp_path_factory.mktemp(f"{name}_raw")
    run_export(
        binary,
        output,
        "--language",
        language,
        "--compiler",
        compiler,
        "--timeout",
        "60",
        "--no-polish",
        ghidra_path=ghidra_path,
        timeout=600,
    )
    return name, output


def _load_functions_index(output: Path) -> list[dict]:
    functions_json = output / "functions.json"
    return json.loads(functions_json.read_text(encoding="utf-8"))


def _read_pseudocode(output: Path, record: dict) -> str:
    c_path = output / record["artifacts"]["pseudocode"]
    return c_path.read_text(encoding="utf-8")


def _successful_records(output: Path) -> list[dict]:
    records = _load_functions_index(output)
    return [r for r in records if r.get("decompilation", {}).get("status") == "success"]


class TestPolishedCorpus:
    def test_sidecar_has_polished_field(self, polish_corpus):
        """Every successful function has the polished field in its sidecar."""
        _name, output = polish_corpus
        for record in _successful_records(output):
            decomp = record["decompilation"]
            assert "polished" in decomp, f"missing polished field in {record['name']}"

    def test_some_functions_polished(self, polish_corpus):
        """At least one function was actually polished."""
        _name, output = polish_corpus
        polished_count = sum(
            1
            for r in _successful_records(output)
            if r["decompilation"].get("polished") is True
        )
        assert polished_count > 0, "no functions were polished"

    def test_pseudocode_files_readable(self, polish_corpus):
        """Every polished function has a non-empty pseudocode file."""
        _name, output = polish_corpus
        for record in _successful_records(output):
            code = _read_pseudocode(output, record)
            assert len(code.strip()) > 0, f"empty pseudocode for {record['name']}"

    def test_at_least_one_function_changed(self, polish_corpus, raw_corpus):
        """Polish actually changed at least one function's output vs raw."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        common = set(p_records) & set(r_records)
        assert common, "no common functions between polished and raw"
        diffs = 0
        for name in common:
            p_code = _read_pseudocode(p_output, p_records[name])
            r_code = _read_pseudocode(r_output, r_records[name])
            if p_code != r_code:
                diffs += 1
        assert diffs > 0, "polish made no changes to any function"

    def test_struct_fields_in_ptr_cast_test(self, polish_corpus, raw_corpus):
        """ptr_cast_test has pointer arithmetic that struct synthesis should rewrite."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "ptr_cast_test" not in p_records or "ptr_cast_test" not in r_records:
            pytest.skip("ptr_cast_test not found in decompiled output")
        raw_code = _read_pseudocode(r_output, r_records["ptr_cast_test"])
        polished_code = _read_pseudocode(p_output, p_records["ptr_cast_test"])
        assert "(int)obj + " in raw_code or "(long)obj + " in raw_code, (
            "raw ptr_cast_test missing expected pointer arithmetic"
        )
        assert "->field_0x" in polished_code, (
            "polished ptr_cast_test should have struct field accesses"
        )
        assert "_struct_obj" in polished_code, (
            "polished ptr_cast_test should have synthesized struct typedef"
        )

    def test_bool_simplification_fired(self, polish_corpus, raw_corpus):
        """At least one function lost a != 0 or == 0 comparison after polish."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        common = set(p_records) & set(r_records)
        raw_zero_cmp = 0
        polished_zero_cmp = 0
        for name in common:
            raw_code = _read_pseudocode(r_output, r_records[name])
            polished_code = _read_pseudocode(p_output, p_records[name])
            raw_zero_cmp += raw_code.count("!= 0") + raw_code.count("== 0")
            polished_zero_cmp += polished_code.count("!= 0") + polished_code.count(
                "== 0"
            )
        assert polished_zero_cmp < raw_zero_cmp, (
            "polish should have removed some != 0 / == 0 comparisons"
        )

    def test_dead_vars_removed(self, polish_corpus, raw_corpus):
        """Polished output has fewer variable declarations than raw."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        common = set(p_records) & set(r_records)
        raw_decls = 0
        polished_decls = 0
        for name in common:
            raw_lines = _read_pseudocode(r_output, r_records[name]).split("\n")
            polished_lines = _read_pseudocode(p_output, p_records[name]).split("\n")
            for line in raw_lines:
                stripped = line.strip()
                if (
                    stripped.startswith(("u32 ", "int ", "uint "))
                    and stripped.endswith(";")
                    and "=" not in stripped
                ):
                    raw_decls += 1
            for line in polished_lines:
                stripped = line.strip()
                if (
                    stripped.startswith(("u32 ", "int ", "uint "))
                    and stripped.endswith(";")
                    and "=" not in stripped
                ):
                    polished_decls += 1
        assert polished_decls < raw_decls, (
            "polish should have removed some dead variable declarations"
        )


    def test_compound_assignments_fired(self, polish_corpus, raw_corpus):
        """compound_assign_test raw has x = x + y patterns; polished has +=."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "compound_assign_test" not in p_records:
            pytest.skip("compound_assign_test not found")
        raw_code = _read_pseudocode(r_output, r_records["compound_assign_test"])
        polished_code = _read_pseudocode(p_output, p_records["compound_assign_test"])
        compound_ops = ["+=", "-=", "*=", "<<=", ">>="]
        polished_compound = sum(polished_code.count(op) for op in compound_ops)
        raw_compound = sum(raw_code.count(op) for op in compound_ops)
        assert polished_compound > raw_compound, (
            f"polished should have more compound ops than raw "
            f"(polished={polished_compound}, raw={raw_compound})\n"
            f"RAW:\n{raw_code}\nPOLISHED:\n{polished_code}"
        )

    def test_return_or_ternary_simplification_fired(self, polish_corpus, raw_corpus):
        """return_simple_test polished differs from raw via some transform.

        Ghidra may emit if/return or ternary or setcc — verify at least one
        transform (return simplify, ternary, bool, dead var) actually changed it.
        """
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "return_simple_test" not in p_records:
            pytest.skip("return_simple_test not found")
        raw_code = _read_pseudocode(r_output, r_records["return_simple_test"])
        polished_code = _read_pseudocode(p_output, p_records["return_simple_test"])
        assert polished_code != raw_code, (
            "polish should have changed return_simple_test output"
        )

    def test_ternary_synthesis_fired(self, polish_corpus, raw_corpus):
        """ternary_test raw has if/else; polished has ? ternary operator."""
        _pname, p_output = polish_corpus
        _rname, _r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        if "ternary_test" not in p_records:
            pytest.skip("ternary_test not found")
        polished_code = _read_pseudocode(p_output, p_records["ternary_test"])
        assert "?" in polished_code, (
            f"polished ternary_test should contain ternary operator\n{polished_code}"
        )
        assert "if" not in polished_code.split("?")[0].split("\n")[-1], (
            "ternary should replace if/else, not coexist on same line"
        )

    def test_nested_if_flattened(self, polish_corpus, raw_corpus):
        """nested_if_test polished differs from raw (bool simplify, compound assign)."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "nested_if_test" not in p_records:
            pytest.skip("nested_if_test not found")
        raw_code = _read_pseudocode(r_output, r_records["nested_if_test"])
        polished_code = _read_pseudocode(p_output, p_records["nested_if_test"])
        assert polished_code != raw_code, (
            "polish should have changed nested_if_test"
        )
        raw_neq0 = raw_code.count("!= 0")
        pol_neq0 = polished_code.count("!= 0")
        assert pol_neq0 < raw_neq0, (
            "bool simplify should remove != 0 comparisons in nested_if_test"
        )


class TestRawCorpus:
    def test_sidecar_has_polished_false(self, raw_corpus):
        """With --no-polish, every function has polished=False."""
        _name, output = raw_corpus
        for record in _successful_records(output):
            decomp = record["decompilation"]
            assert "polished" in decomp, f"missing polished field in {record['name']}"
            assert decomp["polished"] is False, (
                f"expected polished=False for {record['name']}"
            )

    def test_pseudocode_files_readable(self, raw_corpus):
        """Every raw function has a non-empty pseudocode file."""
        _name, output = raw_corpus
        for record in _successful_records(output):
            code = _read_pseudocode(output, record)
            assert len(code.strip()) > 0, f"empty pseudocode for {record['name']}"
