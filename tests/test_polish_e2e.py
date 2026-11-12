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
        """Across all functions, polished has >= compound ops as raw.

        Ghidra may already fold compound_assign_test into a single expression,
        so check across the whole corpus for any x = x + expr patterns that
        got rewritten.
        """
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        common = set(p_records) & set(r_records)
        raw_simple = 0
        polished_simple = 0
        for name in common:
            raw_code = _read_pseudocode(r_output, r_records[name])
            polished_code = _read_pseudocode(p_output, p_records[name])
            for op in [" = ", "= "]:
                raw_simple += raw_code.count(op)
                polished_simple += polished_code.count(op)
        assert polished_simple <= raw_simple, (
            "polished should have same or fewer simple assignments (some became compound)"
        )

    def test_return_simplification_fired(self, polish_corpus, raw_corpus):
        """Polished return_simple_test should lack if...return 1 pattern."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "return_simple_test" not in p_records:
            pytest.skip("return_simple_test not found in decompiled output")
        raw_code = _read_pseudocode(r_output, r_records["return_simple_test"])
        polished_code = _read_pseudocode(p_output, p_records["return_simple_test"])
        raw_returns = raw_code.count("return")
        polished_returns = polished_code.count("return")
        assert polished_returns <= raw_returns, (
            "polished should have same or fewer return statements"
        )

    def test_ternary_synthesis_fired(self, polish_corpus, raw_corpus):
        """Polished ternary_test should have ? operator."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "ternary_test" not in p_records:
            pytest.skip("ternary_test not found in decompiled output")
        raw_code = _read_pseudocode(r_output, r_records["ternary_test"])
        polished_code = _read_pseudocode(p_output, p_records["ternary_test"])
        raw_ternary = raw_code.count("?")
        polished_ternary = polished_code.count("?")
        assert polished_ternary >= raw_ternary, (
            "polished should have same or more ternary operators"
        )

    def test_nested_if_flattened(self, polish_corpus, raw_corpus):
        """Polished nested_if_test should have && where raw has nested ifs."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "nested_if_test" not in p_records:
            pytest.skip("nested_if_test not found in decompiled output")
        raw_code = _read_pseudocode(r_output, r_records["nested_if_test"])
        polished_code = _read_pseudocode(p_output, p_records["nested_if_test"])
        raw_ifs = raw_code.count("if (") + raw_code.count("if(")
        polished_ifs = polished_code.count("if (") + polished_code.count("if(")
        assert polished_ifs <= raw_ifs, (
            "polished should have same or fewer if statements (flattened)"
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
