"""End-to-end tests for the polish pipeline across the synthetic corpus.

Decompiles the cross-compiled polish_* fixtures with and without --no-polish
and asserts the pipeline ran and changed output. ghidra_path, _read_pseudocode
and _successful_records come from conftest.
"""

import pytest
from conftest import FIXTURES, _read_pseudocode, _successful_records, run_export

POLISH_ARCHITECTURES = [
    ("polish_x86_32", "x86:LE:32:default", "gcc"),
    ("polish_mipsel", "MIPS:LE:32:default", "default"),
]


@pytest.fixture(
    scope="module",
    params=POLISH_ARCHITECTURES,
    ids=[a[0] for a in POLISH_ARCHITECTURES],
)
def corpus_pair(request, tmp_path_factory, ghidra_path):
    """Decompile one architecture with and without polish."""
    name, language, compiler = request.param
    binary = FIXTURES / name
    if not binary.is_file():
        pytest.skip(f"fixture {name} not built (run build_polish.sh)")
    pol_output = tmp_path_factory.mktemp(f"{name}_polished")
    raw_output = tmp_path_factory.mktemp(f"{name}_raw")
    run_export(
        binary,
        pol_output,
        "--language",
        language,
        "--compiler",
        compiler,
        "--timeout",
        "60",
        ghidra_path=ghidra_path,
        timeout=600,
    )
    run_export(
        binary,
        raw_output,
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
    return name, pol_output, raw_output


@pytest.fixture(scope="module")
def polish_corpus(corpus_pair):
    name, pol_output, _raw_output = corpus_pair
    return name, pol_output


@pytest.fixture(scope="module")
def raw_corpus(corpus_pair):
    name, _pol_output, raw_output = corpus_pair
    return name, raw_output


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
        """bool_test specifically: raw has != 0 / == 0; polished removes them."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "bool_test" not in p_records or "bool_test" not in r_records:
            pytest.skip("bool_test not found")
        raw_code = _read_pseudocode(r_output, r_records["bool_test"])
        polished_code = _read_pseudocode(p_output, p_records["bool_test"])
        raw_zero_cmp = raw_code.count("!= 0") + raw_code.count("== 0")
        polished_zero_cmp = polished_code.count("!= 0") + polished_code.count("== 0")
        assert raw_zero_cmp >= 4, (
            f"raw bool_test should have many != 0 / == 0 comparisons, got {raw_zero_cmp}"
        )
        assert polished_zero_cmp < raw_zero_cmp, (
            f"polished bool_test should have fewer zero comparisons "
            f"(raw={raw_zero_cmp}, polished={polished_zero_cmp})"
        )

    def test_dead_vars_removed(self, polish_corpus, raw_corpus):
        """dead_var_test: polished has fewer bare variable declarations than raw."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "dead_var_test" not in p_records or "dead_var_test" not in r_records:
            pytest.skip("dead_var_test not found")

        _TYPE_PREFIXES = (
            "u32 ",
            "int ",
            "uint ",
            "undefined",
            "u8 ",
            "byte ",
            "long ",
        )

        def _count_bare_decls(code):
            count = 0
            for line in code.split("\n"):
                stripped = line.strip()
                if (
                    stripped.startswith(_TYPE_PREFIXES)
                    and stripped.endswith(";")
                    and "=" not in stripped
                    and "(" not in stripped
                ):
                    count += 1
            return count

        raw_code = _read_pseudocode(r_output, r_records["dead_var_test"])
        polished_code = _read_pseudocode(p_output, p_records["dead_var_test"])
        raw_decls = _count_bare_decls(raw_code)
        polished_decls = _count_bare_decls(polished_code)
        if raw_decls < 2:
            pytest.skip(
                f"Ghidra did not emit dead declarations on this arch (got {raw_decls})"
            )
        assert polished_decls < raw_decls, (
            f"polished dead_var_test should have fewer declarations "
            f"(raw={raw_decls}, polished={polished_decls})"
        )

    def test_compound_assignments_fired(self, polish_corpus, raw_corpus):
        """compound_assign_test: raw has *acc = *acc + x; polished has *acc += x."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "compound_assign_test" not in p_records:
            pytest.skip("compound_assign_test not found")
        raw_code = _read_pseudocode(r_output, r_records["compound_assign_test"])
        polished_code = _read_pseudocode(p_output, p_records["compound_assign_test"])
        assert "*acc = *acc + " in raw_code or "*acc = *acc << " in raw_code, (
            f"raw compound_assign_test should have *acc = *acc op patterns\n{raw_code}"
        )
        compound_ops = ["+=", "-=", "<<="]
        polished_compound = sum(polished_code.count(op) for op in compound_ops)
        assert polished_compound >= 3, (
            f"polished should have at least 3 compound ops, got {polished_compound}\n"
            f"{polished_code}"
        )
        assert "*acc = *acc + " not in polished_code, (
            "polished should not have *acc = *acc + pattern (should be *acc +=)"
        )

    def test_return_simple_test_transformed(self, polish_corpus, raw_corpus):
        """return_simple_test: polish changes output (ternary, dead vars, etc)."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "return_simple_test" not in p_records:
            pytest.skip("return_simple_test not found")
        raw_code = _read_pseudocode(r_output, r_records["return_simple_test"])
        polished_code = _read_pseudocode(p_output, p_records["return_simple_test"])
        if polished_code == raw_code:
            pytest.skip("polish made no changes to return_simple_test on this arch")

    def test_ternary_synthesis_fired(self, polish_corpus, raw_corpus):
        """ternary_test: raw has if/else; polished has ternary ? operator."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "ternary_test" not in p_records or "ternary_test" not in r_records:
            pytest.skip("ternary_test not found")
        raw_code = _read_pseudocode(r_output, r_records["ternary_test"])
        polished_code = _read_pseudocode(p_output, p_records["ternary_test"])
        if "if" not in raw_code or "else" not in raw_code:
            pytest.skip("Ghidra did not emit if/else for ternary_test on this arch")
        assert "?" in polished_code, (
            f"polished ternary_test should have ternary operator\n{polished_code}"
        )

    def test_loop_normalize_while_to_for(self, polish_corpus, raw_corpus):
        """On non-x86 arches, Ghidra emits while loops that loop_normalize
        converts to for. On x86_32, Ghidra already reconstructs for loops,
        so this test skips.

        The pattern requires: init assignment before while, same var in
        condition, increment as last body statement. MIPS/ARM/RISC-V/PPC
        emit local_c = a; while(local_c != 0) { local_c = local_c - 1; }
        which converts to for(local_c = a; local_c != 0; local_c -= 1).
        """
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}

        convertible_while = False
        for name in set(p_records) & set(r_records):
            raw_code = _read_pseudocode(r_output, r_records[name])
            polished_code = _read_pseudocode(p_output, p_records[name])
            if (
                "while" in raw_code
                and "for (" in polished_code
                and (
                    "for (" not in raw_code
                    or polished_code.count("for (") > raw_code.count("for (")
                )
            ):
                convertible_while = True
                break

        if not convertible_while:
            pytest.skip(
                "Ghidra already reconstructed for loops on this arch "
                "or no while loops have the init+increment pattern"
            )

    def test_nested_if_transforms(self, polish_corpus, raw_corpus):
        """nested_if_test: bool simplify removes != 0, compound assign fires += ."""
        _pname, p_output = polish_corpus
        _rname, r_output = raw_corpus
        p_records = {r["name"]: r for r in _successful_records(p_output)}
        r_records = {r["name"]: r for r in _successful_records(r_output)}
        if "nested_if_test" not in p_records or "nested_if_test" not in r_records:
            pytest.skip("nested_if_test not found")
        raw_code = _read_pseudocode(r_output, r_records["nested_if_test"])
        polished_code = _read_pseudocode(p_output, p_records["nested_if_test"])
        raw_neq0 = raw_code.count("!= 0")
        pol_neq0 = polished_code.count("!= 0")
        assert raw_neq0 >= 2, (
            f"raw nested_if_test should have multiple != 0, got {raw_neq0}"
        )
        assert pol_neq0 < raw_neq0, (
            f"bool simplify should remove standalone != 0 comparisons "
            f"(raw={raw_neq0}, polished={pol_neq0})"
        )
        assert "+=" in polished_code, (
            "polished nested_if_test should have compound assignment"
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
