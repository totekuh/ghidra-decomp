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
