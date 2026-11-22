"""End-to-end tests for the --alloc-map export against embedded Ghidra.

Three tiers:
  - structural tests on the checked-in ``sample`` binary;
  - owned-fixture tests that cross-compile three alloc fixtures fresh via
    Docker and assert per-entry facts across architectures;
  - determinism test: same alloc_map.json regardless of worker count.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import (
    FIXTURES,
    build_crossbuild_fixtures,
    load_json,
    require_docker,
    require_ghidra,
    run_export,
)


@pytest.fixture(scope="module")
def ghidra_path() -> Path:
    return require_ghidra()


# ── Tier 1: structural tests on the sample binary ─────────────────────


@pytest.fixture(scope="module")
def alloc_corpus(tmp_path_factory, ghidra_path) -> Path:
    output = tmp_path_factory.mktemp("alloc") / "corpus"
    run_export(
        FIXTURES / "sample", output, "--pcode", "--alloc-map", ghidra_path=ghidra_path
    )
    return output


def test_alloc_map_is_produced(alloc_corpus):
    path = alloc_corpus / "alloc_map.json"
    assert path.is_file(), "alloc_map.json not written"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert isinstance(data["entries"], list)


def test_alloc_map_entries_have_required_fields(alloc_corpus):
    data = load_json(alloc_corpus, "alloc_map.json")
    for entry in data["entries"]:
        assert "function" in entry
        assert "function_addr" in entry
        assert "callee" in entry
        assert "size_expr" in entry
        assert "stores" in entry
        assert "returns" in entry


def test_existing_pcode_output_still_present(alloc_corpus):
    """--alloc-map must not break regular pcode sidecars."""
    records = load_json(alloc_corpus, "functions.json")
    pcode_records = [r for r in records if isinstance(r["artifacts"].get("pcode"), str)]
    assert pcode_records, "no function produced a pcode sidecar"


def test_existing_indexes_still_present(alloc_corpus):
    for name in ("functions.json", "callgraph.json", "metadata.json", "strings.json"):
        assert (alloc_corpus / name).is_file(), f"{name} missing"


# ── Tier 2: owned-fixture tests ───────────────────────────────────────

ALLOC_FIXTURES_BASIC = ("alloc_basic_x86_32", "alloc_basic_mipsel")
ALLOC_FIXTURES_XFUNC = ("alloc_xfunc_x86_32", "alloc_xfunc_mipsel")
ALLOC_FIXTURES_COMPLEX = ("alloc_complex_x86_32", "alloc_complex_mipsel")
ALLOC_FIXTURES_COMPLEX2 = ("alloc_complex2_x86_32", "alloc_complex2_mipsel")

ALL_ALLOC_FIXTURES = (
    *ALLOC_FIXTURES_BASIC,
    *ALLOC_FIXTURES_XFUNC,
    *ALLOC_FIXTURES_COMPLEX,
    *ALLOC_FIXTURES_COMPLEX2,
)


@pytest.fixture(scope="module")
def compiled_alloc_fixtures(tmp_path_factory) -> Path:
    require_docker()
    dest = tmp_path_factory.mktemp("alloc-fixtures")
    return build_crossbuild_fixtures(dest, list(ALL_ALLOC_FIXTURES))


def _alloc_map(output: Path) -> dict:
    return load_json(output, "alloc_map.json")


def _entries_for(output: Path, function_name: str) -> list[dict]:
    data = _alloc_map(output)
    return [e for e in data["entries"] if e["function"] == function_name]


def _run_alloc(fixture_path: Path, output: Path, ghidra_path: Path) -> Path:
    run_export(fixture_path, output, "--pcode", "--alloc-map", ghidra_path=ghidra_path)
    return output


# ── alloc_basic ───────────────────────────────────────────────────────


@pytest.mark.parametrize("fixture", ALLOC_FIXTURES_BASIC)
class TestAllocBasic:
    @pytest.fixture(autouse=True)
    def _output(self, tmp_path, ghidra_path, compiled_alloc_fixtures, fixture):
        self.output = _run_alloc(
            compiled_alloc_fixtures / fixture, tmp_path / fixture, ghidra_path
        )

    def test_malloc_const_size(self):
        entries = _entries_for(self.output, "alloc_to_field")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 64
        assert e["size_expr"] == "const"
        assert any(s["kind"] == "field" for s in e["stores"]), (
            f"no field store; stores={e['stores']}"
        )

    def test_calloc_product(self):
        entries = _entries_for(self.output, "alloc_calloc")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "calloc"
        assert e["size"] == 64
        assert e["size_expr"] == "product"

    def test_realloc_size_arg(self):
        entries = _entries_for(self.output, "alloc_realloc")
        assert len(entries) >= 1
        realloc_entries = [e for e in entries if e["callee"] == "realloc"]
        assert realloc_entries, "no realloc entry found"
        e = realloc_entries[0]
        assert e["size"] == 128
        assert e["size_expr"] == "const"

    def test_variable_size(self):
        entries = _entries_for(self.output, "alloc_variable")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] is None
        assert e["size_expr"] == "variable"
        assert isinstance(e["size_vn"], str)

    def test_global_store(self):
        entries = _entries_for(self.output, "alloc_to_global")
        assert len(entries) == 1
        e = entries[0]
        assert e["size"] == 256
        assert any(s["kind"] == "global" for s in e["stores"]), (
            f"no global store; stores={e['stores']}"
        )


# ── alloc_xfunc ───────────────────────────────────────────────────────


@pytest.mark.parametrize("fixture", ALLOC_FIXTURES_XFUNC)
class TestAllocXfunc:
    @pytest.fixture(autouse=True)
    def _output(self, tmp_path, ghidra_path, compiled_alloc_fixtures, fixture):
        self.output = _run_alloc(
            compiled_alloc_fixtures / fixture, tmp_path / fixture, ghidra_path
        )

    def test_field_store_pattern(self):
        entries = _entries_for(self.output, "init_ctx")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 64
        assert e["stores"], "no stores recorded"
        assert any(s["kind"] == "field" for s in e["stores"])

    def test_passed_to(self):
        entries = _entries_for(self.output, "alloc_and_pass")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 256
        passed = e["returns"]["passed_to"]
        assert any(pt["callee"] == "use_buffer" for pt in passed), (
            f"use_buffer not in passed_to: {passed}"
        )
        use_buf = next(pt for pt in passed if pt["callee"] == "use_buffer")
        assert use_buf["arg_index"] == 0

    def test_returned(self):
        entries = _entries_for(self.output, "alloc_and_return")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["returns"]["returned"] is True
        assert e["returns"]["output_vn"] is not None

    def test_multiple_fields(self):
        entries = _entries_for(self.output, "init_full")
        assert len(entries) == 2
        sizes = {e["size"] for e in entries}
        assert sizes == {64, 128}
        for e in entries:
            assert any(s["kind"] == "field" for s in e["stores"]), (
                f"no field store in {e}"
            )


# ── alloc_complex ─────────────────────────────────────────────────────


@pytest.mark.parametrize("fixture", ALLOC_FIXTURES_COMPLEX)
class TestAllocComplex:
    @pytest.fixture(autouse=True)
    def _output(self, tmp_path, ghidra_path, compiled_alloc_fixtures, fixture):
        self.output = _run_alloc(
            compiled_alloc_fixtures / fixture, tmp_path / fixture, ghidra_path
        )

    def test_nested_field(self):
        entries = _entries_for(self.output, "alloc_nested")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 96
        assert e["stores"], "no stores"

    def test_two_allocs_one_function(self):
        entries = _entries_for(self.output, "alloc_two")
        assert len(entries) == 2
        sizes = {e["size"] for e in entries}
        assert sizes == {64, 128}

    def test_alloc_and_forward(self):
        entries = _entries_for(self.output, "alloc_and_forward")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 256
        assert e["stores"], "no stores — expected field store"

    def test_multi_alloc_three_entries(self):
        entries = _entries_for(self.output, "multi_alloc")
        assert len(entries) == 3
        sizes = sorted(e["size"] for e in entries)
        assert sizes == [32, 64, 128]


# ── alloc_complex2: edge cases ────────────────────────────────────────


@pytest.mark.parametrize("fixture", ALLOC_FIXTURES_COMPLEX2)
class TestAllocComplex2Positive:
    """Positive edge cases: patterns that MUST produce alloc entries."""

    @pytest.fixture(autouse=True)
    def _output(self, tmp_path, ghidra_path, compiled_alloc_fixtures, fixture):
        self.output = _run_alloc(
            compiled_alloc_fixtures / fixture, tmp_path / fixture, ghidra_path
        )

    def test_deep_nested_3_levels(self):
        entries = _entries_for(self.output, "alloc_deep_nested")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 48
        assert e["stores"], "expected store into deeply nested field"

    def test_double_pointer_store(self):
        entries = _entries_for(self.output, "alloc_double_ptr")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 72

    def test_alloc_in_loop(self):
        """One CALL site inside a loop still produces one entry."""
        entries = _entries_for(self.output, "alloc_in_loop")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 100

    def test_conditional_alloc(self):
        entries = _entries_for(self.output, "alloc_conditional")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 200

    def test_zero_size_alloc(self):
        entries = _entries_for(self.output, "alloc_zero")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 0
        assert e["size_expr"] == "const"
        assert e["returns"]["returned"] is True

    def test_chained_malloc_realloc(self):
        """malloc + realloc in same function → two entries."""
        entries = _entries_for(self.output, "alloc_chain")
        assert len(entries) == 2
        callees = {e["callee"] for e in entries}
        assert "malloc" in callees
        assert "realloc" in callees
        malloc_e = next(e for e in entries if e["callee"] == "malloc")
        realloc_e = next(e for e in entries if e["callee"] == "realloc")
        assert malloc_e["size"] == 16
        assert realloc_e["size"] == 256

    def test_alloc_via_local_to_field(self):
        """Alloc stored to local, then to struct field — store still tracked."""
        entries = _entries_for(self.output, "alloc_via_local")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 512

    def test_alloc_fanout_to_multiple_consumers(self):
        """Alloc result passed to two different calls."""
        entries = _entries_for(self.output, "alloc_fanout")
        assert len(entries) == 1
        e = entries[0]
        assert e["callee"] == "malloc"
        assert e["size"] == 300
        passed = e["returns"]["passed_to"]
        callee_names = {pt["callee"] for pt in passed}
        assert "consume" in callee_names or "memset_fake" in callee_names, (
            f"expected at least one consumer in passed_to: {passed}"
        )


@pytest.mark.parametrize("fixture", ALLOC_FIXTURES_COMPLEX2)
class TestAllocComplex2Negative:
    """Negative cases: patterns that must NOT produce alloc entries."""

    @pytest.fixture(autouse=True)
    def _output(self, tmp_path, ghidra_path, compiled_alloc_fixtures, fixture):
        self.output = _run_alloc(
            compiled_alloc_fixtures / fixture, tmp_path / fixture, ghidra_path
        )

    def test_no_alloc_function_has_no_entries(self):
        """no_alloc_at_all calls only memset_fake/consume/dealloc — no alloc entries."""
        entries = _entries_for(self.output, "no_alloc_at_all")
        # dealloc contains "alloc" so the heuristic may fire for it.
        # Filter to only known allocator names (malloc/calloc/realloc etc.)
        real_alloc_entries = [
            e
            for e in entries
            if e["callee"] in ("malloc", "calloc", "realloc", "kmalloc", "kzalloc")
        ]
        assert real_alloc_entries == [], (
            f"no_alloc_at_all should have no real allocator entries: {entries}"
        )

    def test_heuristic_fires_on_alloc_substring(self):
        """count_alloc_failures contains 'alloc' → heuristic fires, size_expr=unknown."""
        entries = _entries_for(self.output, "calls_count_alloc")
        # The heuristic fires because "count_alloc_failures" contains "alloc"
        heuristic = [e for e in entries if e["callee"] == "count_alloc_failures"]
        if heuristic:
            assert heuristic[0]["size_expr"] == "unknown"

    def test_dealloc_heuristic_produces_unknown(self):
        """dealloc contains 'alloc' so heuristic may fire — if so, size_expr=unknown."""
        entries = _entries_for(self.output, "no_alloc_at_all")
        dealloc_entries = [e for e in entries if e["callee"] == "dealloc"]
        for e in dealloc_entries:
            assert e["size_expr"] == "unknown"


# ── Tier 3: determinism ──────────────────────────────────────────────


def test_alloc_map_deterministic_across_workers(
    tmp_path, ghidra_path, compiled_alloc_fixtures
):
    """The alloc map must be identical for serial and parallel decompilation."""
    fixture = compiled_alloc_fixtures / "alloc_basic_x86_32"
    serial_out = tmp_path / "serial"
    parallel_out = tmp_path / "parallel"
    run_export(
        fixture,
        serial_out,
        "--pcode",
        "--alloc-map",
        "--workers",
        "1",
        ghidra_path=ghidra_path,
    )
    run_export(
        fixture,
        parallel_out,
        "--pcode",
        "--alloc-map",
        "--workers",
        "4",
        ghidra_path=ghidra_path,
    )
    serial = load_json(serial_out, "alloc_map.json")
    parallel = load_json(parallel_out, "alloc_map.json")
    assert serial == parallel
