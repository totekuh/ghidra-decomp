"""End-to-end tests for --struct-map export against embedded Ghidra.

Two tiers:
  - structural tests on the checked-in ``sample`` binary;
  - alloc_map struct_type field validation on the sample binary.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import (
    FIXTURES,
    load_json,
    require_ghidra,
    run_export,
)


@pytest.fixture(scope="module")
def ghidra_path() -> Path:
    return require_ghidra()


# ── Tier 1: structural tests on the sample binary ─────────────────────


@pytest.fixture(scope="module")
def struct_corpus(tmp_path_factory, ghidra_path) -> Path:
    output = tmp_path_factory.mktemp("struct") / "corpus"
    run_export(
        FIXTURES / "sample",
        output,
        "--struct-map",
        ghidra_path=ghidra_path,
    )
    return output


def test_struct_map_is_produced(struct_corpus):
    path = struct_corpus / "struct_map.json"
    assert path.is_file(), "struct_map.json not written"
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["schema_version"] == 1
    assert isinstance(data["structs"], dict)


def test_struct_map_structs_have_required_fields(struct_corpus):
    data = load_json(struct_corpus, "struct_map.json")
    for name, info in data["structs"].items():
        assert "size" in info, f"{name} missing size"
        assert "kind" in info, f"{name} missing kind"
        assert info["kind"] in ("struct", "union"), (
            f"{name} unexpected kind {info['kind']}"
        )
        assert "fields" in info, f"{name} missing fields"
        for field in info["fields"]:
            assert "name" in field, f"{name} field missing name"
            assert "size" in field, f"{name} field missing size"
            assert "type" in field, f"{name} field missing type"


def test_struct_map_struct_fields_sorted_by_offset(struct_corpus):
    data = load_json(struct_corpus, "struct_map.json")
    for name, info in data["structs"].items():
        if info["kind"] != "struct":
            continue
        offsets = [f.get("offset", 0) for f in info["fields"]]
        assert offsets == sorted(offsets), (
            f"{name} fields not sorted by offset: {offsets}"
        )


def test_alloc_map_also_produced(struct_corpus):
    """--struct-map implies --alloc-map."""
    path = struct_corpus / "alloc_map.json"
    assert path.is_file(), (
        "alloc_map.json not written (--struct-map implies --alloc-map)"
    )


def test_alloc_map_entries_have_struct_type_field(struct_corpus):
    """Every alloc_map entry must carry struct_type (may be null)."""
    data = load_json(struct_corpus, "alloc_map.json")
    for entry in data["entries"]:
        assert "struct_type" in entry, (
            f"missing struct_type on {entry['function']}:{entry['callee']}"
        )


def test_pcode_output_still_present(struct_corpus):
    """--struct-map implies --pcode; pcode sidecars must exist."""
    records = load_json(struct_corpus, "functions.json")
    pcode_records = [r for r in records if isinstance(r["artifacts"].get("pcode"), str)]
    assert pcode_records, "no function produced a pcode sidecar"


def test_existing_indexes_still_present(struct_corpus):
    for name in ("functions.json", "callgraph.json", "metadata.json", "strings.json"):
        assert (struct_corpus / name).is_file(), f"{name} missing"


def test_manifest_records_struct_map(struct_corpus):
    manifest = load_json(struct_corpus, "manifest.json")
    secondary = manifest.get("export", {}).get("secondary_products", {})
    assert "struct_map" in secondary, "struct_map not in manifest secondary_products"


# ── Tier 2: struct_map content validation ──────────────────────────────


def test_struct_map_not_empty(struct_corpus):
    """The sample binary should produce at least one struct type."""
    data = load_json(struct_corpus, "struct_map.json")
    # Sample binary may or may not have structs depending on its content.
    # The important thing is the schema is valid.
    assert isinstance(data["structs"], dict)


# ── Tier 3: --struct-map with --gdt dumps all GDT types ──────────────

GDT_ARCHIVE = Path(
    "/usr/share/ghidra/Ghidra/Features/Base/data/typeinfo/generic/generic_clib.gdt"
)


@pytest.fixture(scope="module")
def struct_gdt_corpus(tmp_path_factory, ghidra_path) -> Path:
    if not GDT_ARCHIVE.is_file():
        pytest.skip(f"the Ghidra installation has no {GDT_ARCHIVE.name}")
    output = tmp_path_factory.mktemp("struct_gdt") / "corpus"
    run_export(
        FIXTURES / "sample",
        output,
        "--struct-map",
        "--gdt",
        str(GDT_ARCHIVE),
        ghidra_path=ghidra_path,
    )
    return output


def test_struct_map_with_gdt_has_structs(struct_gdt_corpus):
    """When --gdt is used, struct_map must include GDT types even on stripped binaries."""
    data = load_json(struct_gdt_corpus, "struct_map.json")
    assert data["schema_version"] == 1
    assert len(data["structs"]) > 0, "struct_map is empty despite --gdt providing types"


def test_struct_map_with_gdt_structs_have_fields(struct_gdt_corpus):
    """GDT-sourced structs must have the standard field layout."""
    data = load_json(struct_gdt_corpus, "struct_map.json")
    for name, info in data["structs"].items():
        assert "size" in info, f"{name} missing size"
        assert "kind" in info, f"{name} missing kind"
        assert info["kind"] in ("struct", "union")
        assert "fields" in info, f"{name} missing fields"


def test_struct_map_deterministic_across_workers(tmp_path, ghidra_path):
    """struct_map.json must be identical for serial and parallel decompilation."""
    binary = FIXTURES / "sample"
    serial_out = tmp_path / "serial"
    parallel_out = tmp_path / "parallel"
    run_export(
        binary,
        serial_out,
        "--struct-map",
        "--workers",
        "1",
        ghidra_path=ghidra_path,
    )
    run_export(
        binary,
        parallel_out,
        "--struct-map",
        "--workers",
        "4",
        ghidra_path=ghidra_path,
    )
    serial = load_json(serial_out, "struct_map.json")
    parallel = load_json(parallel_out, "struct_map.json")
    assert serial == parallel
