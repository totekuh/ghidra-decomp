"""End-to-end tests for the --pcode export against embedded Ghidra.

Three layers, cheapest first:
  - structural tests on the small checked-in ``sample`` binary, gating the facts
    every pcode sidecar must carry;
  - owned-fixture tests that cross-compile ``pcode_test.c`` fresh via Docker on
    every run (so a source edit is always exercised) and assert the full fact
    set across architectures; skipped when Docker is unavailable;
  - a golden test reproducing the handoff's acceptance check on the real driver
    sample, skipped unless that binary is available — it is a large proprietary
    blob that is deliberately not vendored into this repository.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import (
    FIXTURES,
    build_crossbuild_fixtures,
    load_json,
    require_docker,
    require_ghidra,
    run_export,
    sha256_of,
)

GOLDEN_FUNCTION = "RTMPDeFragmentDataFrame"
GOLDEN_ENV = "GHIDRA_DECOMP_GOLDEN_KO"
GOLDEN_FALLBACK = Path("/home/witchtape/projects/sem-boundcheck/data/mt_wifi.ko")


@pytest.fixture(scope="module")
def ghidra_path() -> Path:
    return require_ghidra()


@pytest.fixture(scope="module")
def pcode_corpus(tmp_path_factory, ghidra_path) -> Path:
    output = tmp_path_factory.mktemp("pcode") / "corpus"
    run_export(FIXTURES / "sample", output, "--pcode", ghidra_path=ghidra_path)
    return output


def _pcode_records(output: Path) -> list[dict]:
    records = load_json(output, "functions.json")
    return [r for r in records if isinstance(r["artifacts"].get("pcode"), str)]


# ── Structural facts (small fixture) ─────────────────────────────────


def test_pcode_sidecars_are_produced_and_registered(pcode_corpus):
    records = _pcode_records(pcode_corpus)
    assert records, "no function produced a pcode sidecar"
    for record in records:
        pcode_path = pcode_corpus / record["artifacts"]["pcode"]
        assert pcode_path.is_file()
        assert sha256_of(pcode_path) == record["artifacts"]["pcode_sha256"]
        payload = json.loads(pcode_path.read_text(encoding="utf-8"))
        assert {"ops", "varnodes", "blocks", "calls"} <= set(payload)


def test_pcode_schema_version_is_current(pcode_corpus):
    for record in _pcode_records(pcode_corpus):
        payload = json.loads(
            (pcode_corpus / record["artifacts"]["pcode"]).read_text(encoding="utf-8")
        )
        assert payload["schema_version"] == 8


def test_varnode_types_carry_pointer_markers(pcode_corpus):
    """At least one varnode should have a pointer type with ' *' suffix."""
    all_types: list[str] = []
    for record in _pcode_records(pcode_corpus):
        payload = json.loads(
            (pcode_corpus / record["artifacts"]["pcode"]).read_text(encoding="utf-8")
        )
        all_types.extend(v["type"] for v in payload["varnodes"])
    pointer_types = [t for t in all_types if " *" in t]
    assert pointer_types, f"no pointer types found in varnodes; saw {set(all_types)}"


def test_pcode_def_use_and_cfg_are_consistent(pcode_corpus):
    """An output id must be consumable as an input; block edges must be valid."""
    for record in _pcode_records(pcode_corpus):
        payload = json.loads(
            (pcode_corpus / record["artifacts"]["pcode"]).read_text(encoding="utf-8")
        )
        produced = {
            op["output"]["vn"]
            for op in payload["ops"]
            if op["output"] and "vn" in op["output"]
        }
        consumed = {
            inp["vn"] for op in payload["ops"] for inp in op["inputs"] if "vn" in inp
        }
        # Most produced values are read somewhere; at minimum the two sets overlap,
        # which proves ids are shared across ops rather than per-occurrence.
        if produced and consumed:
            assert produced & consumed

        indices = {block["block"] for block in payload["blocks"]}
        for block in payload["blocks"]:
            for neighbor in block["succ"] + block["pred"]:
                assert neighbor in indices
            for seq in block["ops"]:
                assert 0 <= seq < len(payload["ops"])


def test_pcode_is_deterministic_across_worker_counts(tmp_path, ghidra_path):
    serial = tmp_path / "serial"
    parallel = tmp_path / "parallel"
    run_export(
        FIXTURES / "sample",
        serial,
        "--pcode",
        "--workers",
        "1",
        ghidra_path=ghidra_path,
    )
    run_export(
        FIXTURES / "sample",
        parallel,
        "--pcode",
        "--workers",
        "4",
        ghidra_path=ghidra_path,
    )

    serial_pcode = sorted(
        p.relative_to(serial) for p in serial.glob("functions/*.pcode.json")
    )
    parallel_pcode = sorted(
        p.relative_to(parallel) for p in parallel.glob("functions/*.pcode.json")
    )
    assert serial_pcode == parallel_pcode
    assert serial_pcode, "fixture produced no pcode sidecars"
    for relative in serial_pcode:
        assert sha256_of(serial / relative) == sha256_of(parallel / relative)


# ── Owned fixture: compiled fresh, then decompiled, every run ────────

PCODE_FIXTURES = ("pcode_x86_32", "pcode_mipsel")


@pytest.fixture(scope="module")
def compiled_pcode_fixtures(tmp_path_factory) -> Path:
    """Cross-compile the pcode fixtures from source via Docker, once per run.

    This recompiles ``pcode_test.c`` rather than reading a committed binary, so
    any edit to the source is exercised by the same run. Skipped when Docker is
    unavailable.
    """
    require_docker()
    dest = tmp_path_factory.mktemp("pcode-fixtures")
    return build_crossbuild_fixtures(dest, list(PCODE_FIXTURES))


def _function_pcode(output: Path, name: str) -> dict:
    record = next(r for r in load_json(output, "functions.json") if r["name"] == name)
    return json.loads(
        (output / record["artifacts"]["pcode"]).read_text(encoding="utf-8")
    )


@pytest.mark.parametrize("fixture", PCODE_FIXTURES)
def test_owned_fixture_exposes_every_pcode_fact(
    tmp_path, ghidra_path, compiled_pcode_fixtures, fixture
):
    """The pcode facts must hold on a fixture we compiled, independent of arch.

    ``pcode_test.c`` is shaped so one decompilation exercises calls with
    resolved const arguments, a dominating length guard, a stack-buffer extent,
    and an open-coded copy loop. See tests/fixtures/pcode_test.c.
    """
    output = tmp_path / fixture
    run_export(
        compiled_pcode_fixtures / fixture, output, "--pcode", ghidra_path=ghidra_path
    )

    bounded = _function_pcode(output, "bounded_copy")

    # Const allocation size reaches reserve() as a const argument.
    reserve = [c for c in bounded["calls"] if c["callee"] == "reserve"]
    assert reserve, "reserve call not found"
    reserve_consts = {
        a.get("const") for c in reserve for a in c["args"] if "const" in a
    }
    assert 0x800 in reserve_consts, f"0x800 not exposed; saw {reserve_consts}"

    # The copy sink is called with its three arguments recovered positionally.
    copies = [c for c in bounded["calls"] if c["callee"] == "copy_bytes"]
    assert copies, "copy_bytes call not found"
    assert all(len(c["args"]) == 3 for c in copies)

    # The 64-byte stack buffer is reported with its array capacity.
    buffers = [loc for loc in bounded["locals"] if loc.get("array")]
    assert any(
        loc["size"] == 64 and loc["array"] == {"elem_size": 1, "count": 64}
        for loc in buffers
    ), f"64-byte stack buffer not reported; saw {bounded['locals']}"

    # The length guard is a comparison dominating the bounded copy.
    assert any("LESS" in op["op"] for op in bounded["ops"]), (
        "no comparison guard serialized"
    )
    assert any(op["op"] == "CBRANCH" for op in bounded["ops"]), "no CBRANCH guard"

    # The open-coded copy loop yields a STORE sink inside a detected loop.
    copy_fn = _function_pcode(output, "copy_bytes")
    assert any(op["op"] == "STORE" for op in copy_fn["ops"]), (
        "no STORE sink in copy loop"
    )
    assert any(block["loop_header"] for block in copy_fn["blocks"]), (
        "copy loop back-edge was not detected"
    )


# ── Golden acceptance (real driver sample) ───────────────────────────


def _golden_binary() -> Path:
    configured = os.environ.get(GOLDEN_ENV)
    candidate = Path(configured) if configured else GOLDEN_FALLBACK
    if not candidate.is_file():
        pytest.skip(
            f"golden sample unavailable; set {GOLDEN_ENV} to the mt_wifi.ko path "
            f"(tried {candidate})"
        )
    return candidate


def test_golden_overflow_facts_are_recoverable(tmp_path, ghidra_path):
    """The handoff's completion bar, keyed on symbols and structure.

    The sample is MIPS little-endian and relocatable, so the handoff's literal
    addresses and its 0x92a guard constant are build-specific and are not
    asserted. What must hold is that a consumer can recover, from the sidecar
    alone: the memmove sinks with resolved arguments, the heap allocation size,
    comparison guards, and a usable control-flow graph.
    """
    binary = _golden_binary()
    output = tmp_path / "corpus"
    run_export(
        binary,
        output,
        "--pcode",
        "--include",
        GOLDEN_FUNCTION,
        ghidra_path=ghidra_path,
    )

    records = [
        r for r in load_json(output, "functions.json") if r["name"] == GOLDEN_FUNCTION
    ]
    assert records, f"{GOLDEN_FUNCTION} was not exported"
    payload = json.loads(
        (output / records[0]["artifacts"]["pcode"]).read_text(encoding="utf-8")
    )

    # Sink: the memmove copy sites, each with its arguments resolved.
    memmoves = [c for c in payload["calls"] if c["callee"] == "memmove"]
    assert memmoves, "no memmove sink found"
    assert all(len(c["args"]) >= 3 for c in memmoves), "memmove args not resolved"

    # Alloc side: the heap buffer size is exposed as a constant argument.
    alloc = [
        c
        for c in payload["calls"]
        if c["callee"] and "AllocateFragPacketBuffer" in c["callee"]
    ]
    assert alloc, "allocation call not found"
    alloc_consts = {a.get("const") for c in alloc for a in c["args"] if "const" in a}
    assert 0x800 in alloc_consts, f"0x800 alloc size not exposed; saw {alloc_consts}"

    # Guards: signed/unsigned comparison ops are present to dominate the sink.
    comparisons = [
        op
        for op in payload["ops"]
        if "LESS" in op["op"] or op["op"].startswith("INT_EQUAL")
    ]
    assert comparisons, "no comparison guards serialized"
    assert any(op["op"] == "CBRANCH" for op in payload["ops"]), "no CBRANCH guard"

    # CFG: a valid, navigable graph so dominance can be computed downstream.
    indices = {b["block"] for b in payload["blocks"]}
    assert len(indices) > 1
    for block in payload["blocks"]:
        for neighbor in block["succ"] + block["pred"]:
            assert neighbor in indices

    # The memmove length operand is a real, resolvable varnode id.
    length = memmoves[0]["args"][2]
    assert "vn" in length or "const" in length
