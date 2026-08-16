"""Unit tests for the fingerprinted analysis cache."""

import json

import pytest

from ghidra_decomp.artifacts import SCHEMA_VERSION, build_fingerprint
from ghidra_decomp.cache import (
    CACHE_STATE_FILE,
    PROJECT_DIRNAME,
    REASON_HIT,
    REASON_INCOMPLETE,
    REASON_PROJECT_MISSING,
    REASON_UNREADABLE,
    CacheOutcome,
    cache_key,
    cache_key_from,
    default_cache_root,
    discard_project,
    entry_lock,
    entry_path,
    evaluate_entry,
    mark_complete,
    mark_incomplete,
    read_state,
    resolved_versions,
)

IDENTITY = {"path": "/tmp/input.bin", "sha256": "a" * 64, "size": 1024}
ANALYSIS = {
    "base_address": None,
    "entry_point": None,
    "language": "x86:LE:32:default",
    "compiler": "gcc",
}
VERSIONS = resolved_versions(
    ghidra_version="12.1", pyghidra_version="3.0.0", exporter_version="0.3.0"
)


def _complete_entry(tmp_path, fingerprint, versions=VERSIONS):
    entry = tmp_path / cache_key_from(fingerprint)
    (entry / PROJECT_DIRNAME).mkdir(parents=True)
    mark_complete(entry, fingerprint, versions, ANALYSIS)
    return entry


def test_cache_key_is_stable_for_identical_inputs():
    assert cache_key(IDENTITY, ANALYSIS) == cache_key(IDENTITY, dict(ANALYSIS))


def test_cache_key_uses_the_complete_digest_not_a_prefix():
    key = cache_key(IDENTITY, ANALYSIS)

    assert len(key) == 64
    assert key == build_fingerprint(IDENTITY, ANALYSIS)["sha256"]


@pytest.mark.parametrize(
    "identity_change, analysis_change",
    [
        ({"sha256": "b" * 64}, {}),
        ({"size": 2048}, {}),
        ({}, {"base_address": "0x400000"}),
        ({}, {"entry_point": "0x1000"}),
        ({}, {"language": "ARM:LE:32:v7"}),
        ({}, {"compiler": "default"}),
    ],
)
def test_cache_key_changes_for_every_invalidation_input(
    identity_change, analysis_change
):
    baseline = cache_key(IDENTITY, ANALYSIS)

    changed = cache_key(
        {**IDENTITY, **identity_change}, {**ANALYSIS, **analysis_change}
    )

    assert changed != baseline


def test_cache_key_ignores_the_input_path():
    assert cache_key({**IDENTITY, "path": "/elsewhere/input.bin"}, ANALYSIS) == (
        cache_key(IDENTITY, ANALYSIS)
    )


def test_default_cache_root_honors_xdg_cache_home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "xdg"))

    assert default_cache_root() == tmp_path / "xdg" / "ghidra-decomp"


def test_default_cache_root_falls_back_to_the_home_cache(monkeypatch, tmp_path):
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.setattr("pathlib.Path.home", classmethod(lambda cls: tmp_path))

    assert default_cache_root() == tmp_path / ".cache" / "ghidra-decomp"


def test_a_complete_entry_is_reusable(tmp_path):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    entry = _complete_entry(tmp_path, fingerprint)

    assert evaluate_entry(entry, fingerprint, VERSIONS) == (True, REASON_HIT)


def test_an_absent_entry_is_never_reused(tmp_path):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)

    hit, reason = evaluate_entry(tmp_path / "missing", fingerprint, VERSIONS)

    assert hit is False
    assert reason == REASON_UNREADABLE


def test_an_interrupted_entry_is_never_reused(tmp_path):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    entry = entry_path(tmp_path, cache_key_from(fingerprint))
    (entry / PROJECT_DIRNAME).mkdir(parents=True)
    mark_incomplete(entry, fingerprint)

    assert evaluate_entry(entry, fingerprint, VERSIONS) == (False, REASON_INCOMPLETE)


def test_a_corrupt_state_file_is_never_reused(tmp_path):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    entry = _complete_entry(tmp_path, fingerprint)
    (entry / CACHE_STATE_FILE).write_text("{ not json")

    assert evaluate_entry(entry, fingerprint, VERSIONS) == (False, REASON_UNREADABLE)
    assert read_state(entry) is None


def test_an_entry_without_its_project_is_never_reused(tmp_path):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    entry = _complete_entry(tmp_path, fingerprint)
    (entry / PROJECT_DIRNAME).rmdir()

    assert evaluate_entry(entry, fingerprint, VERSIONS) == (
        False,
        REASON_PROJECT_MISSING,
    )


@pytest.mark.parametrize(
    "version_key",
    ["schema_version", "ghidra_version", "pyghidra_version", "exporter_version"],
)
def test_every_resolved_version_invalidates_an_entry(tmp_path, version_key):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    entry = _complete_entry(tmp_path, fingerprint)

    hit, reason = evaluate_entry(
        entry, fingerprint, {**VERSIONS, version_key: "different"}
    )

    assert hit is False
    assert version_key in reason


def test_state_records_the_schema_and_fingerprint(tmp_path):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    entry = _complete_entry(tmp_path, fingerprint)

    state = json.loads((entry / CACHE_STATE_FILE).read_text())

    assert state["schema_version"] == SCHEMA_VERSION
    assert state["status"] == "complete"
    assert state["fingerprint"] == fingerprint
    assert state["versions"] == VERSIONS


def test_a_second_run_cannot_own_a_locked_entry(tmp_path):
    entry = tmp_path / "entry"

    with entry_lock(entry) as first:
        with entry_lock(entry) as second:
            assert second is False
        assert first is True


def test_discard_project_removes_only_the_project(tmp_path):
    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    entry = _complete_entry(tmp_path, fingerprint)
    (entry / PROJECT_DIRNAME / "program.gpr").write_text("project data")

    discard_project(tmp_path, entry)

    assert not (entry / PROJECT_DIRNAME).exists()
    assert (entry / CACHE_STATE_FILE).exists()


def test_discard_project_refuses_a_path_outside_the_cache_root(tmp_path):
    outside = tmp_path.parent / "not-a-cache-entry"
    outside.mkdir(exist_ok=True)

    with pytest.raises(ValueError, match="outside the cache root"):
        discard_project(tmp_path / "root", outside)


def test_cache_outcome_renders_a_manifest_block(tmp_path):
    outcome = CacheOutcome(enabled=True, hit=True, path=tmp_path, reason=REASON_HIT)

    assert outcome.as_manifest_block() == {
        "enabled": True,
        "hit": True,
        "path": str(tmp_path),
        "reason": REASON_HIT,
    }


def test_a_disabled_cache_reports_no_path():
    outcome = CacheOutcome(
        enabled=False, hit=False, path=None, reason="caching disabled"
    )

    assert outcome.as_manifest_block()["path"] is None


def _corpus(tmp_path, *, status="success", request_sha=None):
    """Build a minimal published corpus that resume can read."""
    from ghidra_decomp.artifacts import atomic_write_json, sha256_file
    from ghidra_decomp.decompiler import normalize_filters

    output = tmp_path / "corpus"
    (output / "functions").mkdir(parents=True)
    (output / "assembly").mkdir(parents=True)
    stem = "00100234_" + "0" * 24 + "_parse_config"
    (output / "functions" / f"{stem}.c").write_text("int parse_config(void) { }\n")
    (output / "assembly" / f"{stem}.s").write_text("00100234:  90  nop\n")

    record = {
        "name": "parse_config",
        "address": "00100234",
        "artifacts": {
            "pseudocode": f"functions/{stem}.c",
            "assembly": f"assembly/{stem}.s",
            "sidecar": f"functions/{stem}.json",
        },
        "decompilation": {"status": status, "error": None, "reused": False},
    }
    atomic_write_json(output / "functions" / f"{stem}.json", record)
    for path_key, hash_key in (
        ("pseudocode", "pseudocode_sha256"),
        ("assembly", "assembly_sha256"),
        ("sidecar", "sidecar_sha256"),
    ):
        record["artifacts"][hash_key] = sha256_file(
            output / record["artifacts"][path_key]
        )

    fingerprint = build_fingerprint(IDENTITY, ANALYSIS)
    if request_sha is not None:
        fingerprint = {**fingerprint, "sha256": request_sha}
    atomic_write_json(
        output / "manifest.json",
        {
            "schema_version": SCHEMA_VERSION,
            "status": "complete",
            "tool": {"name": "ghidra-decomp"},
            "input": IDENTITY,
            "fingerprints": {"request": fingerprint, "resolved": fingerprint},
            "indexes": {},
            "export": {"filters": normalize_filters(None)},
        },
    )
    atomic_write_json(output / "functions.json", [record])
    return output, record


def test_a_clean_successful_function_is_reusable(tmp_path):
    from ghidra_decomp.decompiler import load_resume_index

    output, _ = _corpus(tmp_path)

    index = load_resume_index(output, build_fingerprint(IDENTITY, ANALYSIS))

    assert len(index) == 1


@pytest.mark.parametrize("damaged", ["pseudocode", "assembly", "sidecar"])
def test_a_function_with_a_changed_artifact_is_never_reused(tmp_path, damaged):
    from ghidra_decomp.decompiler import load_resume_index

    output, record = _corpus(tmp_path)
    (output / record["artifacts"][damaged]).write_text("tampered")

    assert load_resume_index(output, build_fingerprint(IDENTITY, ANALYSIS)) == {}


@pytest.mark.parametrize("missing", ["pseudocode", "assembly", "sidecar"])
def test_a_function_with_a_missing_artifact_is_never_reused(tmp_path, missing):
    from ghidra_decomp.decompiler import load_resume_index

    output, record = _corpus(tmp_path)
    (output / record["artifacts"][missing]).unlink()

    assert load_resume_index(output, build_fingerprint(IDENTITY, ANALYSIS)) == {}


@pytest.mark.parametrize("status", ["fallback", "failed"])
def test_an_unsettled_function_is_never_reused(tmp_path, status):
    from ghidra_decomp.decompiler import load_resume_index

    output, _ = _corpus(tmp_path, status=status)

    assert load_resume_index(output, build_fingerprint(IDENTITY, ANALYSIS)) == {}


def test_a_corpus_describing_another_request_is_never_reused(tmp_path):
    from ghidra_decomp.decompiler import load_resume_index

    output, _ = _corpus(tmp_path, request_sha="f" * 64)

    assert load_resume_index(output, build_fingerprint(IDENTITY, ANALYSIS)) == {}


def test_a_missing_corpus_degrades_to_a_full_export(tmp_path):
    from ghidra_decomp.decompiler import load_resume_index

    assert (
        load_resume_index(tmp_path / "absent", build_fingerprint(IDENTITY, ANALYSIS))
        == {}
    )


def test_a_corrupt_functions_index_degrades_to_a_full_export(tmp_path):
    from ghidra_decomp.decompiler import load_resume_index

    output, _ = _corpus(tmp_path)
    (output / "functions.json").write_text("{ not json")

    assert load_resume_index(output, build_fingerprint(IDENTITY, ANALYSIS)) == {}


def test_a_corpus_built_with_other_filters_is_never_reused(tmp_path):
    from ghidra_decomp.decompiler import load_resume_index

    output, _ = _corpus(tmp_path)

    assert (
        load_resume_index(
            output, build_fingerprint(IDENTITY, ANALYSIS), {"include": ("^main$",)}
        )
        == {}
    )


def test_the_same_filters_still_allow_reuse(tmp_path):
    from ghidra_decomp.decompiler import load_resume_index

    output, _ = _corpus(tmp_path)

    index = load_resume_index(
        output, build_fingerprint(IDENTITY, ANALYSIS), {"include": ()}
    )

    assert len(index) == 1
