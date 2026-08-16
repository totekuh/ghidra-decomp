"""End-to-end tests for the analysis cache and resumable export.

These start embedded Ghidra and are skipped when it is unavailable. Every run
gets its own XDG_CACHE_HOME so the developer's real cache is never read or
written by the suite.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from conftest import (
    FIXTURES,
    assert_artifact_hashes,
    load_json,
    require_ghidra,
    run_export,
    sha256_of,
)

FIXTURE = "multiarch_x86_32"
LANGUAGE = "x86:LE:32:default"
COMPILER = "gcc"
SPEC = ("--language", LANGUAGE, "--compiler", COMPILER, "--timeout", "30")


@pytest.fixture(scope="module")
def ghidra_path() -> Path:
    return require_ghidra()


@pytest.fixture
def cache_home(tmp_path) -> dict[str, str]:
    """Isolate the cache so a test never touches the developer's own."""
    return {"XDG_CACHE_HOME": str(tmp_path / "xdg")}


def _export(binary, output, ghidra_path, cache_home, *extra):
    return run_export(
        binary, output, *SPEC, *extra, ghidra_path=ghidra_path, env=cache_home
    )


def _index_hashes(output: Path) -> dict[str, str]:
    manifest = load_json(output, "manifest.json")
    return {name: item["sha256"] for name, item in manifest["indexes"].items()}


def test_a_second_run_reuses_the_cached_analysis(tmp_path, ghidra_path, cache_home):
    binary = FIXTURES / FIXTURE
    first = tmp_path / "first"
    second = tmp_path / "second"

    _export(binary, first, ghidra_path, cache_home)
    _export(binary, second, ghidra_path, cache_home)

    cold = load_json(first, "manifest.json")["cache"]
    warm = load_json(second, "manifest.json")["cache"]

    assert cold["enabled"] is True and cold["hit"] is False
    assert warm["hit"] is True
    assert warm["path"] == cold["path"]
    # A reused analysis must produce the same corpus, not merely a faster one.
    assert _index_hashes(second) == _index_hashes(first)


def test_the_cache_is_untouched_when_disabled(tmp_path, ghidra_path, cache_home):
    output = tmp_path / "corpus"

    _export(FIXTURES / FIXTURE, output, ghidra_path, cache_home, "--no-cache")

    cache = load_json(output, "manifest.json")["cache"]
    assert cache == {
        "enabled": False,
        "hit": False,
        "path": None,
        "reason": "caching disabled",
    }
    # Ghidra itself uses XDG_CACHE_HOME, so only this tool's own root must be
    # absent.
    assert not (Path(cache_home["XDG_CACHE_HOME"]) / "ghidra-decomp").exists()


def test_changed_input_bytes_invalidate_the_cache(tmp_path, ghidra_path, cache_home):
    original = FIXTURES / FIXTURE
    mutated = tmp_path / "mutated.elf"
    data = bytearray(original.read_bytes())
    # Flip a byte inside a function body, well past the ELF header.
    data[-1] ^= 0xFF
    mutated.write_bytes(bytes(data))

    _export(original, tmp_path / "first", ghidra_path, cache_home)
    _export(mutated, tmp_path / "second", ghidra_path, cache_home)

    warm = load_json(tmp_path / "second", "manifest.json")["cache"]
    assert warm["hit"] is False


def test_force_analysis_rejects_a_valid_cache_entry(tmp_path, ghidra_path, cache_home):
    binary = FIXTURES / FIXTURE
    _export(binary, tmp_path / "first", ghidra_path, cache_home)

    _export(binary, tmp_path / "second", ghidra_path, cache_home, "--force-analysis")

    warm = load_json(tmp_path / "second", "manifest.json")["cache"]
    assert warm["hit"] is False
    assert warm["reason"] == "reanalysis forced"


def test_force_export_keeps_the_cache_but_rebuilds_artifacts(
    tmp_path, ghidra_path, cache_home
):
    binary = FIXTURES / FIXTURE
    output = tmp_path / "corpus"
    _export(binary, output, ghidra_path, cache_home)

    _export(binary, output, ghidra_path, cache_home, "--resume", "--force-export")

    manifest = load_json(output, "manifest.json")
    assert manifest["cache"]["hit"] is True
    assert manifest["export"]["resumed"] is False
    assert manifest["counts"]["skipped"] == 0


def test_resume_rebuilds_only_invalidated_functions(tmp_path, ghidra_path, cache_home):
    binary = FIXTURES / FIXTURE
    output = tmp_path / "corpus"
    _export(binary, output, ghidra_path, cache_home)

    records = load_json(output, "functions.json")
    total = len(records)
    assert total >= 2

    deleted, corrupted = records[0], records[1]
    (output / deleted["artifacts"]["pseudocode"]).unlink()
    corrupted_assembly = output / corrupted["artifacts"]["assembly"]
    corrupted_assembly.write_text(corrupted_assembly.read_text() + "; tampered\n")

    _export(binary, output, ghidra_path, cache_home, "--resume")

    manifest = load_json(output, "manifest.json")
    assert manifest["export"]["resumed"] is True
    assert manifest["counts"]["skipped"] == total - 2
    assert manifest["counts"]["discovered"] == total

    rebuilt = {
        record["address"]: record for record in load_json(output, "functions.json")
    }
    assert rebuilt[deleted["address"]]["decompilation"]["reused"] is False
    assert rebuilt[corrupted["address"]]["decompilation"]["reused"] is False
    # The repaired corpus must be internally consistent again.
    for record in rebuilt.values():
        assert_artifact_hashes(output, record)


def test_resume_without_a_previous_corpus_is_a_full_export(
    tmp_path, ghidra_path, cache_home
):
    output = tmp_path / "corpus"

    _export(FIXTURES / FIXTURE, output, ghidra_path, cache_home, "--resume")

    manifest = load_json(output, "manifest.json")
    assert manifest["export"]["resumed"] is False
    assert manifest["counts"]["skipped"] == 0


def test_resume_ignores_a_corpus_describing_another_binary(
    tmp_path, ghidra_path, cache_home
):
    output = tmp_path / "corpus"
    _export(FIXTURES / FIXTURE, output, ghidra_path, cache_home)

    other = FIXTURES / "multiarch_aarch64"
    run_export(
        other,
        output,
        "--language",
        "AARCH64:LE:64:v8A",
        "--compiler",
        "default",
        "--timeout",
        "30",
        "--resume",
        ghidra_path=ghidra_path,
        env=cache_home,
    )

    manifest = load_json(output, "manifest.json")
    assert manifest["export"]["resumed"] is False
    assert manifest["counts"]["skipped"] == 0
    assert manifest["analysis"]["language_id"] == "AARCH64:LE:64:v8A"


def test_an_interrupted_analysis_is_never_reused(tmp_path, ghidra_path, cache_home):
    binary = FIXTURES / FIXTURE
    _export(binary, tmp_path / "first", ghidra_path, cache_home)

    root = Path(cache_home["XDG_CACHE_HOME"]) / "ghidra-decomp"
    entries = [path for path in root.iterdir() if path.is_dir()]
    assert len(entries) == 1
    state_path = entries[0] / "cache-state.json"
    state = json.loads(state_path.read_text())
    state["status"] = "incomplete"
    state_path.write_text(json.dumps(state))

    _export(binary, tmp_path / "second", ghidra_path, cache_home)

    warm = load_json(tmp_path / "second", "manifest.json")["cache"]
    assert warm["hit"] is False
    assert warm["reason"] == "cached analysis did not finish"


def test_a_published_corpus_never_contains_run_state_or_lock_files(
    tmp_path, ghidra_path, cache_home
):
    output = tmp_path / "corpus"

    _export(FIXTURES / FIXTURE, output, ghidra_path, cache_home)

    names = {path.name for path in output.rglob("*")}
    assert ".run-state.json" not in names
    assert not any(name.endswith(".lock") for name in names)
    # Staging siblings must not survive a successful run either.
    assert not any(
        path.name.startswith(".corpus.staging-") for path in tmp_path.iterdir()
    )


def test_manifest_index_hashes_match_the_published_files(
    tmp_path, ghidra_path, cache_home
):
    output = tmp_path / "corpus"

    _export(FIXTURES / FIXTURE, output, ghidra_path, cache_home)

    manifest = load_json(output, "manifest.json")
    for item in manifest["indexes"].values():
        assert sha256_of(output / item["path"]) == item["sha256"]


def _corpus_files(output: Path) -> dict[str, str]:
    """Hash every published artifact, keyed by its path inside the corpus."""
    return {
        str(path.relative_to(output)): sha256_of(path)
        for path in sorted(output.rglob("*"))
        if path.is_file()
    }


def test_serial_and_parallel_corpora_are_identical(tmp_path, ghidra_path, cache_home):
    """The gate for parallelism: worker count must not change the corpus."""
    binary = FIXTURES / FIXTURE
    serial = tmp_path / "serial"
    parallel = tmp_path / "parallel"

    _export(binary, serial, ghidra_path, cache_home, "--workers", "1")
    _export(binary, parallel, ghidra_path, cache_home, "--workers", "4")

    serial_files = _corpus_files(serial)
    parallel_files = _corpus_files(parallel)
    assert set(serial_files) == set(parallel_files)

    # Only the manifest legitimately differs, and only in fields that record how
    # the run was configured rather than what it found.
    differing = {
        name for name, digest in serial_files.items() if parallel_files[name] != digest
    }
    assert differing <= {"manifest.json"}

    serial_manifest = load_json(serial, "manifest.json")
    parallel_manifest = load_json(parallel, "manifest.json")
    assert serial_manifest["export"]["workers"] == 1
    assert parallel_manifest["export"]["workers"] == 4
    assert parallel_manifest["counts"] == serial_manifest["counts"]

    for manifest in (serial_manifest, parallel_manifest):
        manifest.pop("export")
        manifest.pop("cache")
        manifest["indexes"].pop("manifest.json", None)
    assert parallel_manifest == serial_manifest


def test_worker_count_does_not_change_the_cache_key(tmp_path, ghidra_path, cache_home):
    binary = FIXTURES / FIXTURE

    _export(binary, tmp_path / "serial", ghidra_path, cache_home, "--workers", "1")
    _export(binary, tmp_path / "parallel", ghidra_path, cache_home, "--workers", "4")

    warm = load_json(tmp_path / "parallel", "manifest.json")["cache"]
    assert warm["hit"] is True


def test_a_filtered_export_produces_a_consistent_subset(
    tmp_path, ghidra_path, cache_home
):
    binary = FIXTURES / FIXTURE
    full = tmp_path / "full"
    subset = tmp_path / "subset"

    _export(binary, full, ghidra_path, cache_home)
    _export(binary, subset, ghidra_path, cache_home, "--include", "^sum_")

    full_names = {record["name"] for record in load_json(full, "functions.json")}
    subset_records = load_json(subset, "functions.json")
    subset_names = {record["name"] for record in subset_records}

    assert subset_names < full_names
    assert all(name.startswith("sum_") for name in subset_names)

    manifest = load_json(subset, "manifest.json")
    assert manifest["export"]["filters"]["include"] == ["^sum_"]
    assert manifest["export"]["discovered_before_filters"] == len(full_names)
    assert manifest["counts"]["discovered"] == len(subset_records)

    # A filtered corpus must still be internally consistent.
    for record in subset_records:
        assert_artifact_hashes(subset, record)
    assert {path.stem for path in (subset / "functions").glob("*.c")} == {
        path.stem for path in (subset / "assembly").glob("*.s")
    }


def test_an_excluded_function_is_absent_from_the_corpus(
    tmp_path, ghidra_path, cache_home
):
    binary = FIXTURES / FIXTURE
    output = tmp_path / "corpus"

    _export(binary, output, ghidra_path, cache_home, "--exclude", "^entry$")

    names = {record["name"] for record in load_json(output, "functions.json")}
    assert "entry" not in names
    assert names


def test_an_explicitly_named_address_is_exported(tmp_path, ghidra_path, cache_home):
    binary = FIXTURES / FIXTURE
    full = tmp_path / "full"
    _export(binary, full, ghidra_path, cache_home)
    target = load_json(full, "functions.json")[0]

    output = tmp_path / "single"
    _export(
        binary,
        output,
        ghidra_path,
        cache_home,
        "--include",
        "^no_such_function$",
        "--function",
        target["address"],
    )

    records = load_json(output, "functions.json")
    assert [record["address"] for record in records] == [target["address"]]


def test_an_invalid_filter_pattern_fails_before_ghidra_starts(
    tmp_path, ghidra_path, cache_home
):
    result = run_export(
        FIXTURES / FIXTURE,
        tmp_path / "corpus",
        *SPEC,
        "--include",
        "[unclosed",
        ghidra_path=ghidra_path,
        env=cache_home,
        check=False,
    )

    assert result.returncode != 0
    assert "Invalid regular expression" in result.stderr
    assert not (tmp_path / "corpus").exists()


def test_a_filtered_corpus_is_never_reused_by_an_unfiltered_run(
    tmp_path, ghidra_path, cache_home
):
    binary = FIXTURES / FIXTURE
    output = tmp_path / "corpus"
    _export(binary, output, ghidra_path, cache_home, "--include", "^sum_")

    _export(binary, output, ghidra_path, cache_home, "--resume")

    manifest = load_json(output, "manifest.json")
    assert manifest["export"]["resumed"] is False
    assert manifest["counts"]["skipped"] == 0
    assert manifest["export"]["filters"]["include"] == []


def test_the_same_filters_still_allow_resume(tmp_path, ghidra_path, cache_home):
    binary = FIXTURES / FIXTURE
    output = tmp_path / "corpus"
    _export(binary, output, ghidra_path, cache_home, "--include", "^sum_")

    _export(binary, output, ghidra_path, cache_home, "--include", "^sum_", "--resume")

    manifest = load_json(output, "manifest.json")
    assert manifest["export"]["resumed"] is True
    assert manifest["counts"]["skipped"] == manifest["counts"]["discovered"]


def test_filters_do_not_invalidate_the_analysis_cache(
    tmp_path, ghidra_path, cache_home
):
    binary = FIXTURES / FIXTURE

    _export(binary, tmp_path / "full", ghidra_path, cache_home)
    _export(binary, tmp_path / "subset", ghidra_path, cache_home, "--include", "^sum_")

    # The Ghidra project is identical regardless of which functions are exported.
    warm = load_json(tmp_path / "subset", "manifest.json")["cache"]
    assert warm["hit"] is True


GDT_ARCHIVE = Path(
    "/usr/share/ghidra/Ghidra/Features/Base/data/typeinfo/generic/generic_clib.gdt"
)


def test_gzf_export_is_written_and_indexed(tmp_path, ghidra_path, cache_home):
    output = tmp_path / "corpus"

    _export(FIXTURES / FIXTURE, output, ghidra_path, cache_home, "--gzf")

    manifest = load_json(output, "manifest.json")
    assert manifest["export"]["secondary_products"]["gzf"] == "program.gzf"

    packed = output / "program.gzf"
    assert packed.is_file()
    assert packed.stat().st_size > 0
    # It must be covered by the manifest's hashes like every other index.
    assert sha256_of(packed) == manifest["indexes"]["program.gzf"]["sha256"]


def test_no_gzf_is_written_by_default(tmp_path, ghidra_path, cache_home):
    output = tmp_path / "corpus"

    _export(FIXTURES / FIXTURE, output, ghidra_path, cache_home)

    assert not (output / "program.gzf").exists()
    assert load_json(output, "manifest.json")["export"]["secondary_products"] == {}


def test_a_data_type_archive_is_recorded_in_the_analysis(
    tmp_path, ghidra_path, cache_home
):
    if not GDT_ARCHIVE.is_file():
        pytest.skip(f"the Ghidra installation has no {GDT_ARCHIVE.name}")
    output = tmp_path / "corpus"

    _export(
        FIXTURES / FIXTURE, output, ghidra_path, cache_home, "--gdt", str(GDT_ARCHIVE)
    )

    archives = load_json(output, "manifest.json")["analysis"]["data_type_archives"]
    assert [Path(item["path"]).name for item in archives] == [GDT_ARCHIVE.name]
    assert archives[0]["sha256"] == sha256_of(GDT_ARCHIVE)


def test_a_data_type_archive_changes_the_cache_key(tmp_path, ghidra_path, cache_home):
    if not GDT_ARCHIVE.is_file():
        pytest.skip(f"the Ghidra installation has no {GDT_ARCHIVE.name}")
    binary = FIXTURES / FIXTURE

    _export(binary, tmp_path / "plain", ghidra_path, cache_home)
    _export(
        binary, tmp_path / "typed", ghidra_path, cache_home, "--gdt", str(GDT_ARCHIVE)
    )

    plain = load_json(tmp_path / "plain", "manifest.json")["cache"]
    typed = load_json(tmp_path / "typed", "manifest.json")["cache"]
    # An archive changes what the analyzer produces, so it must not be served
    # from the cache entry built without it.
    assert typed["hit"] is False
    assert typed["path"] != plain["path"]


def test_a_missing_data_type_archive_fails_before_ghidra_starts(
    tmp_path, ghidra_path, cache_home
):
    result = run_export(
        FIXTURES / FIXTURE,
        tmp_path / "corpus",
        *SPEC,
        "--gdt",
        str(tmp_path / "absent.gdt"),
        ghidra_path=ghidra_path,
        env=cache_home,
        check=False,
    )

    assert result.returncode != 0
    assert not (tmp_path / "corpus").exists()


def test_semgrep_writes_sarif_when_requested(tmp_path, ghidra_path, cache_home):
    if shutil.which("semgrep") is None:
        pytest.skip("semgrep is not installed")
    output = tmp_path / "corpus"

    _export(
        FIXTURES / FIXTURE,
        output,
        ghidra_path,
        cache_home,
        "--semgrep-config",
        "p/default",
    )

    manifest = load_json(output, "manifest.json")
    scan = manifest["export"]["secondary_products"]["semgrep"]
    assert scan["path"] == "semgrep.sarif"
    assert scan["config"] == "p/default"

    sarif = load_json(output, "semgrep.sarif")
    assert sarif["$schema"]
    assert (
        sha256_of(output / "semgrep.sarif")
        == (manifest["indexes"]["semgrep.sarif"]["sha256"])
    )


def test_a_missing_semgrep_is_reported_clearly(tmp_path, ghidra_path, cache_home):
    if shutil.which("semgrep") is not None:
        pytest.skip("semgrep is installed, so its absence cannot be exercised")

    result = run_export(
        FIXTURES / FIXTURE,
        tmp_path / "corpus",
        *SPEC,
        "--semgrep-config",
        "auto",
        ghidra_path=ghidra_path,
        env=cache_home,
        check=False,
    )

    assert result.returncode != 0
    assert "semgrep is not installed" in result.stderr
    # A failed secondary product must not leave a half-published corpus behind.
    assert not (tmp_path / "corpus").exists()
