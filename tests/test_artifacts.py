"""Unit tests for corpus artifact helpers."""

import errno
import hashlib
import json
import os
import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest
from click import ClickException
from click.testing import CliRunner

from ghidra_decomp.artifacts import (
    OWNED_SCHEMA_VERSIONS,
    SCHEMA_VERSION,
    atomic_write_json,
    atomic_write_text,
    build_fingerprint,
    fsync_directory,
    publish_directory,
    recover_destination,
    sha256_file,
    snapshot_input,
    staging_lock,
    staging_prefix,
    sweep_orphan_staging,
    validate_destination,
)
from ghidra_decomp.cli import main
from ghidra_decomp.decompiler import _export_all, _sanitize_name, decompile_binary


def _complete_manifest(**extra):
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "tool": {"name": "ghidra-decomp"},
        "input": {},
        "fingerprints": {},
        "indexes": {},
        **extra,
    }


def test_sha256_file(tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(b"binary data")

    assert sha256_file(path) == hashlib.sha256(b"binary data").hexdigest()


def test_build_fingerprint_is_deterministic_and_sensitive(tmp_path):
    path = tmp_path / "input.bin"
    path.write_bytes(b"binary data")
    analysis = {"language": "x86:LE:64:default", "base_address": None}

    first = build_fingerprint(path, analysis)
    second = build_fingerprint(path, dict(reversed(list(analysis.items()))))

    assert first == second
    assert first["schema_version"] == SCHEMA_VERSION
    assert first["input"]["path"] == str(path.resolve())
    assert first["input"]["size"] == len(b"binary data")

    changed = build_fingerprint(path, {**analysis, "base_address": "0x1000"})
    assert changed["sha256"] != first["sha256"]


def test_fingerprint_identity_does_not_depend_on_source_path(tmp_path):
    first_path = tmp_path / "first.bin"
    second_path = tmp_path / "second.bin"
    first_path.write_bytes(b"same bytes")
    second_path.write_bytes(b"same bytes")

    assert (
        build_fingerprint(first_path, {})["sha256"]
        == build_fingerprint(second_path, {})["sha256"]
    )


def test_snapshot_identity_describes_the_copied_bytes(tmp_path):
    source = tmp_path / "input.bin"
    snapshot = tmp_path / "snapshot.bin"
    source.write_bytes(b"original")

    identity = snapshot_input(source, snapshot)
    source.write_bytes(b"mutated after snapshot")

    assert snapshot.read_bytes() == b"original"
    assert identity == {
        "path": str(source.resolve()),
        "sha256": hashlib.sha256(b"original").hexdigest(),
        "size": len(b"original"),
    }


def test_validate_destination_rejects_unowned_and_ambiguous_directories(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    (output / "unrelated.txt").write_text("keep")

    with pytest.raises(ValueError, match="unowned"):
        validate_destination(output)

    (output / "manifest.json").write_text(json.dumps(_complete_manifest()))
    (output / ".run-state.json").write_text("{}")
    with pytest.raises(ValueError, match="incomplete or unowned"):
        validate_destination(output)


def test_publish_directory_replaces_an_owned_corpus(tmp_path):
    output = tmp_path / "output"
    output.mkdir()
    atomic_write_json(
        output / "manifest.json",
        _complete_manifest(),
    )
    (output / "old.txt").write_text("old")
    expected = validate_destination(output)
    staging = tmp_path / ".output.staging"
    staging.mkdir()
    atomic_write_json(
        staging / "manifest.json",
        _complete_manifest(new=True),
    )

    assert publish_directory(staging, output, expected) is None

    assert json.loads((output / "manifest.json").read_text())["new"] is True
    assert not (output / "old.txt").exists()


def test_publish_directory_restores_backup_when_publication_fails(
    tmp_path, monkeypatch
):
    output = tmp_path / "output"
    output.mkdir()
    atomic_write_json(
        output / "manifest.json",
        _complete_manifest(),
    )
    (output / "valuable.txt").write_text("preserve")
    expected = validate_destination(output)
    staging = tmp_path / ".output.staging"
    staging.mkdir()
    atomic_write_json(
        staging / "manifest.json",
        _complete_manifest(),
    )
    real_replace = os.replace
    calls = 0

    def fail_staging_publish(source, destination):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected publication failure")
        real_replace(source, destination)

    monkeypatch.setattr("ghidra_decomp.artifacts.os.replace", fail_staging_publish)

    with pytest.raises(OSError, match="injected publication failure"):
        publish_directory(staging, output, expected)

    assert (output / "valuable.txt").read_text() == "preserve"
    assert staging.is_dir()


def test_concurrent_publishers_cannot_both_succeed(tmp_path):
    output = tmp_path / "output"
    expected = validate_destination(output)
    staging_dirs = []
    for publisher in ("first", "second"):
        staging = tmp_path / f".{publisher}.staging"
        staging.mkdir()
        atomic_write_json(
            staging / "manifest.json", _complete_manifest(publisher=publisher)
        )
        staging_dirs.append(staging)

    barrier = threading.Barrier(2)
    results = []

    def publish(staging):
        barrier.wait()
        try:
            publish_directory(staging, output, expected)
            results.append("success")
        except ValueError:
            results.append("changed")

    threads = [
        threading.Thread(target=publish, args=(staging,)) for staging in staging_dirs
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert sorted(results) == ["changed", "success"]
    assert json.loads((output / "manifest.json").read_text())["publisher"] in {
        "first",
        "second",
    }


def test_fsync_directory_tolerates_unsupported_permission_error(tmp_path, monkeypatch):
    def unsupported_open(*args, **kwargs):
        raise PermissionError(errno.EACCES, "unsupported")

    monkeypatch.setattr("ghidra_decomp.artifacts.os.open", unsupported_open)

    fsync_directory(tmp_path)


def test_recover_destination_restores_owned_backup(tmp_path):
    output = tmp_path / "output"
    backup = tmp_path / ".output.backup-interrupted"
    backup.mkdir()
    atomic_write_json(
        backup / "manifest.json",
        _complete_manifest(),
    )
    (backup / "valuable.txt").write_text("preserve")

    assert recover_destination(output) is True

    assert (output / "valuable.txt").read_text() == "preserve"
    assert not backup.exists()


def test_recover_destination_treats_output_name_literally(tmp_path):
    output = tmp_path / "result[1]"
    backup = tmp_path / ".result[1].backup-interrupted"
    backup.mkdir()
    atomic_write_json(backup / "manifest.json", _complete_manifest())

    assert recover_destination(output) is True
    assert output.is_dir()


def test_failed_rerun_preserves_complete_corpus(tmp_path, monkeypatch):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")
    output = tmp_path / "output"
    output.mkdir()
    atomic_write_json(
        output / "manifest.json",
        _complete_manifest(),
    )
    (output / "valuable.txt").write_text("preserve")

    def fail_start(_):
        raise ClickException("injected startup failure")

    monkeypatch.setattr("ghidra_decomp.decompiler._start_pyghidra", fail_start)

    with pytest.raises(ClickException, match="injected startup failure"):
        decompile_binary(binary, output)

    assert (output / "valuable.txt").read_text() == "preserve"
    assert (output / "manifest.json").is_file()
    assert not list(tmp_path.glob(".output.staging-*"))


def test_output_must_not_contain_input(tmp_path):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")

    with pytest.raises(ClickException, match="must not contain"):
        decompile_binary(binary, tmp_path)


def test_export_setup_failure_does_not_create_decompiler(tmp_path, monkeypatch):
    created = []

    class FakeDecompInterface:
        def __init__(self):
            created.append(self)

    modules = {
        "ghidra": ModuleType("ghidra"),
        "ghidra.app": ModuleType("ghidra.app"),
        "ghidra.app.decompiler": ModuleType("ghidra.app.decompiler"),
        "ghidra.framework": ModuleType("ghidra.framework"),
        "ghidra.util": ModuleType("ghidra.util"),
        "ghidra.util.task": ModuleType("ghidra.util.task"),
    }
    modules["ghidra.app.decompiler"].DecompInterface = FakeDecompInterface
    modules["ghidra.framework"].Application = object
    modules["ghidra.util.task"].ConsoleTaskMonitor = object
    for name, module in modules.items():
        monkeypatch.setitem(sys.modules, name, module)

    def fail_extraction(_program):
        raise RuntimeError("injected setup failure")

    monkeypatch.setattr("ghidra_decomp.decompiler._extract_strings", fail_extraction)
    program = SimpleNamespace(
        getFunctionManager=lambda: SimpleNamespace(getFunctions=lambda _forward: [])
    )
    output = tmp_path / "staging"
    output.mkdir()

    with pytest.raises(RuntimeError, match="injected setup failure"):
        _export_all(
            program,
            {"path": "/original", "sha256": "digest", "size": 1},
            output,
            60,
            requested_analysis={},
            request_fingerprint={},
            filters={},
            pyghidra_version="test",
        )

    assert created == []


def test_atomic_write_text_replaces_content_and_cleans_temp(tmp_path):
    path = tmp_path / "nested" / "artifact.txt"
    atomic_write_text(path, "old")
    atomic_write_text(path, "new")

    assert path.read_text() == "new"
    assert list(path.parent.glob(".artifact.txt.*.tmp")) == []


def test_atomic_write_json(tmp_path):
    path = tmp_path / "index.json"
    atomic_write_json(path, {"b": 2, "a": 1})

    assert json.loads(path.read_text()) == {"a": 1, "b": 2}
    assert path.read_text().index('"a"') < path.read_text().index('"b"')


def test_sanitize_name_replaces_unsafe_characters():
    assert _sanitize_name("namespace::function/name") == "namespace__function_name"


def test_timeout_must_be_positive():
    result = CliRunner().invoke(main, ["--timeout", "0"])

    assert result.exit_code != 0
    assert "0 is not in the range x>=1" in result.output


@pytest.mark.parametrize(
    ("argument", "expected"), [(None, False), ("--combined", True)]
)
def test_combined_option_is_forwarded(tmp_path, monkeypatch, argument, expected):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")
    received = []

    def fake_decompile_binary(*args, **kwargs):
        received.append(kwargs["combined"])

    monkeypatch.setattr("ghidra_decomp.cli.decompile_binary", fake_decompile_binary)
    arguments = [str(binary)]
    if argument is not None:
        arguments.append(argument)

    result = CliRunner().invoke(main, arguments)

    assert result.exit_code == 0
    assert received == [expected]


def _staged(output, suffix):
    staging = output.parent / f"{staging_prefix(output)}{suffix}"
    staging.mkdir()
    (staging / "partial.c").write_text("half a corpus")
    return staging


def test_sweep_orphan_staging_removes_only_abandoned_siblings(tmp_path):
    output = tmp_path / "corpus"
    abandoned = _staged(output, "aaaa")
    other_output = tmp_path / "unrelated"
    foreign = _staged(other_output, "bbbb")
    decoy = tmp_path / "corpus.staging-cccc"
    decoy.mkdir()

    removed = sweep_orphan_staging(output)

    assert removed == [abandoned]
    assert not abandoned.exists()
    assert foreign.exists()
    assert decoy.exists()


def test_sweep_orphan_staging_spares_a_staging_directory_owned_by_a_live_run(tmp_path):
    output = tmp_path / "corpus"
    live = _staged(output, "dddd")
    abandoned = _staged(output, "eeee")

    with staging_lock(live):
        removed = sweep_orphan_staging(output)

    assert removed == [abandoned]
    assert live.exists()
    assert (live / "partial.c").read_text() == "half a corpus"


def test_staging_lock_refuses_a_directory_another_holder_owns(tmp_path):
    output = tmp_path / "corpus"
    staging = _staged(output, "ffff")

    with staging_lock(staging):
        contender = staging_lock(staging)
        with pytest.raises(ValueError, match="already owned"):
            contender.__enter__()


def test_staging_lock_file_is_never_published_into_the_corpus(tmp_path):
    output = tmp_path / "corpus"
    staging = _staged(output, "gggg")

    with staging_lock(staging):
        assert not any(path.name.endswith(".lock") for path in staging.iterdir())
        assert (staging.parent / f"{staging.name}.lock").exists()

    assert not (staging.parent / f"{staging.name}.lock").exists()


def test_recover_destination_sweeps_staging_before_restoring_a_backup(tmp_path):
    output = tmp_path / "corpus"
    abandoned = _staged(output, "hhhh")
    backup = tmp_path / f".{output.name}.backup-1-xyz"
    backup.mkdir()
    atomic_write_json(backup / "manifest.json", _complete_manifest())

    assert recover_destination(output) is True

    assert not abandoned.exists()
    assert (output / "manifest.json").exists()


def test_a_previous_schema_corpus_stays_replaceable(tmp_path):
    output = tmp_path / "corpus"
    output.mkdir()
    previous = min(OWNED_SCHEMA_VERSIONS)
    atomic_write_json(
        output / "manifest.json", _complete_manifest(schema_version=previous)
    )

    assert previous != SCHEMA_VERSION
    assert validate_destination(output).exists is True


def test_a_foreign_schema_corpus_is_never_replaced(tmp_path):
    output = tmp_path / "corpus"
    output.mkdir()
    atomic_write_json(
        output / "manifest.json",
        _complete_manifest(schema_version=max(OWNED_SCHEMA_VERSIONS) + 1),
    )

    with pytest.raises(ValueError, match="incomplete or unowned"):
        validate_destination(output)


@pytest.mark.parametrize(
    ("arguments", "expected"),
    [
        ([], {"cache_enabled": True, "resume": False}),
        (["--no-cache"], {"cache_enabled": False, "resume": False}),
        (["--resume"], {"cache_enabled": True, "resume": True}),
        (["--force-analysis"], {"force_analysis": True, "force_export": False}),
        (["--force-export"], {"force_analysis": False, "force_export": True}),
    ],
)
def test_cache_and_resume_options_are_forwarded(
    tmp_path, monkeypatch, arguments, expected
):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")
    received = {}

    def fake_decompile_binary(*args, **kwargs):
        received.update(kwargs)

    monkeypatch.setattr("ghidra_decomp.cli.decompile_binary", fake_decompile_binary)

    result = CliRunner().invoke(main, [str(binary), *arguments])

    assert result.exit_code == 0
    for key, value in expected.items():
        assert received[key] == value


def test_cache_dir_is_forwarded_as_a_path(tmp_path, monkeypatch):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")
    received = {}
    monkeypatch.setattr(
        "ghidra_decomp.cli.decompile_binary",
        lambda *args, **kwargs: received.update(kwargs),
    )

    result = CliRunner().invoke(
        main, [str(binary), "--cache-dir", str(tmp_path / "cache")]
    )

    assert result.exit_code == 0
    assert received["cache_dir"] == tmp_path / "cache"


def test_cache_dir_cannot_be_combined_with_no_cache(tmp_path):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")

    result = CliRunner().invoke(
        main, [str(binary), "--no-cache", "--cache-dir", str(tmp_path / "cache")]
    )

    assert result.exit_code != 0
    assert "cannot be combined with --no-cache" in result.output


@pytest.mark.parametrize(
    ("arguments", "key", "expected"),
    [
        (["--workers", "3"], "workers", 3),
        ([], "workers", None),
        (["--include", "^a", "--include", "^b"], "include", ("^a", "^b")),
        (["--exclude", "^_"], "exclude", ("^_",)),
        (["--function", "1000", "--function", "2000"], "function", ("1000", "2000")),
    ],
)
def test_worker_and_filter_options_are_forwarded(
    tmp_path, monkeypatch, arguments, key, expected
):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")
    received = {}
    monkeypatch.setattr(
        "ghidra_decomp.cli.decompile_binary",
        lambda *args, **kwargs: received.update(kwargs),
    )

    result = CliRunner().invoke(main, [str(binary), *arguments])

    assert result.exit_code == 0
    assert received[key] == expected


def test_worker_count_must_be_positive(tmp_path):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")

    result = CliRunner().invoke(main, [str(binary), "--workers", "0"])

    assert result.exit_code != 0
    assert "0 is not in the range x>=1" in result.output


def test_secondary_product_options_are_forwarded(tmp_path, monkeypatch):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")
    archive = tmp_path / "types.gdt"
    archive.write_bytes(b"archive")
    received = {}
    monkeypatch.setattr(
        "ghidra_decomp.cli.decompile_binary",
        lambda *args, **kwargs: received.update(kwargs),
    )

    result = CliRunner().invoke(
        main,
        [
            str(binary),
            "--gzf",
            "--gdt",
            str(archive),
            "--semgrep-config",
            "p/default",
        ],
    )

    assert result.exit_code == 0
    assert received["gzf"] is True
    assert received["gdt"] == (str(archive),)
    assert received["semgrep_config"] == "p/default"


def test_a_missing_data_type_archive_is_rejected_by_the_cli(tmp_path):
    binary = tmp_path / "input.bin"
    binary.write_bytes(b"input")

    result = CliRunner().invoke(
        main, [str(binary), "--gdt", str(tmp_path / "absent.gdt")]
    )

    assert result.exit_code != 0
    assert "does not exist" in result.output
