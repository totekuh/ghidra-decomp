"""Unit tests for corpus artifact helpers."""

import hashlib
import json

import pytest
from click.testing import CliRunner

from ghidra_decomp.artifacts import (
    SCHEMA_VERSION,
    atomic_write_json,
    atomic_write_text,
    build_fingerprint,
    sha256_file,
)
from ghidra_decomp.cli import main
from ghidra_decomp.decompiler import _sanitize_name


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
