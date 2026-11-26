"""Tests for the --json CLI flag."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from ghidra_decomp.cli.main_cmd import _build_json_summary, main


@pytest.fixture()
def manifest_dir(tmp_path: Path) -> Path:
    """Create a minimal output directory with a manifest."""
    manifest = {
        "schema_version": 2,
        "status": "complete",
        "counts": {
            "discovered": 50,
            "successful": 45,
            "fallback": 3,
            "failed": 2,
            "skipped": 5,
        },
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return tmp_path


def test_build_json_summary_reads_manifest(manifest_dir: Path) -> None:
    binary = Path("/fake/firmware.bin")
    result = _build_json_summary(binary, manifest_dir)

    assert result["binary"] == str(binary)
    assert result["output"] == str(manifest_dir)
    assert result["functions_total"] == 50
    assert result["functions_successful"] == 45
    assert result["functions_fallback"] == 3
    assert result["functions_failed"] == 2
    assert result["functions_reused"] == 5
    assert result["manifest"] == str(manifest_dir / "manifest.json")
    assert "version" in result


def test_build_json_summary_missing_counts(tmp_path: Path) -> None:
    (tmp_path / "manifest.json").write_text(
        json.dumps({"schema_version": 2, "status": "complete"}),
        encoding="utf-8",
    )
    result = _build_json_summary(Path("/fake/bin"), tmp_path)
    assert result["functions_total"] == 0
    assert result["functions_failed"] == 0


def test_json_flag_decompile_outputs_json(tmp_path: Path, monkeypatch) -> None:
    """--json suppresses human text and prints JSON summary."""
    binary = tmp_path / "test.bin"
    binary.write_bytes(b"\x00" * 64)
    output = tmp_path / "out"

    manifest = {
        "schema_version": 2,
        "status": "complete",
        "counts": {
            "discovered": 10,
            "successful": 8,
            "fallback": 1,
            "failed": 1,
            "skipped": 0,
        },
    }

    def fake_decompile(bin_path, out_path, **kwargs):
        out_path.mkdir(parents=True, exist_ok=True)
        (out_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr("ghidra_decomp.cli.main_cmd.decompile_binary", fake_decompile)

    result = CliRunner().invoke(main, [str(binary), "-o", str(output), "--json"])
    assert result.exit_code == 0, result.output

    parsed = json.loads(result.output)
    assert parsed["functions_total"] == 10
    assert parsed["functions_successful"] == 8
    assert parsed["functions_failed"] == 1
    assert "Binary:" not in result.output
    assert "Done." not in result.output


def test_json_flag_kernel_gdt_outputs_json(tmp_path: Path, monkeypatch) -> None:
    """--json with --build-kernel-gdt prints stats as JSON."""
    kernel_src = tmp_path / "linux"
    kernel_src.mkdir()
    output = tmp_path / "out.gdt"

    stats = {"types_count": 20000, "headers_processed": 66}

    def fake_build_kernel_gdt(*args, **kwargs):
        return stats

    monkeypatch.setattr(
        "ghidra_decomp.kernel_gdt.build_kernel_gdt", fake_build_kernel_gdt
    )
    monkeypatch.setattr(
        "ghidra_decomp.cli.main_cmd.click.Path",
        lambda **kw: str,
    )

    result = CliRunner().invoke(
        main,
        [
            "--build-kernel-gdt",
            str(kernel_src),
            "--arch",
            "x86_64",
            "-o",
            str(output),
            "--json",
        ],
    )
    assert result.exit_code == 0, result.output
    parsed = json.loads(result.output)
    assert parsed["types_count"] == 20000
    assert "Done." not in result.output


def test_no_json_flag_prints_human_text(tmp_path: Path, monkeypatch) -> None:
    """Without --json, human-readable output appears."""
    binary = tmp_path / "test.bin"
    binary.write_bytes(b"\x00" * 64)
    output = tmp_path / "out"

    def fake_decompile(bin_path, out_path, **kwargs):
        out_path.mkdir(parents=True, exist_ok=True)
        manifest = {
            "schema_version": 2,
            "status": "complete",
            "counts": {
                "discovered": 5,
                "successful": 5,
                "fallback": 0,
                "failed": 0,
                "skipped": 0,
            },
        }
        (out_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    monkeypatch.setattr("ghidra_decomp.cli.main_cmd.decompile_binary", fake_decompile)

    result = CliRunner().invoke(main, [str(binary), "-o", str(output)])
    assert result.exit_code == 0, result.output
    assert "Done." in result.output
    # Should not be valid JSON
    with pytest.raises(json.JSONDecodeError):
        json.loads(result.output)
