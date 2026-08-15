"""Integration test against a real binary supplied by the host system."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture(scope="module")
def system_decomp(tmp_path_factory):
    """Export the host's standard `true` executable once."""
    binary_name = shutil.which("true")
    if binary_name is None:
        pytest.skip("the host does not provide a `true` executable")

    binary = Path(binary_name).resolve()
    ghidra_path = Path(os.environ.get("GHIDRA_INSTALL_DIR", "/usr/share/ghidra"))
    if not ghidra_path.is_dir():
        pytest.skip("Ghidra installation was not found")
    output = tmp_path_factory.mktemp("system_decomp")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "ghidra_decomp",
            str(binary),
            "--ghidra-path",
            str(ghidra_path),
            "--combined",
            "--timeout",
            "30",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    assert result.returncode == 0, (
        f"system binary export failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    return binary, output


def test_manifest_is_complete_and_fingerprinted(system_decomp):
    binary, output = system_decomp
    manifest = json.loads((output / "manifest.json").read_text())

    assert manifest["schema_version"] == 1
    assert manifest["status"] == "complete"
    assert manifest["input"] == {
        "path": str(binary),
        "sha256": _sha256(binary),
        "size": binary.stat().st_size,
    }
    assert manifest["fingerprint"]["sha256"]
    assert manifest["tool"]["ghidra_version"]
    assert manifest["analysis"]["language_id"]
    assert manifest["analysis"]["compiler_id"]
    assert manifest["export"] == {"combined": True, "timeout": 30, "workers": 1}
    assert not (output / ".run-state.json").exists()

    counts = manifest["counts"]
    assert counts["discovered"] > 0
    assert (
        counts["successful"] + counts["fallback"] + counts["failed"]
        == counts["discovered"]
    )


def test_manifest_index_hashes_match(system_decomp):
    _, output = system_decomp
    manifest = json.loads((output / "manifest.json").read_text())

    for artifact in manifest["indexes"].values():
        path = output / artifact["path"]
        assert path.is_file()
        assert _sha256(path) == artifact["sha256"]


def test_function_artifacts_and_sidecars_match(system_decomp):
    _, output = system_decomp
    functions = json.loads((output / "functions.json").read_text())

    assert functions
    for function in functions:
        assert function["body_ranges"]
        assert function["size"] > 0
        assert function["decompilation"]["status"] in {"success", "fallback"}
        assert "parameters" in function["signature"]
        assert "locals" in function["signature"]
        assert set(function["stack_frame"]) == {
            "frame_size",
            "local_size",
            "parameter_offset",
            "return_address_offset",
        }

        artifacts = function["artifacts"]
        for path_key, hash_key in (
            ("pseudocode", "pseudocode_sha256"),
            ("assembly", "assembly_sha256"),
            ("sidecar", "sidecar_sha256"),
        ):
            path = output / artifacts[path_key]
            assert path.is_file()
            assert _sha256(path) == artifacts[hash_key]

        sidecar = json.loads((output / artifacts["sidecar"]).read_text())
        assert sidecar["address"] == function["address"]
        assert (
            sidecar["artifacts"]["pseudocode_sha256"] == artifacts["pseudocode_sha256"]
        )

        for variable in (
            function["signature"]["parameters"] + function["signature"]["locals"]
        ):
            assert variable["data_type"]
            assert variable["size"] >= 0
            assert variable["source"]
            assert set(variable["storage"]) == {
                "kind",
                "register",
                "stack_offset",
                "description",
            }


def test_assembly_contains_addresses_and_raw_bytes(system_decomp):
    _, output = system_decomp
    assembly = "\n".join(
        path.read_text() for path in sorted((output / "assembly").glob("*.s"))
    )

    assert re.search(r"(?m)^[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2} ?)+\s+\w+", assembly)


def test_xrefs_include_call_sites_and_targets(system_decomp):
    _, output = system_decomp
    xrefs = [
        json.loads(line) for line in (output / "xrefs.jsonl").read_text().splitlines()
    ]
    functions = json.loads((output / "functions.json").read_text())
    calls = [call for function in functions for call in function["calls"]]

    assert xrefs
    assert calls
    assert all(call["call_site"] for call in calls)
    assert all(call["target_address"] for call in calls)
    assert all(call["reference_type"] for call in calls)
    assert {call["call_site"] for call in calls} <= {
        reference["from_address"] for reference in xrefs
    }


def test_combined_output_contains_exported_functions(system_decomp):
    _, output = system_decomp
    functions = json.loads((output / "functions.json").read_text())
    combined = (output / "all_functions.c").read_text()

    assert combined
    assert all(
        f"// Address:  {function['address']}" in combined for function in functions
    )
