"""Integration test against a real binary supplied by the host system."""

import json
import re
import shutil
from pathlib import Path

import pytest
from conftest import require_ghidra, run_export, sha256_of

from ghidra_decomp.artifacts import SCHEMA_VERSION


@pytest.fixture(scope="module")
def system_decomp(tmp_path_factory):
    """Export the host's standard `true` executable once."""
    binary_name = shutil.which("true")
    if binary_name is None:
        pytest.skip("the host does not provide a `true` executable")

    binary = Path(binary_name).resolve()
    ghidra_path = require_ghidra()
    output = tmp_path_factory.mktemp("system_decomp")
    run_export(
        binary,
        output,
        "--combined",
        "--timeout",
        "30",
        ghidra_path=ghidra_path,
        timeout=600,
    )
    return binary, output


def test_manifest_is_complete_and_fingerprinted(system_decomp):
    binary, output = system_decomp
    manifest = json.loads((output / "manifest.json").read_text())

    assert manifest["schema_version"] == SCHEMA_VERSION
    assert manifest["status"] == "complete"
    assert manifest["input"] == {
        "path": str(binary),
        "sha256": sha256_of(binary),
        "size": binary.stat().st_size,
    }
    assert manifest["fingerprints"]["request"]["sha256"]
    assert manifest["fingerprints"]["resolved"]["sha256"]
    assert manifest["tool"]["ghidra_version"]
    assert manifest["analysis"]["language_id"]
    assert manifest["analysis"]["compiler_id"]
    export = manifest["export"]
    assert export["combined"] is True
    assert export["timeout"] == 30
    assert export["resumed"] is False
    assert 1 <= export["workers"] <= 4
    assert manifest["cache"]["enabled"] is True
    assert manifest["cache"]["reason"]
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
        assert sha256_of(path) == artifact["sha256"]


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
            assert sha256_of(path) == artifacts[hash_key]

        sidecar = json.loads((output / artifacts["sidecar"]).read_text())
        expected = json.loads(json.dumps(function))
        expected["artifacts"].pop("sidecar_sha256")
        assert sidecar == expected

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
