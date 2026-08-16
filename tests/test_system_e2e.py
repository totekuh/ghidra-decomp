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
            assert set(variable["storage"]) == {
                "kind",
                "register",
                "stack_offset",
                "description",
            }

        # Parameters come from the function object and keep Ghidra's provenance.
        # Locals come from the decompiler, which does not expose one, so the key
        # is present and null rather than absent.
        for parameter in function["signature"]["parameters"]:
            assert parameter["source"]
        for local in function["signature"]["locals"]:
            assert "source" in local


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


def test_thunks_record_their_targets(system_decomp):
    """A thunk must not be a dead end in the callgraph."""
    _, output = system_decomp
    functions = json.loads((output / "functions.json").read_text())
    thunks = [function for function in functions if function["is_thunk"]]
    by_address = {function["address"]: function for function in functions}

    assert thunks, "the system binary was expected to contain thunks"
    for thunk in thunks:
        target = thunk["thunk"]
        assert target is not None
        assert target["name"], f"{thunk['name']} names no thunk target"
        assert target["address"]
        # An external thunk points outside the program, so a target that does
        # resolve locally must agree with the record it resolves to.
        local = by_address.get(target["address"])
        if local is not None:
            assert local["name"] == target["name"]

    for function in functions:
        if not function["is_thunk"]:
            assert function["thunk"] is None


def test_decompiler_warnings_are_recorded(system_decomp):
    """Where the decompiler says it gave up must be a field, not prose."""
    _, output = system_decomp
    functions = json.loads((output / "functions.json").read_text())

    warned = [
        function for function in functions if function["decompilation"]["warnings"]
    ]
    assert warned, "the system binary was expected to produce decompiler warnings"

    texts = set()
    for function in warned:
        pseudocode = (output / function["artifacts"]["pseudocode"]).read_text()
        for note in function["decompilation"]["warnings"]:
            assert note["kind"] in {"warning", "unresolved_local", "note"}
            assert note["text"]
            # Every recorded note must be traceable to the artifact it came from.
            assert note["text"] in " ".join(pseudocode.split())
            texts.add(note["text"])

    assert any("Subroutine does not return" in text for text in texts)


def test_locals_come_from_the_decompiler(system_decomp):
    _, output = system_decomp
    functions = json.loads((output / "functions.json").read_text())

    with_locals = [
        function for function in functions if function["signature"]["locals"]
    ]
    assert with_locals, "no function reported any local variable"

    for function in with_locals:
        for local in function["signature"]["locals"]:
            assert local["name"]
            assert local["data_type"]
            assert local["size"] >= 0
            assert local["storage"]["kind"] in {
                "stack",
                "register",
                "memory",
                "compound",
                "unassigned",
            }
        names = [local["name"] for local in function["signature"]["locals"]]
        parameters = [
            parameter["name"] for parameter in function["signature"]["parameters"]
        ]
        assert not set(names) & set(parameters), "a parameter leaked into locals"
