"""Live-Ghidra integration coverage for checked-in architecture fixtures."""

import json
import re
from pathlib import Path

import pytest
from conftest import FIXTURES, load_json, require_ghidra, run_export, sha256_of

from ghidra_decomp.artifacts import build_fingerprint

MARKER = "ghidra-decomp multiarch fixture"
EXPECTED_FUNCTIONS = {
    "dispatch",
    "entry",
    "marker_checksum",
    "rotate_mix",
    "sum_positive",
}
EXPECTED_EXPORTS = EXPECTED_FUNCTIONS | {"fixture_marker", "global_state"}
EXPECTED_EDGES = {
    ("dispatch", "rotate_mix"),
    ("entry", "dispatch"),
    ("entry", "marker_checksum"),
    ("entry", "sum_positive"),
}
EXPECTED_INDEXES = {
    "callgraph.json",
    "exports.json",
    "functions.json",
    "imports.json",
    "metadata.json",
    "sections.json",
    "strings.json",
    "symbols.json",
    "types.json",
    "xrefs.jsonl",
}
EXPECTED_COUNTS = {
    "discovered": 5,
    "successful": 5,
    "fallback": 0,
    "failed": 0,
    "skipped": 0,
}
EXPECTED_FUNCTION_SIZES = {
    "multiarch_x86_32": [14, 56, 59, 63, 55],
    "multiarch_armv7": [12, 48, 52, 80, 68],
    "multiarch_aarch64": [12, 48, 48, 68, 80],
    "multiarch_mipsel": [44, 88, 92, 120, 100],
    "multiarch_ppc32": [12, 52, 52, 100, 100],
    "multiarch_riscv64": [14, 38, 38, 52, 60],
}
EXPECTED_TARGETS = {
    "multiarch_aarch64": "target=aarch64-none-elf; emulation=aarch64elf; extra_flags=",
    "multiarch_armv7": (
        "target=armv7-none-eabi; emulation=armelf; extra_flags=-mfloat-abi=soft"
    ),
    "multiarch_mipsel": "target=mipsel-none-elf; emulation=elf32ltsmip; extra_flags=",
    "multiarch_ppc32": "target=powerpc-none-elf; emulation=elf32ppc; extra_flags=",
    "multiarch_riscv64": "target=riscv64-none-elf; emulation=elf64lriscv; extra_flags=",
    "multiarch_x86_32": "target=i386-none-elf; emulation=elf_i386; extra_flags=",
}
ARCHITECTURES = [
    ("multiarch_x86_32", "x86", "x86:LE:32:default", "gcc", 32, "little"),
    ("multiarch_armv7", "ARM", "ARM:LE:32:v7", "default", 32, "little"),
    (
        "multiarch_aarch64",
        "AARCH64",
        "AARCH64:LE:64:v8A",
        "default",
        64,
        "little",
    ),
    (
        "multiarch_mipsel",
        "MIPS",
        "MIPS:LE:32:default",
        "default",
        32,
        "little",
    ),
    (
        "multiarch_ppc32",
        "PowerPC",
        "PowerPC:BE:32:default",
        "default",
        32,
        "big",
    ),
    ("multiarch_riscv64", "RISCV", "RISCV:LE:64:default", "gcc", 64, "little"),
]
ASSEMBLY_LINE = re.compile(
    r"^(?P<address>(?:[^:\s]+:)?[0-9a-fA-F]+):\s+"
    r"(?P<bytes>[0-9a-fA-F]{2}(?: [0-9a-fA-F]{2})*)\s+"
    r"(?P<mnemonic>\S+)(?:\s+.*)?$"
)


def _address_offset(value: str) -> int:
    return int(value.rsplit(":", 1)[-1], 16)


def _contained_path(output: Path, value: str) -> Path:
    relative = Path(value)
    assert not relative.is_absolute()
    assert ".." not in relative.parts
    path = (output / relative).resolve()
    assert path.is_relative_to(output.resolve())
    return path


@pytest.fixture(scope="module", params=ARCHITECTURES, ids=lambda item: item[0])
def architecture_corpus(request, tmp_path_factory):
    """Export one fixture in an isolated process with a bounded wall-clock time."""
    fixture_name, processor, language, compiler, address_size, endian = request.param
    ghidra_path = require_ghidra()

    binary = FIXTURES / fixture_name
    output = tmp_path_factory.mktemp(f"{fixture_name}_decomp")
    run_export(
        binary,
        output,
        "--language",
        language,
        "--compiler",
        compiler,
        "--timeout",
        "30",
        ghidra_path=ghidra_path,
    )
    return binary, output, processor, language, compiler, address_size, endian


def test_checked_in_fixture_hashes_and_provenance():
    checksums = {}
    for line in (
        (FIXTURES / "multiarch.sha256").read_text(encoding="ascii").splitlines()
    ):
        digest, name = line.split("  ", 1)
        checksums[name] = digest

    fixture_names = {architecture[0] for architecture in ARCHITECTURES}
    assert set(checksums) == fixture_names
    assert checksums == {name: sha256_of(FIXTURES / name) for name in fixture_names}
    assert all(
        b"/fixture-src/multiarch.c" in (FIXTURES / name).read_bytes()
        for name in fixture_names
    )

    provenance_lines = (
        (FIXTURES / "multiarch.provenance").read_text(encoding="utf-8").splitlines()
    )
    fields = dict(
        line.split(": ", 1)
        for line in provenance_lines
        if line and not line.startswith(" ") and line != "targets:"
    )
    targets = dict(
        line.strip().split(": ", 1)
        for line in provenance_lines
        if line.startswith("  ")
    )
    assert fields["format"] == "1"
    assert fields["source"] == "tests/fixtures/multiarch.c"
    assert fields["source_sha256"] == sha256_of(FIXTURES / "multiarch.c")
    assert fields["build_script"] == "tests/fixtures/build_multiarch.sh"
    assert fields["build_script_sha256"] == sha256_of(FIXTURES / "build_multiarch.sh")
    assert "clang version 21." in fields["compiler"]
    assert "LLD 21." in fields["linker"]
    assert fields["common_compile_flags"].split() == [
        "-O1",
        "-g",
        "-ffreestanding",
        "-fno-stack-protector",
        "-fno-builtin",
        "-fno-pic",
        "-ffile-prefix-map=<fixture-dir>=/fixture-src",
        "-fdebug-prefix-map=<fixture-dir>=/fixture-src",
        "-fmacro-prefix-map=<fixture-dir>=/fixture-src",
    ]
    assert fields["common_link_flags"] == "-e entry --build-id=none"
    assert fields["path_mapping"] == "<fixture-dir>=/fixture-src"
    assert targets == EXPECTED_TARGETS


def test_architecture_metadata_manifest_and_indexes(architecture_corpus):
    binary, output, processor, language, compiler, address_size, endian = (
        architecture_corpus
    )
    manifest = load_json(output, "manifest.json")
    metadata = load_json(output, "metadata.json")
    functions = load_json(output, "functions.json")
    callgraph = load_json(output, "callgraph.json")

    assert manifest["status"] == "complete"
    assert manifest["input"] == {
        "path": str(binary.resolve()),
        "sha256": sha256_of(binary),
        "size": binary.stat().st_size,
    }
    assert manifest["analysis"]["language_id"] == language
    assert manifest["analysis"]["compiler_id"] == compiler
    assert metadata["architecture"] == processor
    assert metadata["address_size"] == address_size
    assert metadata["endian"] == endian

    assert manifest["counts"] == EXPECTED_COUNTS
    assert metadata["counts"] == EXPECTED_COUNTS
    assert metadata["num_functions"] == len(functions) == len(callgraph) == 5
    assert metadata["num_successful"] == 5
    assert metadata["num_fallback"] == metadata["num_failed"] == 0
    assert metadata["num_skipped"] == 0
    assert metadata["fallback_functions"] == metadata["failed_functions"] == []

    counts = manifest["counts"]
    # Outcomes partition the corpus. Reuse overlaps them and is bounded by it.
    assert counts["discovered"] == (
        counts["successful"] + counts["fallback"] + counts["failed"]
    )
    assert counts["skipped"] <= counts["discovered"]
    assert len(metadata["fallback_functions"]) == counts["fallback"]
    assert len(metadata["failed_functions"]) == counts["failed"]
    reported = {record["decompilation"]["status"] for record in functions}
    assert reported <= {"success", "fallback", "failed", "skipped"}
    for fingerprint in manifest["fingerprints"].values():
        assert (
            build_fingerprint(fingerprint["input"], fingerprint["analysis"])
            == fingerprint
        )

    assert set(manifest["indexes"]) == EXPECTED_INDEXES
    for name, record in manifest["indexes"].items():
        assert set(record) == {"path", "sha256"}
        assert record["path"] == name
        artifact = _contained_path(output, record["path"])
        assert artifact.is_file()
        assert sha256_of(artifact) == record["sha256"]


def test_architecture_function_artifacts_and_assembly(architecture_corpus):
    binary, output, *_ = architecture_corpus
    functions = load_json(output, "functions.json")
    by_name = {function["name"]: function for function in functions}

    assert set(by_name) == EXPECTED_FUNCTIONS
    assert sorted(function["size"] for function in functions) == sorted(
        EXPECTED_FUNCTION_SIZES[binary.name]
    )
    for name in EXPECTED_FUNCTIONS:
        function = by_name[name]
        decompilation = function["decompilation"]
        assert decompilation["status"] == "success"
        assert decompilation["error"] is None
        assert decompilation["reused"] is False
        assert isinstance(decompilation["warnings"], list)
        # These fixtures define no thunks, so the block must be absent for all
        # of them rather than merely falsy.
        assert function["is_thunk"] is False
        assert function["thunk"] is None
        assert function["body_ranges"]
        artifacts = function["artifacts"]
        for path_key, hash_key in (
            ("pseudocode", "pseudocode_sha256"),
            ("assembly", "assembly_sha256"),
            ("sidecar", "sidecar_sha256"),
        ):
            artifact = _contained_path(output, artifacts[path_key])
            assert artifact.is_file()
            assert sha256_of(artifact) == artifacts[hash_key]

        assembly = _contained_path(output, artifacts["assembly"])
        lines = assembly.read_text(encoding="utf-8").splitlines()
        matches = [ASSEMBLY_LINE.fullmatch(line) for line in lines]
        assert lines and all(matches)
        instruction_bytes = sum(
            len(match.group("bytes").split()) for match in matches if match is not None
        )
        body_coverage = sum(
            _address_offset(body_range["end"])
            - _address_offset(body_range["start"])
            + 1
            for body_range in function["body_ranges"]
        )
        assert instruction_bytes == function["size"] == body_coverage

        instructions = sorted(
            (
                _address_offset(match.group("address")),
                len(match.group("bytes").split()),
            )
            for match in matches
            if match is not None
        )
        instruction_index = 0
        for body_range in function["body_ranges"]:
            cursor = _address_offset(body_range["start"])
            end = _address_offset(body_range["end"])
            while cursor <= end:
                address, length = instructions[instruction_index]
                assert address == cursor
                cursor += length
                instruction_index += 1
            assert cursor == end + 1
        assert instruction_index == len(instructions)
        if binary.name == "multiarch_riscv64":
            assert {length for _, length in instructions} == {2, 4}

        sidecar = load_json(output, artifacts["sidecar"])
        expected = json.loads(json.dumps(function))
        expected["artifacts"].pop("sidecar_sha256")
        assert sidecar == expected


def test_architecture_calls_xrefs_and_callgraph(architecture_corpus):
    _, output, *_ = architecture_corpus
    functions = load_json(output, "functions.json")
    callgraph = load_json(output, "callgraph.json")
    xrefs = [
        json.loads(line)
        for line in (output / "xrefs.jsonl").read_text(encoding="utf-8").splitlines()
    ]

    by_address = {function["address"]: function for function in functions}
    assert set(callgraph) == set(by_address)
    assert {
        (function["name"], call["target_name"])
        for function in functions
        for call in function["calls"]
    } == EXPECTED_EDGES

    call_tuples = {
        (
            function["name"],
            call["call_site"],
            call["target_address"],
            call["target_function_address"],
            call["target_name"],
            call["reference_type"],
        )
        for function in functions
        for call in function["calls"]
    }
    xref_call_tuples = {
        (
            reference["function_name"],
            reference["from_address"],
            reference["to_address"],
            reference["target_function_address"],
            reference["target_function_name"],
            reference["reference_type"],
        )
        for reference in xrefs
        if (reference["function_name"], reference["target_function_name"])
        in EXPECTED_EDGES
    }
    assert call_tuples == xref_call_tuples

    for address, function in by_address.items():
        graph_record = callgraph[address]
        assert graph_record == {
            "name": function["name"],
            "address": address,
            "calls": function["calls"],
            "called_by": function["called_by"],
        }
        expected_callers = {
            caller for caller, callee in EXPECTED_EDGES if callee == function["name"]
        }
        assert {caller["name"] for caller in function["called_by"]} == expected_callers
        assert {
            (
                caller["call_site"],
                caller["address"],
                caller["name"],
                caller["reference_type"],
            )
            for caller in function["called_by"]
        } == {
            (
                call["call_site"],
                source["address"],
                source["name"],
                call["reference_type"],
            )
            for source in functions
            for call in source["calls"]
            if call["target_function_address"] == address
        }


def test_architecture_exports_symbols_and_marker(architecture_corpus):
    _, output, *_ = architecture_corpus
    exports = load_json(output, "exports.json")
    symbols = load_json(output, "symbols.json")
    strings = load_json(output, "strings.json")

    assert {item["name"] for item in exports} == EXPECTED_EXPORTS
    assert len(exports) == len(EXPECTED_EXPORTS)
    assert len({item["address"] for item in exports}) == len(exports)
    assert all(item["namespace"] == "Global" for item in exports)
    assert all(item["is_primary"] is True for item in exports)
    named_symbols = {
        item["name"]: item
        for item in symbols
        if item["name"] in {"fixture_marker", "global_state"}
    }
    assert set(named_symbols) == {"fixture_marker", "global_state"}
    assert all(
        item["type"] in {"Label", "Global Variable"} for item in named_symbols.values()
    )
    assert all(item["is_primary"] is True for item in named_symbols.values())
    assert named_symbols["fixture_marker"]["data_type"] == "char *"
    assert named_symbols["global_state"]["data_type"] == "u32"
    marker_strings = [item for item in strings if item["value"] == MARKER]
    assert len(marker_strings) == 1
    assert marker_strings[0]["length"] == len(MARKER) + 1
    assert {
        xref["function"]
        for xref in marker_strings[0]["xrefs"]
        if xref["function"] is not None
    } == {"entry"}


def test_locals_come_from_the_decompiler(architecture_corpus):
    """`Function.getLocalVariables()` reports nothing for these fixtures.

    Every function here uses local variables, so a corpus that reports none is
    describing Ghidra's empty function object rather than the decompiler's own
    model of the code.
    """
    _, output, _, _, _, _, _ = architecture_corpus
    functions = load_json(output, "functions.json")

    with_locals = [
        function for function in functions if function["signature"]["locals"]
    ]
    assert with_locals, "no function reported a single local variable"

    for function in with_locals:
        parameters = {
            parameter["name"] for parameter in function["signature"]["parameters"]
        }
        for local in function["signature"]["locals"]:
            assert local["name"]
            assert local["data_type"] not in (None, "")
            assert local["size"] >= 0
            assert local["storage"]["kind"] in {
                "stack",
                "register",
                "memory",
                "compound",
                "unassigned",
            }
            assert local["name"] not in parameters, "a parameter leaked into locals"


def test_recorded_locals_relate_to_the_pseudocode(architecture_corpus):
    """The recorded locals must be the ones the emitted C actually uses.

    Not every modelled local reaches the output: on MIPS the decompiler models a
    stack slot that it then folds into an expression, so its name never appears.
    The invariant is therefore that the corpus is describing this function's
    code, not that every symbol survives printing.
    """
    _, output, _, _, _, _, _ = architecture_corpus
    functions = load_json(output, "functions.json")

    matched = 0
    for function in functions:
        locals_ = function["signature"]["locals"]
        if not locals_:
            continue
        pseudocode = _contained_path(output, function["artifacts"]["pseudocode"])
        text = pseudocode.read_text(encoding="utf-8")
        matched += sum(1 for local in locals_ if local["name"] in text)

    assert matched, "no recorded local appears anywhere in the pseudocode"


def test_decompiler_warnings_are_traceable_to_the_pseudocode(architecture_corpus):
    _, output, _, _, _, _, _ = architecture_corpus
    functions = load_json(output, "functions.json")

    for function in functions:
        pseudocode = _contained_path(output, function["artifacts"]["pseudocode"])
        collapsed = " ".join(pseudocode.read_text(encoding="utf-8").split())
        for note in function["decompilation"]["warnings"]:
            assert note["kind"] in {"warning", "unresolved_local", "note"}
            assert note["text"]
            assert note["text"] in collapsed
