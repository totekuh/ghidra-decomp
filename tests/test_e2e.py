"""End-to-end tests for ghidra-decomp.

Runs the full decompilation pipeline against tests/fixtures/sample
and validates the output structure and content.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SAMPLE_BIN = FIXTURES / "sample"

# Known functions compiled into the test binary
KNOWN_FUNCTIONS = {"add", "multiply", "compute", "print_banner", "make_point", "sum_array", "factorial", "main"}


@pytest.fixture(scope="module")
def decomp_output(tmp_path_factory):
    """Run ghidra-decomp once and return the output directory."""
    out = tmp_path_factory.mktemp("decomp_output")
    result = subprocess.run(
        [sys.executable, "-m", "ghidra_decomp.cli", str(SAMPLE_BIN), "-o", str(out)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, f"ghidra-decomp failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return out


@pytest.fixture(scope="module")
def decomp_output_rebased(tmp_path_factory):
    """Run ghidra-decomp with --base-addr and return the output directory."""
    out = tmp_path_factory.mktemp("decomp_rebased")
    result = subprocess.run(
        [sys.executable, "-m", "ghidra_decomp.cli", str(SAMPLE_BIN), "-o", str(out), "--base-addr", "0xdead0000"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, f"ghidra-decomp (rebased) failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
    return out, result.stdout


# ---- Output structure tests ----

class TestOutputStructure:
    def test_functions_dir_exists(self, decomp_output):
        assert (decomp_output / "functions").is_dir()

    def test_functions_dir_not_empty(self, decomp_output):
        c_files = list((decomp_output / "functions").glob("*.c"))
        assert len(c_files) > 0

    def test_all_functions_file(self, decomp_output):
        assert (decomp_output / "all_functions.c").is_file()
        content = (decomp_output / "all_functions.c").read_text()
        assert len(content) > 0

    def test_types_header(self, decomp_output):
        assert (decomp_output / "types.h").is_file()

    @pytest.mark.parametrize("name", [
        "functions.json", "callgraph.json", "strings.json", "imports.json",
        "exports.json", "symbols.json", "sections.json", "metadata.json",
    ])
    def test_json_files_exist_and_valid(self, decomp_output, name):
        path = decomp_output / name
        assert path.is_file()
        data = json.loads(path.read_text())
        assert data is not None


# ---- Function decompilation tests ----

class TestFunctions:
    def test_known_functions_have_files(self, decomp_output):
        func_dir = decomp_output / "functions"
        all_filenames = {f.name for f in func_dir.glob("*.c")}
        for func_name in KNOWN_FUNCTIONS:
            matches = [f for f in all_filenames if func_name in f]
            assert matches, f"No .c file found for function '{func_name}'"

    def test_function_files_have_header_comments(self, decomp_output):
        func_dir = decomp_output / "functions"
        for c_file in func_dir.glob("*.c"):
            content = c_file.read_text()
            assert "// Function:" in content
            assert "// Address:" in content

    def test_all_functions_contains_known(self, decomp_output):
        content = (decomp_output / "all_functions.c").read_text()
        for func_name in KNOWN_FUNCTIONS:
            assert func_name in content, f"'{func_name}' not found in all_functions.c"

    def test_functions_json_has_known(self, decomp_output):
        funcs = json.loads((decomp_output / "functions.json").read_text())
        names = {f["name"] for f in funcs}
        for func_name in KNOWN_FUNCTIONS:
            assert func_name in names, f"'{func_name}' not in functions.json"

    def test_functions_json_has_address_ranges(self, decomp_output):
        funcs = json.loads((decomp_output / "functions.json").read_text())
        for f in funcs:
            assert "address" in f
            assert "end_address" in f
            assert "size" in f
            assert f["size"] > 0


# ---- Call graph tests ----

class TestCallGraph:
    def test_call_graph_has_entries(self, decomp_output):
        cg = json.loads((decomp_output / "callgraph.json").read_text())
        assert len(cg) > 0

    def test_compute_calls_add_and_multiply(self, decomp_output):
        cg = json.loads((decomp_output / "callgraph.json").read_text())
        # Find the compute entry
        compute_entry = None
        for addr, entry in cg.items():
            if entry["name"] == "compute":
                compute_entry = entry
                break
        assert compute_entry is not None, "compute not found in callgraph"
        called_names = {c["name"] for c in compute_entry["calls"]}
        assert "add" in called_names
        assert "multiply" in called_names

    def test_add_called_by_compute(self, decomp_output):
        cg = json.loads((decomp_output / "callgraph.json").read_text())
        add_entry = None
        for addr, entry in cg.items():
            if entry["name"] == "add":
                add_entry = entry
                break
        assert add_entry is not None
        caller_names = {c["name"] for c in add_entry["called_by"]}
        assert "compute" in caller_names


# ---- Strings tests ----

class TestStrings:
    def test_strings_extracted(self, decomp_output):
        strings = json.loads((decomp_output / "strings.json").read_text())
        assert len(strings) > 0

    def test_known_strings_present(self, decomp_output):
        strings = json.loads((decomp_output / "strings.json").read_text())
        values = {s["value"] for s in strings}
        # At least some of our format strings or globals should show up
        assert any("ghidra-decomp" in v for v in values), f"Banner string not found. Got: {values}"


# ---- Imports tests ----

class TestImports:
    def test_imports_extracted(self, decomp_output):
        imports = json.loads((decomp_output / "imports.json").read_text())
        assert len(imports) > 0

    def test_known_imports(self, decomp_output):
        imports = json.loads((decomp_output / "imports.json").read_text())
        names = {i["name"] for i in imports}
        assert "printf" in names
        assert "strncpy" in names


# ---- Exports tests ----

class TestExports:
    def test_exports_extracted(self, decomp_output):
        exports = json.loads((decomp_output / "exports.json").read_text())
        assert len(exports) > 0

    def test_main_is_exported(self, decomp_output):
        exports = json.loads((decomp_output / "exports.json").read_text())
        names = {e["name"] for e in exports}
        assert "main" in names


# ---- Symbols tests ----

class TestSymbols:
    def test_symbols_extracted(self, decomp_output):
        symbols = json.loads((decomp_output / "symbols.json").read_text())
        assert len(symbols) > 0


# ---- Sections tests ----

class TestSections:
    def test_sections_extracted(self, decomp_output):
        sections = json.loads((decomp_output / "sections.json").read_text())
        assert len(sections) > 0

    def test_text_section_executable(self, decomp_output):
        sections = json.loads((decomp_output / "sections.json").read_text())
        text = [s for s in sections if s["name"] == ".text"]
        assert text, ".text section not found"
        assert text[0]["executable"] is True


# ---- Metadata tests ----

class TestMetadata:
    def test_metadata_fields(self, decomp_output):
        meta = json.loads((decomp_output / "metadata.json").read_text())
        assert "binary" in meta
        assert "format" in meta
        assert "architecture" in meta
        assert "endian" in meta
        assert "address_size" in meta
        assert "image_base" in meta
        assert "num_functions" in meta
        assert meta["num_functions"] > 0

    def test_architecture_x86(self, decomp_output):
        meta = json.loads((decomp_output / "metadata.json").read_text())
        assert "x86" in meta["architecture"].lower() or "x86" in meta["architecture"]

    def test_endianness(self, decomp_output):
        meta = json.loads((decomp_output / "metadata.json").read_text())
        assert meta["endian"] == "little"


# ---- Rebase tests ----

class TestRebase:
    def test_rebase_logged(self, decomp_output_rebased):
        _, stdout = decomp_output_rebased
        assert "0xdead0000" in stdout or "dead0000" in stdout

    def test_rebase_metadata(self, decomp_output_rebased):
        out, _ = decomp_output_rebased
        meta = json.loads((out / "metadata.json").read_text())
        assert "dead0000" in meta["image_base"]

    def test_rebased_addresses_differ(self, decomp_output, decomp_output_rebased):
        out_rebased, _ = decomp_output_rebased
        meta_default = json.loads((decomp_output / "metadata.json").read_text())
        meta_rebased = json.loads((out_rebased / "metadata.json").read_text())
        assert meta_default["image_base"] != meta_rebased["image_base"]

    def test_rebased_functions_have_new_addresses(self, decomp_output, decomp_output_rebased):
        out_rebased, _ = decomp_output_rebased
        cg_default = json.loads((decomp_output / "callgraph.json").read_text())
        cg_rebased = json.loads((out_rebased / "callgraph.json").read_text())
        default_addrs = set(cg_default.keys())
        rebased_addrs = set(cg_rebased.keys())
        assert default_addrs != rebased_addrs, "Rebased addresses should differ from defaults"
