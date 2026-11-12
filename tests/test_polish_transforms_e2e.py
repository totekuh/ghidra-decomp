"""End-to-end tests that each polish transform fires on a real binary.

Decompiles a real cross-compiled fixture with and without --no-polish and
asserts the specific transform changed the output. Shared fixtures and helpers
(ghidra_path, _read_pseudocode, _successful_records) come from conftest.
"""

import pytest
from conftest import FIXTURES, _read_pseudocode, _successful_records, run_export


class TestReturnSimplifyRealBinary:
    """Decompile a real stripped MIPS binary where Ghidra emits the
    if (cond) { return 1; } return 0; pattern, proving return_simplify
    fires on genuine decompiler output."""

    BINARY = "kazoo"
    LANGUAGE = "MIPS:LE:32:default"
    COMPILER = "default"

    @pytest.fixture(scope="class")
    @classmethod
    def return_simplify_pair(cls, tmp_path_factory, ghidra_path):
        binary = FIXTURES / cls.BINARY
        if not binary.is_file():
            pytest.skip(f"fixture {cls.BINARY} not present")
        pol_output = tmp_path_factory.mktemp("retsimpl_polished")
        raw_output = tmp_path_factory.mktemp("retsimpl_raw")
        run_export(
            binary,
            pol_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        run_export(
            binary,
            raw_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            "--no-polish",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        return pol_output, raw_output

    def test_return_simplify_fires(self, return_simplify_pair):
        """At least one function has 'if (...) { return 1; } return 0;' in raw
        that becomes 'return <cond>;' in polished."""
        pol_output, raw_output = return_simplify_pair
        raw_records = {r["name"]: r for r in _successful_records(raw_output)}
        pol_records = {r["name"]: r for r in _successful_records(pol_output)}
        common = set(raw_records) & set(pol_records)
        assert common, "no successfully decompiled functions"

        simplified = []
        for name in common:
            raw_code = _read_pseudocode(raw_output, raw_records[name])
            pol_code = _read_pseudocode(pol_output, pol_records[name])
            raw_has_pattern = "return 1;" in raw_code and "return 0;" in raw_code
            pol_lost_pattern = (
                raw_has_pattern
                and raw_code != pol_code
                and (
                    raw_code.count("return 1;") > pol_code.count("return 1;")
                    or raw_code.count("return 0;") > pol_code.count("return 0;")
                )
            )
            if pol_lost_pattern:
                simplified.append(name)

        assert simplified, (
            "return_simplify did not fire on any function in the real binary"
        )


class TestGotoReduceRealBinary:
    """Decompile a real MIPS binary where Ghidra emits same-block forward
    if-goto patterns, proving goto_reduce inverts them on genuine output.

    Reuses the shared loop_normalize fixture; one of its functions has
    invertible if-goto patterns.
    """

    BINARY = "noodle"
    LANGUAGE = "MIPS:LE:32:default"
    COMPILER = "default"

    @pytest.fixture(scope="class")
    @classmethod
    def goto_pair(cls, tmp_path_factory, ghidra_path):
        binary = FIXTURES / cls.BINARY
        if not binary.is_file():
            pytest.skip(f"fixture {cls.BINARY} not present")
        pol_output = tmp_path_factory.mktemp("goto_polished")
        raw_output = tmp_path_factory.mktemp("goto_raw")
        run_export(
            binary,
            pol_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        run_export(
            binary,
            raw_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            "--no-polish",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        return pol_output, raw_output

    def test_goto_reduce_fires(self, goto_pair):
        """At least one function has fewer gotos in polished output than raw,
        proving goto_reduce inverted a same-block if-goto."""
        pol_output, raw_output = goto_pair
        raw_records = {r["name"]: r for r in _successful_records(raw_output)}
        pol_records = {r["name"]: r for r in _successful_records(pol_output)}
        common = set(raw_records) & set(pol_records)
        assert common, "no successfully decompiled functions"

        reduced = []
        for name in common:
            raw_code = _read_pseudocode(raw_output, raw_records[name])
            pol_code = _read_pseudocode(pol_output, pol_records[name])
            if raw_code.count("goto ") > pol_code.count("goto "):
                reduced.append(name)

        assert reduced, "goto_reduce did not remove any goto in the real binary"


class TestLoopNormalizeRealBinary:
    """Decompile a real MIPS executable where Ghidra emits while loops with
    init/condition/increment pattern, proving loop_normalize converts them
    to for loops on genuine decompiler output."""

    BINARY = "noodle"
    LANGUAGE = "MIPS:LE:32:default"
    COMPILER = "default"

    @pytest.fixture(scope="class")
    @classmethod
    def loop_normalize_pair(cls, tmp_path_factory, ghidra_path):
        binary = FIXTURES / cls.BINARY
        if not binary.is_file():
            pytest.skip(f"fixture {cls.BINARY} not present")
        pol_output = tmp_path_factory.mktemp("loopnorm_polished")
        raw_output = tmp_path_factory.mktemp("loopnorm_raw")
        run_export(
            binary,
            pol_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        run_export(
            binary,
            raw_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            "--no-polish",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        return pol_output, raw_output

    def test_while_to_for_fires(self, loop_normalize_pair):
        """At least one function has a while loop in raw that becomes a for
        loop in polished."""
        pol_output, raw_output = loop_normalize_pair
        raw_records = {r["name"]: r for r in _successful_records(raw_output)}
        pol_records = {r["name"]: r for r in _successful_records(pol_output)}
        common = set(raw_records) & set(pol_records)
        assert common, "no successfully decompiled functions"

        converted = []
        for name in common:
            raw_code = _read_pseudocode(raw_output, raw_records[name])
            pol_code = _read_pseudocode(pol_output, pol_records[name])
            if (
                "while" in raw_code
                and "for (" in pol_code
                and (
                    "for (" not in raw_code
                    or pol_code.count("for (") > raw_code.count("for (")
                )
            ):
                converted.append(name)

        assert converted, (
            "loop_normalize did not convert any while loop to for in the real binary"
        )


class TestVtableSynthesisRealBinary:
    """Decompile a stripped C++ binary where Ghidra emits double-deref vtable
    dispatch, proving vtable_synthesis fires on genuine output."""

    BINARY = "vtable_x86_64_stripped"
    LANGUAGE = "x86:LE:64:default"
    COMPILER = "gcc"

    @pytest.fixture(scope="class")
    @classmethod
    def vtable_pair(cls, tmp_path_factory, ghidra_path):
        binary = FIXTURES / cls.BINARY
        if not binary.is_file():
            pytest.skip(f"fixture {cls.BINARY} not present")
        pol_output = tmp_path_factory.mktemp("vtable_polished")
        raw_output = tmp_path_factory.mktemp("vtable_raw")
        run_export(
            binary,
            pol_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        run_export(
            binary,
            raw_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--timeout",
            "60",
            "--no-polish",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        return pol_output, raw_output

    def test_vtable_synthesis_fires(self, vtable_pair):
        """At least one function has vtable arrow syntax in polished output
        where raw had double-deref code** casts."""
        pol_output, raw_output = vtable_pair
        raw_records = {r["name"]: r for r in _successful_records(raw_output)}
        pol_records = {r["name"]: r for r in _successful_records(pol_output)}
        common = set(raw_records) & set(pol_records)
        assert common, "no successfully decompiled functions"

        synthesized = []
        for name in common:
            pol_code = _read_pseudocode(pol_output, pol_records[name])
            if "->_vtable->vfunc_0x" in pol_code:
                synthesized.append(name)

        assert synthesized, (
            "vtable_synthesis did not fire on any function in the stripped C++ binary"
        )
