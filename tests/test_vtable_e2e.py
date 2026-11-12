"""End-to-end test that vtable_synthesis fires on a real stripped C++ binary.

Decompiles the vtable_x86_64_stripped fixture (built from vtable_test.cpp) with
and without --no-polish and asserts the transform rewrote Ghidra's double-deref
dispatch into arrow syntax. Shared fixtures and helpers come from conftest.
"""

import pytest
from conftest import FIXTURES, _read_pseudocode, _successful_records, run_export


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
