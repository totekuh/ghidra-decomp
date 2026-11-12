"""End-to-end tests for Ghidra decompiler invocation levers.

Exercises --aggressive (Decompiler Parameter ID analyzer) and --max-payload-mb
on real binaries, asserting both the decompiled output and the manifest reflect
the chosen options. Shared fixtures and helpers come from conftest.
"""

import json

import pytest
from conftest import FIXTURES, _read_pseudocode, _successful_records, run_export


class TestAggressiveParamId:
    """Decompile a real MIPS binary with and without --aggressive, proving the
    Decompiler Parameter ID analyzer recovers better parameter/return types.

    The aggressive run should type parameters that otherwise stay `undefined*`
    (e.g. undefined4 *param -> char **param), reducing the corpus-wide count of
    `undefined` type tokens.
    """

    BINARY = "kazoo"
    LANGUAGE = "MIPS:LE:32:default"
    COMPILER = "default"

    @pytest.fixture(scope="class")
    @classmethod
    def aggressive_pair(cls, tmp_path_factory, ghidra_path):
        binary = FIXTURES / cls.BINARY
        if not binary.is_file():
            pytest.skip(f"fixture {cls.BINARY} not present")
        off_output = tmp_path_factory.mktemp("agg_off")
        on_output = tmp_path_factory.mktemp("agg_on")
        run_export(
            binary,
            off_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--no-polish",
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        run_export(
            binary,
            on_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--no-polish",
            "--aggressive",
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        return off_output, on_output

    def test_aggressive_recovers_types(self, aggressive_pair):
        off_output, on_output = aggressive_pair
        off_records = {r["name"]: r for r in _successful_records(off_output)}
        on_records = {r["name"]: r for r in _successful_records(on_output)}
        common = set(off_records) & set(on_records)
        assert common, "no successfully decompiled functions"

        off_undef = 0
        on_undef = 0
        changed = 0
        for name in common:
            off_code = _read_pseudocode(off_output, off_records[name])
            on_code = _read_pseudocode(on_output, on_records[name])
            off_undef += off_code.count("undefined")
            on_undef += on_code.count("undefined")
            if off_code != on_code:
                changed += 1

        assert changed > 0, (
            "--aggressive changed no function output; Parameter ID analyzer "
            "may not have run"
        )
        assert on_undef < off_undef, (
            f"--aggressive should reduce undefined type tokens "
            f"(off={off_undef}, on={on_undef})"
        )

    def test_aggressive_recorded_in_manifest(self, aggressive_pair):
        _off_output, on_output = aggressive_pair
        manifest = json.loads((on_output / "manifest.json").read_text(encoding="utf-8"))
        assert manifest.get("analysis", {}).get("aggressive") is True, (
            "manifest should record aggressive=True for an --aggressive run"
        )


class TestMaxPayloadLimit:
    """Decompile a binary with a tiny and a default decompiler payload cap,
    proving --max-payload-mb controls how many functions decompile.

    A tiny cap forces large functions to exceed the payload limit and fall
    back (no C output); the default cap decompiles them. Uses the statically
    linked x86_64 C++ fixture, whose libc provides several large functions.
    """

    BINARY = "vtable_x86_64_stripped"
    LANGUAGE = "x86:LE:64:default"
    COMPILER = "gcc"

    @pytest.fixture(scope="class")
    @classmethod
    def payload_pair(cls, tmp_path_factory, ghidra_path):
        binary = FIXTURES / cls.BINARY
        if not binary.is_file():
            pytest.skip(f"fixture {cls.BINARY} not present")
        low_output = tmp_path_factory.mktemp("payload_low")
        default_output = tmp_path_factory.mktemp("payload_default")
        run_export(
            binary,
            low_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--no-polish",
            "--max-payload-mb",
            "1",
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        run_export(
            binary,
            default_output,
            "--language",
            cls.LANGUAGE,
            "--compiler",
            cls.COMPILER,
            "--no-polish",
            "--timeout",
            "60",
            ghidra_path=ghidra_path,
            timeout=600,
        )
        return low_output, default_output

    def test_tiny_cap_loses_functions(self, payload_pair):
        low_output, default_output = payload_pair
        low_success = len(_successful_records(low_output))
        default_success = len(_successful_records(default_output))
        assert low_success < default_success, (
            f"a 1MB payload cap should decompile fewer functions than the "
            f"default (low={low_success}, default={default_success})"
        )

    def test_payload_recorded_in_manifest(self, payload_pair):
        low_output, _default_output = payload_pair
        manifest = json.loads(
            (low_output / "manifest.json").read_text(encoding="utf-8")
        )
        assert manifest.get("analysis", {}).get("max_payload_mb") == 1, (
            "manifest should record the configured payload cap"
        )
