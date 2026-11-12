"""End-to-end test for the --max-payload-mb Ghidra invocation lever.

Exercises --max-payload-mb on a real binary, asserting both the decompiled
output and the manifest reflect the chosen cap. Shared fixtures and helpers
come from conftest.
"""

import json

import pytest
from conftest import FIXTURES, _successful_records, run_export


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
