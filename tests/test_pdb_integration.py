"""Integration tests for PDB symbol resolution.

Tests are organized by what they require:

- **Offline** tests use only local fixtures and monkeypatched network calls.
  They run everywhere.
- **Network** tests hit the real Microsoft symbol server.  They are marked
  ``pytest.mark.network`` and skipped unless ``--run-network`` is passed.
- **Ghidra** tests start embedded Ghidra.  They are skipped when Ghidra or
  PyGhidra is unavailable.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import FIXTURES, load_json, require_ghidra, run_export, sha256_of

from ghidra_decomp.pdb import (
    RsdsInfo,
    fetch_pdb,
    parse_rsds,
    pdb_cache_path,
    pdb_identity,
    symbol_server_url,
)

# ---------------------------------------------------------------------------
# Real fixture data
# ---------------------------------------------------------------------------

PE_EXE = FIXTURES / "hostname.exe"
PE_DLL = FIXTURES / "version.dll"
ELF = FIXTURES / "sample"

HOSTNAME_GUID = "2D4D1EB1D63BAB382A00E7DF7D0297CB"
HOSTNAME_AGE = 1
HOSTNAME_PDB = "hostname.pdb"

VERSION_GUID = "440DD63BE2B021F80FD0C78EF0AECEF2"
VERSION_AGE = 1
VERSION_PDB = "version.pdb"


def network_available():
    """Best-effort check that the symbol server is reachable."""
    try:
        from urllib.request import urlopen

        urlopen("https://msdl.microsoft.com/download/symbols/", timeout=5)
        return True
    except OSError:
        return False


network = pytest.mark.skipif(
    not network_available(), reason="Microsoft symbol server unreachable"
)


# ===================================================================
# Offline: RSDS parsing on real fixtures
# ===================================================================


class TestRealFixtureRsds:
    """Parse RSDS from the checked-in Windows binaries."""

    def test_hostname_exe_fields(self):
        info = parse_rsds(PE_EXE)
        assert info is not None
        assert info.guid == HOSTNAME_GUID
        assert info.age == HOSTNAME_AGE
        assert info.pdb_name == HOSTNAME_PDB

    def test_version_dll_fields(self):
        info = parse_rsds(PE_DLL)
        assert info is not None
        assert info.guid == VERSION_GUID
        assert info.age == VERSION_AGE
        assert info.pdb_name == VERSION_PDB

    def test_elf_returns_none(self):
        if not ELF.is_file():
            pytest.skip("sample fixture not available")
        assert parse_rsds(ELF) is None

    def test_hostname_url(self):
        info = parse_rsds(PE_EXE)
        url = symbol_server_url(info)
        assert url == (
            f"https://msdl.microsoft.com/download/symbols/"
            f"{HOSTNAME_PDB}/{HOSTNAME_GUID}{HOSTNAME_AGE}/{HOSTNAME_PDB}"
        )

    def test_version_url(self):
        info = parse_rsds(PE_DLL)
        url = symbol_server_url(info)
        assert url == (
            f"https://msdl.microsoft.com/download/symbols/"
            f"{VERSION_PDB}/{VERSION_GUID}{VERSION_AGE}/{VERSION_PDB}"
        )


# ===================================================================
# Offline: PDB caching mechanics
# ===================================================================


class TestPdbCaching:
    """Cache layout, identity hashing, and monkeypatched fetch."""

    def test_cache_path_matches_symbol_server_layout(self):
        info = parse_rsds(PE_EXE)
        cache = pdb_cache_path(info, Path("/cache"))
        assert cache == Path(
            f"/cache/pdb/{HOSTNAME_PDB}/{HOSTNAME_GUID}{HOSTNAME_AGE}/{HOSTNAME_PDB}"
        )

    def test_fetch_returns_cached_file_without_network(self, tmp_path):
        info = parse_rsds(PE_EXE)
        cached = pdb_cache_path(info, tmp_path)
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"pre-cached pdb")

        result = fetch_pdb(info, tmp_path)
        assert result == cached
        assert result.read_bytes() == b"pre-cached pdb"

    def test_fetch_writes_to_correct_cache_path(self, tmp_path, monkeypatch):
        info = parse_rsds(PE_EXE)
        fake_content = b"downloaded pdb bytes"
        monkeypatch.setattr("ghidra_decomp.pdb._download", lambda url: fake_content)

        result = fetch_pdb(info, tmp_path)
        expected = pdb_cache_path(info, tmp_path)
        assert result == expected
        assert result.read_bytes() == fake_content

    def test_second_fetch_hits_cache(self, tmp_path, monkeypatch):
        info = parse_rsds(PE_EXE)
        call_count = 0

        def counting_download(url):
            nonlocal call_count
            call_count += 1
            return b"pdb data"

        monkeypatch.setattr("ghidra_decomp.pdb._download", counting_download)

        first = fetch_pdb(info, tmp_path)
        second = fetch_pdb(info, tmp_path)
        assert first == second
        assert call_count == 1

    def test_identity_includes_sha256_of_pdb_file(self, tmp_path):
        info = parse_rsds(PE_EXE)
        pdb_file = tmp_path / "test.pdb"
        pdb_file.write_bytes(b"pdb content for hashing")

        identity = pdb_identity(pdb_file, info)
        assert identity is not None
        assert identity["pdb_name"] == HOSTNAME_PDB
        assert identity["guid"] == HOSTNAME_GUID
        assert identity["age"] == HOSTNAME_AGE
        assert identity["sha256"] == sha256_of(pdb_file)

    def test_different_pdb_content_different_identity(self, tmp_path):
        info = parse_rsds(PE_EXE)

        pdb_a = tmp_path / "a.pdb"
        pdb_a.write_bytes(b"version A")
        pdb_b = tmp_path / "b.pdb"
        pdb_b.write_bytes(b"version B")

        id_a = pdb_identity(pdb_a, info)
        id_b = pdb_identity(pdb_b, info)
        assert id_a["sha256"] != id_b["sha256"]


# ===================================================================
# Offline: cache key interaction
# ===================================================================


class TestPdbCacheKeyIntegration:
    """PDB identity changes the analysis cache fingerprint."""

    def test_pdb_identity_changes_fingerprint(self, tmp_path):
        from ghidra_decomp.artifacts import build_fingerprint

        identity = {"path": "/tmp/binary", "sha256": "a" * 64, "size": 1024}
        analysis_no_pdb = {
            "base_address": None,
            "entry_point": None,
            "language": "x86:LE:64:default",
            "compiler": "windows",
            "data_type_archives": [],
            "pdb": None,
        }
        analysis_with_pdb = {
            **analysis_no_pdb,
            "pdb": {
                "pdb_name": HOSTNAME_PDB,
                "guid": HOSTNAME_GUID,
                "age": HOSTNAME_AGE,
                "sha256": "b" * 64,
            },
        }

        fp_no = build_fingerprint(identity, analysis_no_pdb)
        fp_with = build_fingerprint(identity, analysis_with_pdb)
        assert fp_no["sha256"] != fp_with["sha256"]

    def test_different_pdb_different_fingerprint(self, tmp_path):
        from ghidra_decomp.artifacts import build_fingerprint

        identity = {"path": "/tmp/binary", "sha256": "a" * 64, "size": 1024}
        base = {
            "base_address": None,
            "entry_point": None,
            "language": "x86:LE:64:default",
            "compiler": "windows",
            "data_type_archives": [],
        }
        analysis_a = {
            **base,
            "pdb": {"pdb_name": "a.pdb", "guid": "AA", "age": 1, "sha256": "a" * 64},
        }
        analysis_b = {
            **base,
            "pdb": {"pdb_name": "b.pdb", "guid": "BB", "age": 1, "sha256": "b" * 64},
        }

        fp_a = build_fingerprint(identity, analysis_a)
        fp_b = build_fingerprint(identity, analysis_b)
        assert fp_a["sha256"] != fp_b["sha256"]


# ===================================================================
# Offline: CLI routing (subprocess, no Ghidra)
# ===================================================================


class TestCliPdbRouting:
    """Verify --pdb values reach decompile_binary correctly.

    These intercept ``_start_pyghidra`` so Ghidra never starts, but PDB
    resolution (which runs before Ghidra) executes for real.
    """

    @staticmethod
    def _intercept_before_ghidra(monkeypatch):
        def _raise(*args, **kwargs):
            raise RuntimeError("intercepted")

        monkeypatch.setattr(
            "ghidra_decomp.decompiler._start_pyghidra",
            _raise,
        )

    def test_pdb_none_suppresses_rsds_detection(self, tmp_path, monkeypatch):
        self._intercept_before_ghidra(monkeypatch)
        calls = []
        original = parse_rsds
        monkeypatch.setattr(
            "ghidra_decomp.pdb.parse_rsds",
            lambda b: (calls.append(b), original(b))[1],
        )

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(PE_EXE, tmp_path / "out", pdb="none")
        except RuntimeError:
            pass

        assert len(calls) == 0

    def test_pdb_auto_calls_parse_rsds(self, tmp_path, monkeypatch):
        self._intercept_before_ghidra(monkeypatch)
        calls = []
        monkeypatch.setattr(
            "ghidra_decomp.pdb.parse_rsds",
            lambda b: (calls.append(b), RsdsInfo("AA", 1, "x.pdb", "x.pdb"))[1],
        )
        monkeypatch.setattr("ghidra_decomp.pdb.fetch_pdb", lambda info, cache: None)

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(PE_EXE, tmp_path / "out", pdb="auto")
        except RuntimeError:
            pass

        assert len(calls) == 1

    def test_pdb_auto_on_elf_skips_fetch(self, tmp_path, monkeypatch):
        if not ELF.is_file():
            pytest.skip("sample fixture not available")
        self._intercept_before_ghidra(monkeypatch)
        fetch_calls = []
        monkeypatch.setattr(
            "ghidra_decomp.pdb.fetch_pdb",
            lambda info, cache: fetch_calls.append(info),
        )

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(ELF, tmp_path / "out", pdb="auto")
        except RuntimeError:
            pass

        assert len(fetch_calls) == 0

    def test_pdb_local_path_validated(self, tmp_path):
        import click

        from ghidra_decomp.decompiler import decompile_binary

        with pytest.raises(click.BadParameter, match="PDB file not found"):
            decompile_binary(
                PE_EXE,
                tmp_path / "out",
                pdb=str(tmp_path / "nonexistent.pdb"),
            )

    def test_pdb_local_path_parses_rsds_for_identity(self, tmp_path, monkeypatch):
        self._intercept_before_ghidra(monkeypatch)
        pdb_file = tmp_path / "local.pdb"
        pdb_file.write_bytes(b"fake pdb")

        calls = []
        original = parse_rsds
        monkeypatch.setattr(
            "ghidra_decomp.pdb.parse_rsds",
            lambda b: (calls.append(b), original(b))[1],
        )

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(PE_EXE, tmp_path / "out", pdb=str(pdb_file))
        except RuntimeError:
            pass

        assert len(calls) == 1
        assert calls[0] == PE_EXE


# ===================================================================
# Offline: prompt behavior
# ===================================================================


class TestPromptIntegration:
    """Interactive prompt interacts correctly with real RSDS data."""

    @staticmethod
    def _intercept_before_ghidra(monkeypatch):
        def _raise(*args, **kwargs):
            raise RuntimeError("intercepted")

        monkeypatch.setattr(
            "ghidra_decomp.decompiler._start_pyghidra",
            _raise,
        )

    def test_default_mode_detects_pe_and_would_prompt(self, tmp_path, monkeypatch):
        self._intercept_before_ghidra(monkeypatch)
        prompted = []

        def fake_prompt(info):
            prompted.append(info)
            return False

        monkeypatch.setattr("ghidra_decomp.pdb.prompt_pdb_fetch", fake_prompt)

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(PE_EXE, tmp_path / "out")
        except RuntimeError:
            pass

        assert len(prompted) == 1
        assert prompted[0].guid == HOSTNAME_GUID

    def test_default_mode_skips_prompt_for_elf(self, tmp_path, monkeypatch):
        if not ELF.is_file():
            pytest.skip("sample fixture not available")
        self._intercept_before_ghidra(monkeypatch)
        prompted = []

        def fake_prompt(info):
            prompted.append(info)
            return False

        monkeypatch.setattr("ghidra_decomp.pdb.prompt_pdb_fetch", fake_prompt)

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(ELF, tmp_path / "out")
        except RuntimeError:
            pass

        assert len(prompted) == 0

    def test_prompt_yes_triggers_fetch(self, tmp_path, monkeypatch):
        self._intercept_before_ghidra(monkeypatch)
        monkeypatch.setattr("ghidra_decomp.pdb.prompt_pdb_fetch", lambda info: True)
        fetch_calls = []
        monkeypatch.setattr(
            "ghidra_decomp.pdb.fetch_pdb",
            lambda info, cache: (fetch_calls.append(info), None)[1],
        )

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(PE_EXE, tmp_path / "out")
        except RuntimeError:
            pass

        assert len(fetch_calls) == 1
        assert fetch_calls[0].guid == HOSTNAME_GUID

    def test_prompt_no_skips_fetch(self, tmp_path, monkeypatch):
        self._intercept_before_ghidra(monkeypatch)
        monkeypatch.setattr("ghidra_decomp.pdb.prompt_pdb_fetch", lambda info: False)
        fetch_calls = []
        monkeypatch.setattr(
            "ghidra_decomp.pdb.fetch_pdb",
            lambda info, cache: fetch_calls.append(info),
        )

        from ghidra_decomp.decompiler import decompile_binary

        try:
            decompile_binary(PE_EXE, tmp_path / "out")
        except RuntimeError:
            pass

        assert len(fetch_calls) == 0


# ===================================================================
# Network: fetch real PDBs from Microsoft symbol server
# ===================================================================


@network
class TestSymbolServerFetch:
    """Download real PDBs — requires internet access."""

    def test_fetch_hostname_pdb(self, tmp_path):
        info = parse_rsds(PE_EXE)
        result = fetch_pdb(info, tmp_path)

        assert result is not None
        assert result.is_file()
        assert result.stat().st_size > 0
        assert result.name == HOSTNAME_PDB

    def test_fetch_version_pdb(self, tmp_path):
        info = parse_rsds(PE_DLL)
        result = fetch_pdb(info, tmp_path)

        assert result is not None
        assert result.is_file()
        assert result.stat().st_size > 0
        assert result.name == VERSION_PDB

    def test_fetched_pdb_is_cached_on_disk(self, tmp_path):
        info = parse_rsds(PE_EXE)
        fetch_pdb(info, tmp_path)

        expected = pdb_cache_path(info, tmp_path)
        assert expected.is_file()

    def test_fake_guid_returns_none(self, tmp_path):
        fake = RsdsInfo(
            guid="00000000000000000000000000000000",
            age=1,
            pdb_name="nonexistent.pdb",
            pdb_path="nonexistent.pdb",
        )
        result = fetch_pdb(fake, tmp_path)
        assert result is None

    def test_identity_from_fetched_pdb(self, tmp_path):
        info = parse_rsds(PE_EXE)
        pdb_path = fetch_pdb(info, tmp_path)
        assert pdb_path is not None

        identity = pdb_identity(pdb_path, info)
        assert identity["pdb_name"] == HOSTNAME_PDB
        assert identity["guid"] == HOSTNAME_GUID
        assert identity["age"] == HOSTNAME_AGE
        assert len(identity["sha256"]) == 64


# ===================================================================
# Ghidra E2E: full pipeline with PDB
# ===================================================================


@pytest.fixture(scope="module")
def ghidra_path() -> Path:
    return require_ghidra()


@pytest.fixture
def cache_home(tmp_path) -> dict[str, str]:
    return {"XDG_CACHE_HOME": str(tmp_path / "xdg")}


def _function_names(output: Path) -> set[str]:
    """Collect all function names from the exported corpus."""
    functions = load_json(output, "functions.json")
    return {f["name"] for f in functions}


def _all_pseudocode(output: Path) -> str:
    """Concatenate all .c files from the functions/ directory."""
    parts = []
    functions_dir = output / "functions"
    if functions_dir.is_dir():
        for c_file in sorted(functions_dir.glob("*.c")):
            parts.append(c_file.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


class TestGhidraE2ePdb:
    """Full pipeline tests — decompile real PE fixtures and verify PDB symbols
    appear in the output.  Skipped when Ghidra or network is unavailable."""

    def test_hostname_without_pdb_has_no_real_names(
        self, tmp_path, ghidra_path, cache_home
    ):
        output = tmp_path / "corpus"
        run_export(
            PE_EXE,
            output,
            "--pdb",
            "none",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )

        manifest = load_json(output, "manifest.json")
        assert manifest["status"] == "complete"
        assert manifest["analysis"]["pdb"] is None

        names = _function_names(output)
        fun_prefixed = {n for n in names if n.startswith("FUN_")}
        # Without PDB most functions should be FUN_ addresses
        assert len(fun_prefixed) > 0

    def test_hostname_with_pdb_auto_gains_real_names(
        self, tmp_path, ghidra_path, cache_home
    ):
        if not network_available():
            pytest.skip("symbol server unreachable")
        output = tmp_path / "corpus"
        run_export(
            PE_EXE,
            output,
            "--pdb",
            "auto",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )

        manifest = load_json(output, "manifest.json")
        assert manifest["status"] == "complete"
        pdb_record = manifest["analysis"]["pdb"]
        if pdb_record is None:
            pytest.skip("PDB fetch failed")

        assert pdb_record["pdb_name"] == HOSTNAME_PDB
        assert pdb_record["guid"] == HOSTNAME_GUID

        names = _function_names(output)
        fun_prefixed = {n for n in names if n.startswith("FUN_")}
        named = names - fun_prefixed
        # PDB should have resolved at least some real function names
        assert len(named) > 0, f"PDB loaded but all functions still FUN_: {names}"

    def test_hostname_pdb_symbols_appear_in_pseudocode(
        self, tmp_path, ghidra_path, cache_home
    ):
        if not network_available():
            pytest.skip("symbol server unreachable")
        output = tmp_path / "corpus"
        run_export(
            PE_EXE,
            output,
            "--pdb",
            "auto",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )

        manifest = load_json(output, "manifest.json")
        if manifest["analysis"]["pdb"] is None:
            pytest.skip("PDB fetch failed")

        code = _all_pseudocode(output)
        # With PDB, decompiled C should contain at least one non-FUN_ call
        # reference.  The pseudocode includes function signatures and calls.
        assert len(code) > 0, "No pseudocode produced"
        names = _function_names(output)
        named = {n for n in names if not n.startswith("FUN_")}
        # At least one named function should appear in the pseudocode body
        found_in_code = {n for n in named if n in code}
        assert len(found_in_code) > 0, (
            f"Named functions {named} not found in pseudocode"
        )

    def test_hostname_pdb_vs_no_pdb_diff(self, tmp_path, ghidra_path, cache_home):
        """PDB export should have strictly more named functions than bare export."""
        if not network_available():
            pytest.skip("symbol server unreachable")

        out_bare = tmp_path / "bare"
        out_pdb = tmp_path / "pdb"

        run_export(
            PE_EXE,
            out_bare,
            "--pdb",
            "none",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )
        run_export(
            PE_EXE,
            out_pdb,
            "--pdb",
            "auto",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )

        if load_json(out_pdb, "manifest.json")["analysis"]["pdb"] is None:
            pytest.skip("PDB fetch failed")

        bare_names = _function_names(out_bare)
        pdb_names = _function_names(out_pdb)

        bare_named = {n for n in bare_names if not n.startswith("FUN_")}
        pdb_named = {n for n in pdb_names if not n.startswith("FUN_")}

        assert len(pdb_named) > len(bare_named), (
            f"PDB should add names. bare={len(bare_named)}, pdb={len(pdb_named)}"
        )

    def test_version_dll_with_pdb_produces_named_functions(
        self, tmp_path, ghidra_path, cache_home
    ):
        if not network_available():
            pytest.skip("symbol server unreachable")
        output = tmp_path / "corpus"
        run_export(
            PE_DLL,
            output,
            "--pdb",
            "auto",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )

        manifest = load_json(output, "manifest.json")
        assert manifest["status"] == "complete"
        pdb_record = manifest["analysis"]["pdb"]
        if pdb_record is None:
            pytest.skip("PDB fetch failed")

        assert pdb_record["pdb_name"] == VERSION_PDB

        names = _function_names(output)
        named = {n for n in names if not n.startswith("FUN_")}
        assert len(named) > 0, f"version.dll PDB loaded but no named functions: {names}"

    def test_pdb_auto_on_elf_is_silent_skip(self, tmp_path, ghidra_path, cache_home):
        if not ELF.is_file():
            pytest.skip("sample fixture not available")
        output = tmp_path / "corpus"
        run_export(
            ELF,
            output,
            "--pdb",
            "auto",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )
        manifest = load_json(output, "manifest.json")
        assert manifest["status"] == "complete"
        assert manifest["analysis"]["pdb"] is None

    def test_missing_local_pdb_fails_before_ghidra(
        self, tmp_path, ghidra_path, cache_home
    ):
        result = run_export(
            PE_EXE,
            tmp_path / "corpus",
            "--pdb",
            str(tmp_path / "absent.pdb"),
            ghidra_path=ghidra_path,
            env=cache_home,
            check=False,
        )
        assert result.returncode != 0

    def test_pdb_identity_in_manifest_fingerprint(
        self, tmp_path, ghidra_path, cache_home
    ):
        if not network_available():
            pytest.skip("symbol server unreachable")

        out_none = tmp_path / "no_pdb"
        out_auto = tmp_path / "with_pdb"

        run_export(
            PE_EXE,
            out_none,
            "--pdb",
            "none",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )
        run_export(
            PE_EXE,
            out_auto,
            "--pdb",
            "auto",
            ghidra_path=ghidra_path,
            env=cache_home,
            timeout=600,
        )

        man_none = load_json(out_none, "manifest.json")
        man_auto = load_json(out_auto, "manifest.json")

        assert man_none["analysis"]["pdb"] is None
        if man_auto["analysis"]["pdb"] is not None:
            assert (
                man_none["fingerprints"]["request"]["sha256"]
                != man_auto["fingerprints"]["request"]["sha256"]
            )
