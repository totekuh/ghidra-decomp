"""Tests for PE/PDB symbol resolution."""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from ghidra_decomp.pdb import (
    RsdsInfo,
    fetch_pdb,
    parse_rsds,
    pdb_cache_path,
    pdb_identity,
    prompt_pdb_fetch,
    symbol_server_url,
)

FIXTURES = Path(__file__).parent / "fixtures"

# Known values from the hand-crafted PE fixture built by _build_pe_rsds_fixture.
FIXTURE_GUID = "41414141414141414141414141414141"
FIXTURE_AGE = 1
FIXTURE_PDB_NAME = "test.pdb"


# ---------------------------------------------------------------------------
# Minimal PE fixture builder
# ---------------------------------------------------------------------------


def _build_pe_rsds_fixture(path: Path, *, pe32_plus: bool = True) -> None:
    """Write a minimal PE binary with an RSDS CodeView debug record."""
    buf = bytearray(0x300)

    # DOS header
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)  # PE offset

    # PE signature
    buf[0x80:0x84] = b"PE\x00\x00"

    # COFF header
    coff = 0x84
    struct.pack_into("<H", buf, coff, 0x8664 if pe32_plus else 0x14C)  # Machine
    struct.pack_into("<H", buf, coff + 2, 1)  # NumberOfSections
    if pe32_plus:
        opt_size = 112 + 8 * 7  # base optional header + 7 data directories
    else:
        opt_size = 96 + 8 * 7
    struct.pack_into("<H", buf, coff + 16, opt_size)  # SizeOfOptionalHeader
    struct.pack_into("<H", buf, coff + 18, 0x22)  # Characteristics

    # Optional header
    opt = coff + 20
    if pe32_plus:
        struct.pack_into("<H", buf, opt, 0x20B)  # Magic PE32+
        dd_base = opt + 112
    else:
        struct.pack_into("<H", buf, opt, 0x10B)  # Magic PE32
        dd_base = opt + 96
    struct.pack_into("<I", buf, opt + (108 if pe32_plus else 92), 7)  # NumberOfRvaAndSizes

    # Data directory[6] = debug directory
    debug_rva = 0x200
    debug_size = 28  # one entry
    struct.pack_into("<I", buf, dd_base + 6 * 8, debug_rva)
    struct.pack_into("<I", buf, dd_base + 6 * 8 + 4, debug_size)

    # Section header (.text) — maps RVA 0x200 to file offset 0x200
    sec = opt + opt_size
    buf[sec : sec + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", buf, sec + 8, 0x100)  # VirtualSize
    struct.pack_into("<I", buf, sec + 12, 0x200)  # VirtualAddress
    struct.pack_into("<I", buf, sec + 16, 0x100)  # SizeOfRawData
    struct.pack_into("<I", buf, sec + 20, 0x200)  # PointerToRawData
    struct.pack_into("<I", buf, sec + 36, 0x60000020)  # Characteristics

    # Debug directory entry at file offset 0x200
    dde = 0x200
    struct.pack_into("<I", buf, dde + 12, 2)  # Type = IMAGE_DEBUG_TYPE_CODEVIEW
    pdb_filename = b"test.pdb\x00"
    cv_size = 4 + 16 + 4 + len(pdb_filename)  # RSDS + GUID + age + name
    struct.pack_into("<I", buf, dde + 16, cv_size)  # SizeOfData
    struct.pack_into("<I", buf, dde + 20, 0x220)  # AddressOfRawData (RVA)
    struct.pack_into("<I", buf, dde + 24, 0x220)  # PointerToRawData

    # CodeView RSDS record at file offset 0x220
    cv = 0x220
    buf[cv : cv + 4] = b"RSDS"
    buf[cv + 4 : cv + 20] = b"\x41" * 16  # GUID (all 0x41 = 'A')
    struct.pack_into("<I", buf, cv + 20, 1)  # Age
    buf[cv + 24 : cv + 24 + len(pdb_filename)] = pdb_filename

    path.write_bytes(bytes(buf))


def _build_pe_no_debug(path: Path) -> None:
    """Write a minimal PE binary with no debug directory."""
    buf = bytearray(0x200)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x80)
    buf[0x80:0x84] = b"PE\x00\x00"
    coff = 0x84
    struct.pack_into("<H", buf, coff, 0x8664)
    struct.pack_into("<H", buf, coff + 2, 1)
    opt_size = 112 + 8 * 7
    struct.pack_into("<H", buf, coff + 16, opt_size)
    opt = coff + 20
    struct.pack_into("<H", buf, opt, 0x20B)
    struct.pack_into("<I", buf, opt + 108, 7)
    # Data directory[6] left as zero — no debug directory.
    path.write_bytes(bytes(buf))


# ---------------------------------------------------------------------------
# parse_rsds
# ---------------------------------------------------------------------------


class TestParseRsds:
    def test_extracts_guid_age_and_name(self, tmp_path):
        pe = tmp_path / "test.dll"
        _build_pe_rsds_fixture(pe)
        info = parse_rsds(pe)

        assert info is not None
        assert info.guid == FIXTURE_GUID
        assert info.age == FIXTURE_AGE
        assert info.pdb_name == FIXTURE_PDB_NAME
        assert info.pdb_path == FIXTURE_PDB_NAME

    def test_pe32_variant(self, tmp_path):
        pe = tmp_path / "test32.dll"
        _build_pe_rsds_fixture(pe, pe32_plus=False)
        info = parse_rsds(pe)

        assert info is not None
        assert info.guid == FIXTURE_GUID
        assert info.age == FIXTURE_AGE
        assert info.pdb_name == FIXTURE_PDB_NAME

    def test_returns_none_for_non_pe(self):
        elf = FIXTURES / "sample"
        if not elf.is_file():
            pytest.skip("sample fixture not available")
        assert parse_rsds(elf) is None

    def test_returns_none_for_pe_without_debug_directory(self, tmp_path):
        pe = tmp_path / "nodebug.dll"
        _build_pe_no_debug(pe)
        assert parse_rsds(pe) is None

    def test_returns_none_for_empty_file(self, tmp_path):
        empty = tmp_path / "empty"
        empty.write_bytes(b"")
        assert parse_rsds(empty) is None

    def test_returns_none_for_truncated_pe(self, tmp_path):
        truncated = tmp_path / "truncated.exe"
        truncated.write_bytes(b"MZ" + b"\x00" * 10)
        assert parse_rsds(truncated) is None

    def test_returns_none_for_nonexistent_file(self, tmp_path):
        assert parse_rsds(tmp_path / "missing.dll") is None

    def test_skips_non_codeview_debug_entries(self, tmp_path):
        pe = tmp_path / "non_cv.dll"
        _build_pe_rsds_fixture(pe)
        data = bytearray(pe.read_bytes())
        # Change debug entry type from 2 (CODEVIEW) to 13 (POGO)
        struct.pack_into("<I", data, 0x200 + 12, 13)
        pe.write_bytes(bytes(data))
        assert parse_rsds(pe) is None

    def test_on_real_exe(self):
        exe = FIXTURES / "hostname.exe"
        if not exe.is_file():
            pytest.skip("hostname.exe fixture not available")
        info = parse_rsds(exe)
        assert info is not None
        assert info.guid == "2D4D1EB1D63BAB382A00E7DF7D0297CB"
        assert info.age == 1
        assert info.pdb_name == "hostname.pdb"

    def test_on_real_dll(self):
        dll = FIXTURES / "version.dll"
        if not dll.is_file():
            pytest.skip("version.dll fixture not available")
        info = parse_rsds(dll)
        assert info is not None
        assert info.guid == "440DD63BE2B021F80FD0C78EF0AECEF2"
        assert info.age == 1
        assert info.pdb_name == "version.pdb"


# ---------------------------------------------------------------------------
# symbol_server_url
# ---------------------------------------------------------------------------


class TestSymbolServerUrl:
    def test_format(self):
        info = RsdsInfo(
            guid="BD124415890CD9D15591374C078A9B66",
            age=1,
            pdb_name="MpSvc.pdb",
            pdb_path="MpSvc.pdb",
        )
        url = symbol_server_url(info)
        assert url == (
            "https://msdl.microsoft.com/download/symbols/"
            "MpSvc.pdb/BD124415890CD9D15591374C078A9B661/MpSvc.pdb"
        )

    def test_age_appended_as_decimal(self):
        info = RsdsInfo(guid="AABB", age=12, pdb_name="x.pdb", pdb_path="x.pdb")
        assert "/AABB12/x.pdb" in symbol_server_url(info)


# ---------------------------------------------------------------------------
# pdb_cache_path
# ---------------------------------------------------------------------------


class TestPdbCachePath:
    def test_structure(self, tmp_path):
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")
        path = pdb_cache_path(info, tmp_path)
        assert path == tmp_path / "pdb" / "test.pdb" / "AABB1" / "test.pdb"


# ---------------------------------------------------------------------------
# fetch_pdb
# ---------------------------------------------------------------------------


class TestFetchPdb:
    def test_returns_cached_file_on_hit(self, tmp_path):
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")
        cached = pdb_cache_path(info, tmp_path)
        cached.parent.mkdir(parents=True)
        cached.write_bytes(b"fake pdb content")

        result = fetch_pdb(info, tmp_path)
        assert result == cached

    def test_downloads_on_cache_miss(self, tmp_path, monkeypatch):
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")
        pdb_content = b"downloaded pdb data"

        def fake_download(url):
            return pdb_content

        monkeypatch.setattr("ghidra_decomp.pdb._download", fake_download)

        result = fetch_pdb(info, tmp_path)
        assert result is not None
        assert result.read_bytes() == pdb_content

    def test_returns_none_on_404(self, tmp_path, monkeypatch):
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")

        monkeypatch.setattr("ghidra_decomp.pdb._download", lambda url: None)

        assert fetch_pdb(info, tmp_path) is None

    def test_returns_none_on_network_error(self, tmp_path, monkeypatch):
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")

        monkeypatch.setattr("ghidra_decomp.pdb._download", lambda url: None)

        assert fetch_pdb(info, tmp_path) is None

    def test_tries_compressed_on_primary_miss(self, tmp_path, monkeypatch):
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")
        calls = []

        def fake_download(url):
            calls.append(url)
            if url.endswith("test.pdb"):
                return
            return  # compressed also misses

        monkeypatch.setattr("ghidra_decomp.pdb._download", fake_download)
        fetch_pdb(info, tmp_path)

        assert len(calls) == 2
        assert calls[0].endswith("test.pdb")
        assert calls[1].endswith("test.pd_")


# ---------------------------------------------------------------------------
# pdb_identity
# ---------------------------------------------------------------------------


class TestPdbIdentity:
    def test_with_local_file(self, tmp_path):
        pdb = tmp_path / "test.pdb"
        pdb.write_bytes(b"fake pdb")
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")

        identity = pdb_identity(pdb, info)
        assert identity is not None
        assert identity["pdb_name"] == "test.pdb"
        assert identity["guid"] == "AABB"
        assert identity["age"] == 1
        assert len(identity["sha256"]) == 64

    def test_returns_none_without_path(self):
        info = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")
        assert pdb_identity(None, info) is None

    def test_returns_none_without_info(self, tmp_path):
        pdb = tmp_path / "test.pdb"
        pdb.write_bytes(b"fake pdb")
        assert pdb_identity(pdb, None) is None


# ---------------------------------------------------------------------------
# prompt_pdb_fetch
# ---------------------------------------------------------------------------


class TestPromptPdbFetch:
    INFO = RsdsInfo(guid="AABB", age=1, pdb_name="test.pdb", pdb_path="test.pdb")

    def test_returns_false_when_not_tty(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": lambda self: False})())
        assert prompt_pdb_fetch(self.INFO) is False

    def test_returns_true_on_empty_input(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": lambda self: True})())
        monkeypatch.setattr("builtins.input", lambda: "")
        assert prompt_pdb_fetch(self.INFO) is True

    def test_returns_true_on_y(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": lambda self: True})())
        monkeypatch.setattr("builtins.input", lambda: "y")
        assert prompt_pdb_fetch(self.INFO) is True

    def test_returns_false_on_n(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": lambda self: True})())
        monkeypatch.setattr("builtins.input", lambda: "n")
        assert prompt_pdb_fetch(self.INFO) is False

    def test_returns_false_on_eof(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", type("FakeStdin", (), {"isatty": lambda self: True})())
        monkeypatch.setattr("builtins.input", lambda: (_ for _ in ()).throw(EOFError))
        assert prompt_pdb_fetch(self.INFO) is False
