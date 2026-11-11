"""PE/PDB symbol resolution for Windows binaries.

Parses the CodeView RSDS debug record from PE files, fetches PDB symbols
from Microsoft's public symbol server, and caches them locally.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import click

from .artifacts import sha256_file

_SYMBOL_SERVER = "https://msdl.microsoft.com/download/symbols"
_IMAGE_DEBUG_TYPE_CODEVIEW = 2
_RSDS_SIGNATURE = b"RSDS"


@dataclass(frozen=True)
class RsdsInfo:
    """CodeView RSDS debug record extracted from a PE binary."""

    guid: str
    age: int
    pdb_name: str
    pdb_path: str


def parse_rsds(binary: Path) -> RsdsInfo | None:
    """Extract the CodeView RSDS record from a PE binary.

    Returns ``None`` for non-PE files, PEs without a debug directory, or
    PEs whose debug directory contains no RSDS CodeView entry.
    """
    try:
        data = binary.read_bytes()
    except OSError:
        return None

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if len(data) < pe_offset + 4 or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return None

    coff = pe_offset + 4
    if len(data) < coff + 20:
        return None
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt_offset = coff + 20

    if len(data) < opt_offset + 2:
        return None
    magic = struct.unpack_from("<H", data, opt_offset)[0]

    if magic == 0x20B:  # PE32+
        dd_offset = opt_offset + 112
    elif magic == 0x10B:  # PE32
        dd_offset = opt_offset + 96
    else:
        return None

    if len(data) < dd_offset + 7 * 8:
        return None
    debug_rva = struct.unpack_from("<I", data, dd_offset + 6 * 8)[0]
    debug_size = struct.unpack_from("<I", data, dd_offset + 6 * 8 + 4)[0]
    if debug_rva == 0 or debug_size == 0:
        return None

    sections_offset = opt_offset + optional_size
    file_offset = _rva_to_file_offset(data, debug_rva, sections_offset, num_sections)
    if file_offset is None:
        return None

    num_entries = debug_size // 28
    for i in range(num_entries):
        entry = file_offset + i * 28
        if len(data) < entry + 28:
            return None
        dtype = struct.unpack_from("<I", data, entry + 12)[0]
        dsize = struct.unpack_from("<I", data, entry + 16)[0]
        dptr = struct.unpack_from("<I", data, entry + 24)[0]
        if dtype != _IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        if len(data) < dptr + 24 or dsize < 25:
            continue
        if data[dptr : dptr + 4] != _RSDS_SIGNATURE:
            continue

        guid_bytes = data[dptr + 4 : dptr + 20]
        age = struct.unpack_from("<I", data, dptr + 20)[0]
        pdb_path_raw = data[dptr + 24 : dptr + dsize]
        pdb_path_str = pdb_path_raw.split(b"\x00", 1)[0].decode(
            "utf-8", errors="replace"
        )

        d1 = struct.unpack_from("<I", guid_bytes, 0)[0]
        d2 = struct.unpack_from("<H", guid_bytes, 4)[0]
        d3 = struct.unpack_from("<H", guid_bytes, 6)[0]
        d4 = guid_bytes[8:16].hex().upper()
        guid = f"{d1:08X}{d2:04X}{d3:04X}{d4}"

        pdb_name = (
            pdb_path_str.rsplit("\\", 1)[-1] if "\\" in pdb_path_str else pdb_path_str
        )

        return RsdsInfo(guid=guid, age=age, pdb_name=pdb_name, pdb_path=pdb_path_str)

    return None


def symbol_server_url(info: RsdsInfo) -> str:
    """Build the Microsoft symbol server URL for a PDB."""
    return f"{_SYMBOL_SERVER}/{info.pdb_name}/{info.guid}{info.age}/{info.pdb_name}"


def pdb_cache_path(info: RsdsInfo, cache_dir: Path) -> Path:
    """Canonical local path for a cached PDB."""
    return cache_dir / "pdb" / info.pdb_name / f"{info.guid}{info.age}" / info.pdb_name


def fetch_pdb(info: RsdsInfo, cache_dir: Path) -> Path | None:
    """Download a PDB from the symbol server, or return the cached copy.

    Returns the local path on success, ``None`` on 404 or network error.
    """
    cached = pdb_cache_path(info, cache_dir)
    if cached.is_file() and cached.stat().st_size > 0:
        return cached

    url = symbol_server_url(info)
    pdb_bytes = _download(url)
    if pdb_bytes is None:
        compressed_name = info.pdb_name[:-1] + "_"
        compressed_url = (
            f"{_SYMBOL_SERVER}/{info.pdb_name}/{info.guid}{info.age}/{compressed_name}"
        )
        cab_bytes = _download(compressed_url)
        if cab_bytes is None:
            return None
        pdb_bytes = _decompress_cab(cab_bytes)
        if pdb_bytes is None:
            return None

    cached.parent.mkdir(parents=True, exist_ok=True)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=cached.parent, suffix=".tmp")
        import os

        os.write(fd, pdb_bytes)
        os.close(fd)
        Path(tmp).replace(cached)
    except OSError:
        if tmp is not None:
            Path(tmp).unlink(missing_ok=True)
        return None
    return cached


def pdb_identity(pdb_path: Path | None, info: RsdsInfo | None) -> dict | None:
    """Build a PDB identity dict for cache fingerprinting."""
    if pdb_path is None or info is None:
        return None
    return {
        "pdb_name": info.pdb_name,
        "guid": info.guid,
        "age": info.age,
        "sha256": sha256_file(pdb_path),
    }


def prompt_pdb_fetch(info: RsdsInfo) -> bool:
    """Ask the user whether to fetch a detected PDB from the symbol server.

    Returns ``False`` without prompting when stdin is not a TTY.
    """
    if not sys.stdin.isatty():
        return False
    click.echo(
        f"PDB available: {info.pdb_name} ({info.guid}). "
        "Fetch from symbol server? [Y/n] ",
        nl=False,
    )
    try:
        answer = input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        click.echo()
        return False
    return answer in ("", "y", "yes")


def _rva_to_file_offset(
    data: bytes, rva: int, sections_offset: int, num_sections: int
) -> int | None:
    """Convert a relative virtual address to a file offset using section headers."""
    for i in range(num_sections):
        s = sections_offset + i * 40
        if len(data) < s + 40:
            return None
        vaddr = struct.unpack_from("<I", data, s + 12)[0]
        vsize = struct.unpack_from("<I", data, s + 8)[0]
        raw_offset = struct.unpack_from("<I", data, s + 20)[0]
        if vaddr <= rva < vaddr + vsize:
            return raw_offset + (rva - vaddr)
    return None


def _download(url: str) -> bytes | None:
    """Fetch a URL, returning bytes on success or None on error."""
    request = Request(url, headers={"User-Agent": "ghidra-decomp"})
    try:
        with urlopen(request, timeout=30) as response:
            return response.read()
    except (HTTPError, URLError, OSError):
        return None


def _decompress_cab(cab_bytes: bytes) -> bytes | None:
    """Extract the first file from a CAB archive using cabextract."""
    if not shutil.which("cabextract"):
        return None
    try:
        result = subprocess.run(
            ["cabextract", "-p", "-"],
            input=cab_bytes,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None
