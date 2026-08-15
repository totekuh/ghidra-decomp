"""Deterministic and atomic corpus artifact helpers."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_fingerprint(binary: Path, analysis: dict[str, Any]) -> dict[str, Any]:
    """Build the complete, canonical input and analysis fingerprint."""
    fingerprint: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "input": {
            "path": str(binary.resolve()),
            "sha256": sha256_file(binary),
            "size": binary.stat().st_size,
        },
        "analysis": analysis,
    }
    canonical = json.dumps(
        fingerprint, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    fingerprint["sha256"] = hashlib.sha256(canonical).hexdigest()
    return fingerprint


def atomic_write_chunks(path: Path, chunks: Iterable[str]) -> None:
    """Durably replace a text file from an iterable of chunks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temp_path = Path(stream.name)
            for chunk in chunks:
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        temp_path.replace(path)
    finally:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink()


def atomic_write_text(path: Path, content: str) -> None:
    """Durably replace a text file using a temporary sibling."""
    atomic_write_chunks(path, (content,))


def atomic_write_json(path: Path, data: Any) -> None:
    """Write stable, formatted JSON through :func:`atomic_write_text`."""
    atomic_write_text(
        path, json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    )
