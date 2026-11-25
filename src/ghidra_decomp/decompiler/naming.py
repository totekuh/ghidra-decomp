"""Artifact naming and filename sanitization."""

from __future__ import annotations

import hashlib
import re


def _sanitize_name(name: str, max_length: int = 80) -> str:
    """Turn a function name into a safe filename component."""
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", name).rstrip(". ") or "_"
    reserved = {"CON", "PRN", "AUX", "NUL"} | {
        f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
    }
    if safe.upper() in reserved:
        safe = f"_{safe}"
    return safe[:max_length]


def _artifact_stem(address: str, name: str, max_length: int = 120) -> str:
    """Build a bounded, portable, collision-resistant artifact stem."""
    digest = hashlib.sha256(f"{address}\0{name}".encode()).hexdigest()[:24]
    safe_address = _sanitize_name(address, 40)
    name_limit = max(1, max_length - len(safe_address) - len(digest) - 2)
    safe_name = _sanitize_name(name, name_limit)
    return f"{safe_address}_{digest}_{safe_name}"
