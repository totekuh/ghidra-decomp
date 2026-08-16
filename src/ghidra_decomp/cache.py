"""Fingerprinted analysis cache holding retained Ghidra projects.

Re-importing and re-analyzing a binary dominates the cost of a run, so a
completed analysis is kept under a directory named after the full fingerprint of
its inputs. A cache entry is reused only when every input that could change the
analysis still matches; anything else is a miss that re-analyzes rather than an
error.

Ownership of an entry is held for the lifetime of a run through an exclusive
lock, so two runs never open the same Ghidra project.
"""

from __future__ import annotations

import json
import os
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import (
    SCHEMA_VERSION,
    atomic_write_json,
    build_fingerprint,
    ensure_directory,
    file_lock,
    fsync_directory,
)

CACHE_STATE_FILE = "cache-state.json"
CACHE_LOCK_FILE = ".lock"
PROJECT_DIRNAME = "project"
PROJECT_NAME = "project"

# Reasons recorded in the manifest so a miss is explainable after the fact.
REASON_HIT = "reused cached analysis"
REASON_DISABLED = "caching disabled"
REASON_FORCED = "reanalysis forced"
REASON_ABSENT = "no cached analysis for this fingerprint"
REASON_UNREADABLE = "cached analysis state is unreadable"
REASON_INCOMPLETE = "cached analysis did not finish"
REASON_PROJECT_MISSING = "cached project directory is missing"
REASON_BUSY = "cached analysis is in use by another run"


@dataclass(frozen=True)
class CacheOutcome:
    """What a run decided about the analysis cache, for the manifest."""

    enabled: bool
    hit: bool
    path: Path | None
    reason: str

    def as_manifest_block(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "hit": self.hit,
            "path": str(self.path) if self.path is not None else None,
            "reason": self.reason,
        }


def default_cache_root() -> Path:
    """Return the XDG cache root, honoring an explicit XDG_CACHE_HOME."""
    configured = os.environ.get("XDG_CACHE_HOME")
    if configured:
        return Path(configured).expanduser() / "ghidra-decomp"
    return Path.home() / ".cache" / "ghidra-decomp"


def cache_key_from(fingerprint: dict[str, Any]) -> str:
    """Return the directory name for an already-built fingerprint.

    The complete digest is used, never a shortened prefix, so two different
    requests cannot collide into one retained project.
    """
    return fingerprint["sha256"]


def cache_key(input_identity: Any, requested_analysis: dict[str, Any]) -> str:
    """Derive the directory name for one binary and analysis request."""
    return cache_key_from(build_fingerprint(input_identity, requested_analysis))


def entry_path(root: Path, key: str) -> Path:
    return root / key


def resolved_versions(
    *, ghidra_version: str, pyghidra_version: str, exporter_version: str
) -> dict[str, Any]:
    """Collect the versions that invalidate an entry once the JVM is up."""
    return {
        "schema_version": SCHEMA_VERSION,
        "ghidra_version": ghidra_version,
        "pyghidra_version": pyghidra_version,
        "exporter_version": exporter_version,
    }


def read_state(entry: Path) -> dict[str, Any] | None:
    """Read an entry's state file, treating any damage as a miss."""
    try:
        state = json.loads((entry / CACHE_STATE_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return state if isinstance(state, dict) else None


def evaluate_entry(
    entry: Path, request_fingerprint: dict[str, Any], versions: dict[str, Any]
) -> tuple[bool, str]:
    """Decide whether a retained project may be reopened."""
    state = read_state(entry)
    if state is None:
        return False, REASON_UNREADABLE
    if state.get("status") != "complete":
        return False, REASON_INCOMPLETE
    if state.get("fingerprint", {}).get("sha256") != request_fingerprint["sha256"]:
        # Defensive: the directory name already encodes this digest.
        return False, REASON_ABSENT
    for key, value in versions.items():
        if state.get("versions", {}).get(key) != value:
            return False, f"cached analysis was built with a different {key}"
    if not (entry / PROJECT_DIRNAME).is_dir():
        return False, REASON_PROJECT_MISSING
    return True, REASON_HIT


@contextmanager
def entry_lock(entry: Path, *, blocking: bool = False):
    """Own a cache entry for the duration of a run.

    Yields True when the lock was taken. A caller that cannot take it must fall
    back to a temporary project instead of sharing a Ghidra project.
    """
    ensure_directory(entry)
    with file_lock(entry / CACHE_LOCK_FILE, blocking=blocking) as acquired:
        yield acquired


def mark_incomplete(entry: Path, request_fingerprint: dict[str, Any]) -> None:
    """Record that an entry is being built, so a killed run is never reused."""
    atomic_write_json(
        entry / CACHE_STATE_FILE,
        {
            "schema_version": SCHEMA_VERSION,
            "status": "incomplete",
            "fingerprint": request_fingerprint,
        },
    )


def mark_complete(
    entry: Path,
    request_fingerprint: dict[str, Any],
    versions: dict[str, Any],
    analysis: dict[str, Any],
) -> None:
    """Publish an entry as reusable once its project is durable."""
    fsync_directory(entry)
    atomic_write_json(
        entry / CACHE_STATE_FILE,
        {
            "schema_version": SCHEMA_VERSION,
            "status": "complete",
            "fingerprint": request_fingerprint,
            "versions": versions,
            "analysis": analysis,
        },
    )


def discard_project(root: Path, entry: Path) -> None:
    """Remove a retained project, refusing any path outside the cache root.

    Only the project is removed, never the entry itself: the entry holds the
    lock file that makes this run the owner, and replacing it mid-run would let
    a second run believe the entry is free. Cleanup never infers a directory
    from an output path.
    """
    root = root.resolve()
    project = (entry / PROJECT_DIRNAME).resolve()
    if project == root or root not in project.parents:
        raise ValueError(f"Refusing to remove a path outside the cache root: {project}")
    shutil.rmtree(project, ignore_errors=True)
