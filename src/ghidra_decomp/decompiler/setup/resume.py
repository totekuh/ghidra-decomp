"""Incremental resume logic for reusing previous corpus artifacts."""

from __future__ import annotations

import json
from pathlib import Path

from ghidra_decomp.artifacts import SCHEMA_VERSION, sha256_file
from ghidra_decomp.decompiler.constants import STATUS_SUCCESS
from ghidra_decomp.decompiler.naming import _artifact_stem


def normalize_filters(filters: dict | None) -> dict[str, list[str]]:
    """Render the function selection in one canonical, comparable form."""
    filters = filters or {}
    return {
        key: sorted(filters.get(key) or ())
        for key in ("include", "exclude", "function")
    }


def _artifact_hashes_match(previous: Path, record: dict) -> bool:
    """Check every artifact a record claims still hashes to the recorded digest."""
    artifacts = record.get("artifacts")
    if not isinstance(artifacts, dict):
        return False
    checks = [
        ("pseudocode", "pseudocode_sha256"),
        ("assembly", "assembly_sha256"),
        ("sidecar", "sidecar_sha256"),
    ]
    if isinstance(artifacts.get("pcode"), str):
        checks.append(("pcode", "pcode_sha256"))
    for path_key, hash_key in checks:
        relative = artifacts.get(path_key)
        expected = artifacts.get(hash_key)
        if not isinstance(relative, str) or not isinstance(expected, str):
            return False
        path = previous / relative
        if not path.resolve().is_relative_to(previous.resolve()):
            return False
        if not path.is_file() or sha256_file(path) != expected:
            return False
    return True


def _reusable_function_artifacts(previous: Path, record: dict) -> bool:
    """Decide whether a previously exported function may be reused verbatim."""
    if record.get("decompilation", {}).get("status") != STATUS_SUCCESS:
        return False
    sidecar_relative = record.get("artifacts", {}).get("sidecar")
    if not isinstance(sidecar_relative, str):
        return False
    try:
        sidecar = json.loads((previous / sidecar_relative).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    if not isinstance(sidecar, dict):
        return False
    return _artifact_hashes_match(previous, record)


def load_resume_index(
    previous: Path, request_fingerprint: dict, filters: dict | None = None
) -> dict[str, dict]:
    """Map artifact stem to the reusable record of a previous corpus."""
    try:
        manifest = json.loads((previous / "manifest.json").read_text(encoding="utf-8"))
        records = json.loads((previous / "functions.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(manifest, dict) or not isinstance(records, list):
        return {}
    if manifest.get("schema_version") != SCHEMA_VERSION:
        return {}
    if manifest.get("status") != "complete":
        return {}
    previous_request = manifest.get("fingerprints", {}).get("request", {})
    if previous_request.get("sha256") != request_fingerprint.get("sha256"):
        return {}
    if manifest.get("export", {}).get("filters") != normalize_filters(filters):
        return {}

    reusable = {}
    for record in records:
        if not isinstance(record, dict) or "address" not in record:
            continue
        if not _reusable_function_artifacts(previous, record):
            continue
        reusable[_artifact_stem(record["address"], record["name"])] = record
    return reusable
