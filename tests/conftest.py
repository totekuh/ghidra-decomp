"""Shared helpers for the end-to-end suites.

The three e2e modules previously carried their own copies of the hashing
helper, the Ghidra discovery guard, the subprocess invocation, and the
sidecar equality check. They live here so a change to how the tool is invoked
is made once.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def sha256_of(path: Path) -> str:
    """Hash a file without loading it whole."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(output: Path, name: str):
    return json.loads((output / name).read_text(encoding="utf-8"))


def require_ghidra() -> Path:
    """Return the Ghidra installation, skipping when it cannot be used.

    An explicitly configured but unusable GHIDRA_INSTALL_DIR is a failure, not a
    skip: the operator asked for that installation and deserves to hear that it
    is wrong rather than watch the suite quietly pass.
    """
    configured = os.environ.get("GHIDRA_INSTALL_DIR")
    if configured is not None:
        if not configured:
            pytest.fail("GHIDRA_INSTALL_DIR is explicitly configured but empty")
        path = Path(configured)
        if not path.is_dir():
            pytest.fail(f"configured GHIDRA_INSTALL_DIR is not a directory: {path}")
    else:
        path = Path("/usr/share/ghidra")
        if not path.is_dir():
            pytest.skip(
                "GHIDRA_INSTALL_DIR is unset and /usr/share/ghidra is unavailable"
            )
    if importlib.util.find_spec("pyghidra") is None:
        pytest.skip("pyghidra is not installed")
    return path


def run_export(
    binary: Path,
    output: Path,
    *extra: str,
    ghidra_path: Path | None = None,
    timeout: int = 300,
    env: dict[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess:
    """Run the CLI in its own process, the way a user would."""
    arguments = [sys.executable, "-m", "ghidra_decomp", str(binary), "-o", str(output)]
    if ghidra_path is not None:
        arguments += ["--ghidra-path", str(ghidra_path)]
    arguments += list(extra)

    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, **(env or {})},
    )
    if check:
        assert result.returncode == 0, (
            f"export failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
    return result


def assert_sidecar_matches_record(output: Path, record: dict) -> None:
    """A sidecar must equal its index record apart from its own hash."""
    sidecar = load_json(output, record["artifacts"]["sidecar"])
    expected = json.loads(json.dumps(record))
    expected["artifacts"].pop("sidecar_sha256")
    assert sidecar == expected


def assert_artifact_hashes(output: Path, record: dict) -> None:
    """Every artifact a record names must still hash to its recorded digest."""
    for path_key, hash_key in (
        ("pseudocode", "pseudocode_sha256"),
        ("assembly", "assembly_sha256"),
        ("sidecar", "sidecar_sha256"),
    ):
        path = output / record["artifacts"][path_key]
        assert path.is_file()
        assert sha256_of(path) == record["artifacts"][hash_key]
