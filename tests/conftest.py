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
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[1]
CROSSBUILD_DOCKERFILE = "tests/fixtures/Dockerfile.crossbuild"
CROSSBUILD_TAG = "ghidra-decomp-crossbuild:test"


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


@pytest.fixture(scope="module")
def ghidra_path() -> Path:
    return require_ghidra()


def _load_functions_index(output: Path) -> list[dict]:
    functions_json = output / "functions.json"
    return json.loads(functions_json.read_text(encoding="utf-8"))


def _read_pseudocode(output: Path, record: dict) -> str:
    c_path = output / record["artifacts"]["pseudocode"]
    return c_path.read_text(encoding="utf-8")


def _successful_records(output: Path) -> list[dict]:
    records = _load_functions_index(output)
    return [r for r in records if r.get("decompilation", {}).get("status") == "success"]


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


def require_docker() -> None:
    """Skip when Docker cannot be used to cross-compile fixtures.

    A fixture family compiled in-test needs a working Docker daemon; its absence
    is a skip, not a failure, so the rest of the suite still runs on a host
    without it.
    """
    if shutil.which("docker") is None:
        pytest.skip("docker is not installed")
    probe = subprocess.run(
        ["docker", "info"], capture_output=True, text=True, check=False
    )
    if probe.returncode != 0:
        pytest.skip("docker is installed but not usable")


def build_crossbuild_fixtures(dest: Path, names: list[str]) -> Path:
    """Compile named fixtures fresh from source via the crossbuild image.

    The image build is the compile step. Its COPY layers are keyed on the
    fixture sources, so editing a fixture's `.c` invalidates the cache and the
    binary is rebuilt — the test always decompiles what the current source
    produces, never a stale committed blob. Built binaries are extracted to
    `dest`, outside the image, for the test to consume.
    """
    build = subprocess.run(
        ["docker", "build", "-f", CROSSBUILD_DOCKERFILE, "-t", CROSSBUILD_TAG, "."],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert build.returncode == 0, f"crossbuild image failed:\n{build.stderr}"

    created = subprocess.run(
        ["docker", "create", CROSSBUILD_TAG],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert created.returncode == 0, f"docker create failed:\n{created.stderr}"
    container = created.stdout.strip()
    try:
        for name in names:
            copied = subprocess.run(
                ["docker", "cp", f"{container}:/fixtures/{name}", str(dest / name)],
                capture_output=True,
                text=True,
                check=False,
            )
            assert copied.returncode == 0, f"docker cp {name} failed:\n{copied.stderr}"
    finally:
        subprocess.run(
            ["docker", "rm", container], capture_output=True, text=True, check=False
        )
    return dest
