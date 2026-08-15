"""Deterministic and atomic corpus artifact helpers."""

from __future__ import annotations

import errno
import hashlib
import importlib
import json
import os
import shutil
import tempfile
import time
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 2
CORPUS_OWNER = "ghidra-decomp"


@dataclass(frozen=True)
class DestinationState:
    """Identity of a destination checked before a long-running export."""

    exists: bool
    device: int | None = None
    inode: int | None = None
    mode: int | None = None
    group: int | None = None


def sha256_file(path: Path) -> str:
    """Return the SHA-256 digest of a file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_input(source: Path, destination: Path) -> dict[str, Any]:
    """Copy an input once and return the identity of the exact copied bytes."""
    source_path = source.resolve()
    digest = hashlib.sha256()
    size = 0
    with source_path.open("rb") as input_stream, destination.open("xb") as snapshot:
        for chunk in iter(lambda: input_stream.read(1024 * 1024), b""):
            snapshot.write(chunk)
            digest.update(chunk)
            size += len(chunk)
        snapshot.flush()
        os.fsync(snapshot.fileno())
    return {"path": str(source_path), "sha256": digest.hexdigest(), "size": size}


def build_fingerprint(
    input_identity: Path | Mapping[str, Any], analysis: dict[str, Any]
) -> dict[str, Any]:
    """Build the complete, canonical input and analysis fingerprint."""
    if isinstance(input_identity, Path):
        input_data = {
            "path": str(input_identity.resolve()),
            "sha256": sha256_file(input_identity),
            "size": input_identity.stat().st_size,
        }
    else:
        input_data = dict(input_identity)
    fingerprint: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "input": input_data,
        "analysis": analysis,
    }
    hash_input = {key: value for key, value in input_data.items() if key != "path"}
    canonical = json.dumps(
        {**fingerprint, "input": hash_input},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    fingerprint["sha256"] = hashlib.sha256(canonical).hexdigest()
    return fingerprint


def fsync_directory(path: Path) -> None:
    """Sync directory entries when the host filesystem supports it."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if os.name == "nt" or error.errno in {
            errno.EACCES,
            errno.EINVAL,
            errno.ENOTSUP,
            errno.EOPNOTSUPP,
        }:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
                raise
    finally:
        os.close(descriptor)


def fsync_tree(root: Path) -> None:
    """Sync all directories in an artifact tree from leaves to root."""
    directories = [Path(path) for path, _, _ in os.walk(root)]
    for directory in reversed(directories):
        fsync_directory(directory)


def ensure_directory(path: Path) -> None:
    """Create a directory tree and sync every newly created parent entry."""
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    path.mkdir(parents=True, exist_ok=True)
    for directory in reversed(missing):
        fsync_directory(directory.parent)


def _owned_complete_manifest(output: Path) -> bool:
    manifest_path = output / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(manifest, dict)
        and manifest.get("schema_version") == SCHEMA_VERSION
        and manifest.get("status") == "complete"
        and isinstance(manifest.get("tool"), dict)
        and manifest["tool"].get("name") == CORPUS_OWNER
        and isinstance(manifest.get("input"), dict)
        and isinstance(manifest.get("fingerprints"), dict)
        and isinstance(manifest.get("indexes"), dict)
        and not (output / ".run-state.json").exists()
    )


@contextmanager
def destination_lock(output: Path):
    """Serialize publication and recovery for one destination."""
    lock_path = output.parent / f".{output.name}.lock"
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        if os.name == "nt":
            msvcrt = importlib.import_module("msvcrt")

            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        if os.name == "nt":
            msvcrt = importlib.import_module("msvcrt")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def validate_destination(output: Path) -> DestinationState:
    """Reject destinations that are neither empty nor owned complete corpora."""
    if not output.exists():
        return DestinationState(exists=False)
    if not output.is_dir():
        raise ValueError(f"Output path is not a directory: {output}")

    entries = {path.name for path in output.iterdir()}
    if entries and not _owned_complete_manifest(output):
        raise ValueError(
            f"Refusing to replace incomplete or unowned output directory: {output}"
        )

    stat = output.stat()
    return DestinationState(
        exists=True,
        device=stat.st_dev,
        inode=stat.st_ino,
        mode=stat.st_mode & 0o7777,
        group=stat.st_gid,
    )


def _backup_directories(output: Path) -> list[Path]:
    """Find backups using a literal prefix, not a user-controlled glob pattern."""
    prefix = f".{output.name}.backup-"
    return [
        path
        for path in output.parent.iterdir()
        if path.name.startswith(prefix)
        and path.is_dir()
        and _owned_complete_manifest(path)
    ]


def _backup_generation(output: Path, backup: Path) -> int:
    prefix = f".{output.name}.backup-"
    generation = backup.name[len(prefix) :].split("-", 1)[0]
    try:
        return int(generation)
    except ValueError:
        return -1


def recover_destination(output: Path) -> bool:
    """Restore an owned backup left by an interrupted publication."""
    with destination_lock(output):
        if output.exists():
            return False
        backups = _backup_directories(output)
        if not backups:
            return False
        newest = max(backups, key=lambda path: _backup_generation(output, path))
        os.replace(newest, output)
        fsync_directory(output.parent)
        for stale in backups:
            if stale != newest:
                shutil.rmtree(stale, ignore_errors=True)
        fsync_directory(output.parent)
        return True


def publish_directory(
    staging: Path, output: Path, expected: DestinationState
) -> Path | None:
    """Atomically publish staging, restoring the prior corpus on failure."""
    with destination_lock(output):
        if not staging.is_dir() or not _owned_complete_manifest(staging):
            raise ValueError(
                f"Refusing to publish incomplete staging directory: {staging}"
            )
        current = validate_destination(output)
        if current != expected:
            raise ValueError(f"Output directory changed during export: {output}")

        staging.chmod(expected.mode if expected.mode is not None else 0o755)
        if expected.group is not None and hasattr(os, "chown"):
            try:
                os.chown(staging, -1, expected.group)
            except PermissionError:
                pass

        backup: Path | None = None
        if current.exists:
            backup = Path(
                tempfile.mkdtemp(
                    prefix=f".{output.name}.backup-{time.time_ns()}-",
                    dir=output.parent,
                )
            )
            backup.rmdir()

        old_moved = False
        new_moved = False
        try:
            if backup is not None:
                os.replace(output, backup)
                old_moved = True
                fsync_directory(output.parent)
            os.replace(staging, output)
            new_moved = True
            fsync_directory(output.parent)
        except BaseException as publication_error:
            rollback_errors = []
            if new_moved:
                try:
                    os.replace(output, staging)
                    fsync_directory(output.parent)
                    new_moved = False
                except BaseException as error:  # noqa: BLE001 - preserve rollback state
                    rollback_errors.append(error)
            if old_moved and backup is not None and not output.exists():
                try:
                    os.replace(backup, output)
                    fsync_directory(output.parent)
                    old_moved = False
                except BaseException as error:  # noqa: BLE001 - preserve rollback state
                    rollback_errors.append(error)
            for rollback_error in rollback_errors:
                publication_error.add_note(f"Rollback also failed: {rollback_error}")
            raise

        if backup is not None:
            try:
                shutil.rmtree(backup)
                fsync_directory(output.parent)
            except OSError:
                return backup
        return None


def atomic_write_chunks(path: Path, chunks: Iterable[str]) -> None:
    """Durably replace a text file from an iterable of chunks."""
    ensure_directory(path.parent)
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
        fsync_directory(path.parent)
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
