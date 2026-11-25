"""Low-level filesystem primitives: fsync, locking, atomic writes."""

from __future__ import annotations

import ctypes
import ctypes.util
import errno
import importlib
import json
import os
import tempfile
from collections.abc import Iterable
from contextlib import contextmanager
from pathlib import Path
from typing import Any


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


_RENAME_EXCHANGE = 2
_AT_FDCWD = -100
_renameat2_fn = None
_renameat2_resolved = False


def _resolve_renameat2():
    global _renameat2_fn, _renameat2_resolved
    if _renameat2_resolved:
        return
    _renameat2_resolved = True
    if os.name == "nt":
        return
    try:
        libc_name = ctypes.util.find_library("c")
        if libc_name is None:
            return
        libc = ctypes.CDLL(libc_name, use_errno=True)
        fn = libc.renameat2
        fn.argtypes = [
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_uint,
        ]
        fn.restype = ctypes.c_int
        _renameat2_fn = fn
    except (OSError, AttributeError):
        pass


def _try_atomic_exchange(source: Path, target: Path) -> bool:
    _resolve_renameat2()
    if _renameat2_fn is None:
        return False
    result = _renameat2_fn(
        _AT_FDCWD,
        str(source).encode(),
        _AT_FDCWD,
        str(target).encode(),
        _RENAME_EXCHANGE,
    )
    return result == 0


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


def _acquire_lock(descriptor: int, *, blocking: bool) -> bool:
    """Take an exclusive lock on an open descriptor, honoring the platform API."""
    if os.name == "nt":
        msvcrt = importlib.import_module("msvcrt")

        os.lseek(descriptor, 0, os.SEEK_SET)
        if os.fstat(descriptor).st_size == 0:
            os.write(descriptor, b"\0")
        os.lseek(descriptor, 0, os.SEEK_SET)
        mode = msvcrt.LK_LOCK if blocking else msvcrt.LK_NBLCK
        try:
            msvcrt.locking(descriptor, mode, 1)
        except OSError:
            if blocking:
                raise
            return False
        return True

    import fcntl

    flags = fcntl.LOCK_EX if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
    try:
        fcntl.flock(descriptor, flags)
    except OSError:
        if blocking:
            raise
        return False
    return True


def _release_lock(descriptor: int) -> None:
    """Release a lock taken by `_acquire_lock`."""
    if os.name == "nt":
        msvcrt = importlib.import_module("msvcrt")
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def file_lock(lock_path: Path, *, blocking: bool = True):
    """Hold an exclusive lock on a lock file, yielding whether it was taken."""
    descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    acquired = False
    try:
        acquired = _acquire_lock(descriptor, blocking=blocking)
        yield acquired
    finally:
        if acquired:
            _release_lock(descriptor)
        os.close(descriptor)


@contextmanager
def destination_lock(output: Path):
    """Serialize publication and recovery for one destination."""
    with file_lock(output.parent / f".{output.name}.lock"):
        yield


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
