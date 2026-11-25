"""Allocator catalogue and config loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ALLOC_MAP_SCHEMA_VERSION = 1

# ── allocator catalogue ──────────────────────────────────────────────────
#
# Each value is a size-argument spec:
#   {"index": N}          — single argument at position N is the byte count
#   {"product": [A, B]}   — two arguments whose product is the byte count
#   None                  — size is implicit or unknown (strdup, cache allocs)

DEFAULT_ALLOCATORS: dict[str, dict[str, Any] | None] = {
    # Standard libc
    "malloc": {"index": 0},
    "calloc": {"product": [0, 1]},
    "realloc": {"index": 1},
    "reallocarray": {"product": [1, 2]},
    "aligned_alloc": {"index": 1},
    "posix_memalign": {"index": 2},
    "memalign": {"index": 1},
    "pvalloc": {"index": 0},
    "valloc": {"index": 0},
    "strdup": None,
    "strndup": {"index": 1},
    # Linux kernel
    "kmalloc": {"index": 0},
    "kzalloc": {"index": 0},
    "kcalloc": {"product": [0, 1]},
    "krealloc": {"index": 1},
    "kvmalloc": {"index": 0},
    "kvzalloc": {"index": 0},
    "kvcalloc": {"product": [0, 1]},
    "vmalloc": {"index": 0},
    "vzalloc": {"index": 0},
    "kmalloc_array": {"product": [0, 1]},
    "devm_kmalloc": {"index": 1},
    "devm_kzalloc": {"index": 1},
    "devm_kcalloc": {"product": [1, 2]},
    "kmem_cache_alloc": None,
    "kmem_cache_alloc_trace": {"index": 2},
    "kmem_cache_zalloc": None,
    "__kmalloc": {"index": 0},
    "kmalloc_node": {"index": 0},
    "kzalloc_node": {"index": 0},
    "alloc_skb": {"index": 0},
    "__alloc_skb": {"index": 0},
    "netdev_alloc_skb": {"index": 1},
    "dev_alloc_skb": {"index": 0},
    "skb_copy": None,
    "skb_clone": None,
}


def load_allocators(
    config_path: Path | None = None,
) -> dict[str, dict[str, Any] | None]:
    """Return the allocator catalogue, optionally extended by a JSON config."""
    allocators = dict(DEFAULT_ALLOCATORS)
    if config_path is not None:
        with open(config_path, encoding="utf-8") as fh:
            user = json.load(fh)
        if isinstance(user, dict):
            allocators.update(user)
    return allocators
