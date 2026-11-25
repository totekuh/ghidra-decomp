"""Build a binary-wide allocation map from high pcode.

Records every allocation call site, where its result pointer is stored, and how
it flows forward to other calls or the function's return.  The output is a fact
file — it records what Ghidra sees in the pcode, not opinions about bugs.

Wrapper unwrapping: when a call site targets a simple allocator wrapper (a
function that calls exactly one known allocator, returns its result, and passes
a parameter as the size without arithmetic), the entry resolves the size through
the wrapper chain (up to 2 levels deep).

Must stay importable without Ghidra: every function takes already-live objects
and only calls methods on them, so unit tests can drive it with fakes.
"""

from .builder import build_alloc_entries, serialize_alloc_map
from .catalog import ALLOC_MAP_SCHEMA_VERSION, DEFAULT_ALLOCATORS, load_allocators
from .wrapper_resolution import (
    detect_wrappers_from_candidates,
    resolve_wrappers,
)
from .wrappers import build_wrapper_candidate

__all__ = [
    "ALLOC_MAP_SCHEMA_VERSION",
    "DEFAULT_ALLOCATORS",
    "build_alloc_entries",
    "build_wrapper_candidate",
    "detect_wrappers_from_candidates",
    "load_allocators",
    "resolve_wrappers",
    "serialize_alloc_map",
]
