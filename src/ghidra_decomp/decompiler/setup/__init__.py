"""Pre-decompilation setup: Ghidra JVM, function filtering, resume."""

from ghidra_decomp.decompiler.setup.filters import (
    _selected_by_name,
    compile_filters,
    default_workers,
    select_functions,
)
from ghidra_decomp.decompiler.setup.ghidra import (
    _apply_gdts,
    _apply_pdb,
    _build_vm_args,
    _default_pdb_cache,
    _mark_entry,
    _parse_address,
    _rebase_program,
    _run_analysis,
    _start_pyghidra,
    list_languages,
)
from ghidra_decomp.decompiler.setup.resume import (
    _artifact_hashes_match,
    _reusable_function_artifacts,
    load_resume_index,
    normalize_filters,
)

__all__ = [
    "_apply_gdts",
    "_apply_pdb",
    "_artifact_hashes_match",
    "_build_vm_args",
    "_default_pdb_cache",
    "_mark_entry",
    "_parse_address",
    "_rebase_program",
    "_reusable_function_artifacts",
    "_run_analysis",
    "_selected_by_name",
    "_start_pyghidra",
    "compile_filters",
    "default_workers",
    "list_languages",
    "load_resume_index",
    "normalize_filters",
    "select_functions",
]
