"""Phase 3 of _export_all: program-wide indexes, secondary products, manifest."""

from __future__ import annotations

from pathlib import Path

import click

from ghidra_decomp import __version__
from ghidra_decomp.alloc_map import (
    detect_wrappers_from_candidates,
    resolve_wrappers,
    serialize_alloc_map,
)
from ghidra_decomp.artifacts import (
    SCHEMA_VERSION,
    atomic_write_chunks,
    atomic_write_json,
    atomic_write_text,
    build_fingerprint,
    fsync_tree,
    sha256_file,
)
from ghidra_decomp.decompiler.constants import STATUS_FAILED, STATUS_FALLBACK
from ghidra_decomp.decompiler.export.secondary import (
    _export_cpp,
    _export_gzf,
    _run_semgrep,
)
from ghidra_decomp.decompiler.extract.functions import (
    _extract_entry_points,
    _extract_exports,
    _extract_imports,
    _extract_sections,
    _extract_strings,
    _extract_symbols,
    _extract_unowned_references,
    json_line,
)
from ghidra_decomp.decompiler.extract.types import _extract_types
from ghidra_decomp.decompiler.graph.callgraph import (
    _condense_graph,
    _find_all_paths,
    _find_endpoints,
    _is_reachable,
    _resolve_function,
)
from ghidra_decomp.decompiler.graph.mermaid import (
    _render_mermaid_condensed,
    _render_mermaid_function,
    _render_mermaid_neighborhood,
    _render_mermaid_paths,
    _render_mermaid_whole,
)
from ghidra_decomp.decompiler.naming import _artifact_stem
from ghidra_decomp.decompiler.worker import _addresses_with_status, _summarize_statuses
from ghidra_decomp.struct_map import build_struct_map, filter_referenced_types


def write_indexes_and_manifest(
    program,
    input_identity: dict,
    output: Path,
    timeout: int,
    records: list[dict],
    all_alloc_entries: list[dict],
    wrapper_candidates: dict[str, dict],
    *,
    combined: bool,
    pcode: bool,
    alloc_map: bool,
    struct_map: bool,
    dump_all_structs: bool,
    alloc_map_config: Path | None,
    requested_analysis: dict,
    request_fingerprint: dict,
    pyghidra_version: str,
    workers: int,
    filters: dict,
    gzf: bool,
    semgrep_config: str | None,
    cpp_export: bool,
    mermaid: bool,
    callgraph_depth: int,
    condense_threshold: int | None,
    reachable: tuple[str, str] | None,
    max_payload_mb: int | None,
    reusable: dict,
    discovered_count: int,
    total: int,
    allocators: dict | None,
) -> None:
    """Write program-wide indexes, secondary products, and manifest."""
    from ghidra.framework import Application

    strings = _extract_strings(program)
    imports = _extract_imports(program)
    exports = _extract_exports(program)
    symbols = _extract_symbols(program)
    types = _extract_types(program)
    sections = _extract_sections(program)

    combined_path = output / "all_functions.c"
    separator = "\n" + ("/" * 80) + "\n\n"
    if combined:

        def combined_chunks():
            for index, record in enumerate(records):
                if index:
                    yield separator
                yield (output / record["artifacts"]["pseudocode"]).read_text(
                    encoding="utf-8"
                )

        atomic_write_chunks(combined_path, combined_chunks())
    elif combined_path.exists():
        combined_path.unlink()

    lang = program.getLanguage()
    counts = _summarize_statuses(records)
    metadata = {
        "binary": input_identity["path"],
        "format": program.getExecutableFormat(),
        "architecture": lang.getProcessor().toString(),
        "endian": lang.isBigEndian() and "big" or "little",
        "address_size": lang.getDefaultSpace().getSize(),
        "image_base": program.getImageBase().toString(),
        "num_functions": total,
        "num_successful": counts["successful"],
        "num_fallback": counts["fallback"],
        "num_failed": counts["failed"],
        "num_skipped": counts["skipped"],
        "fallback_functions": _addresses_with_status(records, STATUS_FALLBACK),
        "failed_functions": _addresses_with_status(records, STATUS_FAILED),
        "counts": counts,
    }

    callgraph = {
        record["address"]: {
            "name": record["name"],
            "address": record["address"],
            "calls": record["calls"],
            "called_by": record["called_by"],
        }
        for record in records
    }
    xrefs = [ref for record in records for ref in record["references"]]
    xrefs.extend(_extract_unowned_references(program, xrefs))

    indexes = {
        "types.json": types,
        "functions.json": records,
        "callgraph.json": callgraph,
        "strings.json": strings,
        "imports.json": imports,
        "exports.json": exports,
        "symbols.json": symbols,
        "sections.json": sections,
        "metadata.json": metadata,
    }
    for name, data in indexes.items():
        atomic_write_json(output / name, data)
    atomic_write_chunks(
        output / "xrefs.jsonl",
        (json_line(ref) for ref in xrefs),
    )

    ghidra_version = str(Application.getApplicationVersion())
    actual_analysis = {
        **requested_analysis,
        "language_id": str(program.getLanguageID()),
        "compiler_id": str(program.getCompilerSpec().getCompilerSpecID()),
        "image_base": program.getImageBase().toString(),
        "loader": program.getExecutableFormat(),
        "entry_points": _extract_entry_points(program),
        "ghidra_version": ghidra_version,
        "pyghidra_version": pyghidra_version,
        "exporter_version": __version__,
    }
    indexed_paths = [output / name for name in indexes] + [output / "xrefs.jsonl"]
    if combined:
        indexed_paths.append(combined_path)

    secondary: dict = {}
    if alloc_map:
        wrapper_db = detect_wrappers_from_candidates(
            wrapper_candidates, allocators or {}
        )
        resolve_wrappers(all_alloc_entries, wrapper_db, allocators or {})
        alloc_map_data = serialize_alloc_map(all_alloc_entries)
        alloc_map_path = output / "alloc_map.json"
        atomic_write_json(alloc_map_path, alloc_map_data)
        indexed_paths.append(alloc_map_path)
        secondary["alloc_map"] = str(alloc_map_path.relative_to(output))
    if struct_map:
        raw_struct_map = build_struct_map(types)
        if dump_all_structs:
            final_struct_map = raw_struct_map
        else:
            final_struct_map = filter_referenced_types(
                raw_struct_map,
                alloc_entries=all_alloc_entries,
                function_records=records,
            )
        struct_map_path = output / "struct_map.json"
        atomic_write_json(struct_map_path, final_struct_map)
        indexed_paths.append(struct_map_path)
        secondary["struct_map"] = str(struct_map_path.relative_to(output))
    if gzf:
        gzf_path = output / "program.gzf"
        _export_gzf(program, gzf_path)
        indexed_paths.append(gzf_path)
        secondary["gzf"] = str(gzf_path.relative_to(output))
    if semgrep_config:
        sarif_path = output / "semgrep.sarif"
        secondary["semgrep"] = {
            **_run_semgrep(semgrep_config, output, sarif_path),
            "path": str(sarif_path.relative_to(output)),
        }
        indexed_paths.append(sarif_path)
    if cpp_export:
        cpp_path = output / "program.c"
        _export_cpp(program, cpp_path)
        indexed_paths.append(cpp_path)
        secondary["cpp_export"] = str(cpp_path.relative_to(output))
        header_path = output / "program.h"
        if header_path.is_file():
            indexed_paths.append(header_path)
            secondary["cpp_header"] = str(header_path.relative_to(output))
    if mermaid:
        cg_dir = output / "callgraphs"
        cg_dir.mkdir(exist_ok=True)
        atomic_write_json(cg_dir / "endpoints.json", _find_endpoints(callgraph))
        if condense_threshold is not None:
            condensed = _condense_graph(callgraph, condense_threshold)
            if condensed is not None:
                atomic_write_text(
                    cg_dir / "callgraph.md",
                    _render_mermaid_condensed(callgraph, condensed),
                )
            else:
                atomic_write_text(
                    cg_dir / "callgraph.md", _render_mermaid_whole(callgraph)
                )
        else:
            atomic_write_text(cg_dir / "callgraph.md", _render_mermaid_whole(callgraph))
        for addr, cg_entry in callgraph.items():
            stem = _artifact_stem(addr, cg_entry["name"])
            if callgraph_depth > 1:
                content = _render_mermaid_neighborhood(callgraph, addr, callgraph_depth)
            else:
                content = _render_mermaid_function(callgraph, addr)
            atomic_write_text(cg_dir / f"{stem}.md", content)
        secondary["mermaid"] = "callgraphs/"
    if reachable is not None:
        try:
            src_addr = _resolve_function(callgraph, reachable[0])
            dst_addr = _resolve_function(callgraph, reachable[1])
        except ValueError as e:
            raise click.ClickException(str(e))
        reached = _is_reachable(callgraph, src_addr, dst_addr)
        all_paths = _find_all_paths(callgraph, src_addr, dst_addr) if reached else []
        reach_result = {
            "source": {
                "address": src_addr,
                "name": callgraph[src_addr]["name"],
            },
            "destination": {
                "address": dst_addr,
                "name": callgraph[dst_addr]["name"],
            },
            "reachable": reached,
            "path_count": len(all_paths),
            "paths": [[callgraph[a]["name"] for a in p] for p in all_paths],
            "paths_by_address": all_paths,
        }
        cg_dir = output / "callgraphs"
        cg_dir.mkdir(exist_ok=True)
        atomic_write_json(cg_dir / "reachability.json", reach_result)
        if mermaid and all_paths:
            atomic_write_text(
                cg_dir / "paths.md",
                _render_mermaid_paths(callgraph, all_paths),
            )
        src_name = callgraph[src_addr]["name"]
        dst_name = callgraph[dst_addr]["name"]
        if reached:
            click.echo(
                f"Reachable: {src_name} -> {dst_name} ({len(all_paths)} path(s))"
            )
        else:
            click.echo(f"Not reachable: {src_name} -> {dst_name}")

    from ghidra_decomp.decompiler.setup.resume import normalize_filters

    manifest = {
        "schema_version": SCHEMA_VERSION,
        "status": "complete",
        "fingerprints": {
            "request": request_fingerprint,
            "resolved": build_fingerprint(input_identity, actual_analysis),
        },
        "input": input_identity,
        "tool": {
            "name": "ghidra-decomp",
            "version": __version__,
            "pyghidra_version": pyghidra_version,
            "ghidra_version": ghidra_version,
        },
        "analysis": actual_analysis,
        "export": {
            "timeout": timeout,
            "workers": workers,
            "combined": combined,
            "resumed": bool(reusable),
            "filters": normalize_filters(filters),
            "discovered_before_filters": discovered_count,
            "secondary_products": secondary,
        },
        "counts": counts,
        "indexes": {
            str(path.relative_to(output)): {
                "path": str(path.relative_to(output)),
                "sha256": sha256_file(path),
            }
            for path in indexed_paths
        },
    }
    run_state_path = output / ".run-state.json"
    run_state_path.unlink()
    fsync_tree(output)
    atomic_write_json(output / "manifest.json", manifest)

    click.echo(
        f"Wrote {counts['successful']} functions, "
        f"{counts['fallback']} fallback, "
        f"{counts['failed']} failed, "
        f"{len(strings)} strings, "
        f"{len(imports)} imports, "
        f"{len(exports)} exports, "
        f"{len(symbols)} symbols, "
        f"{len(sections)} sections"
    )
