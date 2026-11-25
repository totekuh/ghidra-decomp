"""Mermaid flowchart renderers for callgraph data."""

from __future__ import annotations

import re

from ghidra_decomp.decompiler.graph.callgraph import _neighborhood_bfs


def _mermaid_escape(text: str) -> str:
    """Escape characters that break Mermaid node labels."""
    for char in ('"', "<", ">", "&", "|", "{", "}", "(", ")"):
        text = text.replace(char, f"#{ord(char)};")
    return text


def _mermaid_node_id(address: str) -> str:
    """Turn an address into a valid Mermaid node ID."""
    return re.sub(r"[^A-Za-z0-9_]", "_", address)


def _render_mermaid_whole(callgraph: dict) -> str:
    """Render the complete program callgraph as a Mermaid flowchart."""
    lines = ["flowchart TD"]
    for address, entry in sorted(callgraph.items()):
        nid = _mermaid_node_id(address)
        lines.append(f'    {nid}["{_mermaid_escape(entry["name"])}"]')
    for address, entry in sorted(callgraph.items()):
        src = _mermaid_node_id(address)
        seen: set[str] = set()
        for call in entry["calls"]:
            tgt = call.get("target_function_address") or call.get("target_address")
            if tgt and tgt in callgraph and tgt not in seen:
                seen.add(tgt)
                lines.append(f"    {src} --> {_mermaid_node_id(tgt)}")
    return "\n".join(lines) + "\n"


def _render_mermaid_function(callgraph: dict, address: str) -> str:
    """Render the neighborhood (callers + callees) of one function."""
    entry = callgraph[address]
    lines = ["flowchart TD"]
    nid = _mermaid_node_id(address)
    lines.append(f'    {nid}["{_mermaid_escape(entry["name"])}"]:::focus')
    seen: set[str] = set()
    for call in entry["calls"]:
        tgt = call.get("target_function_address") or call.get("target_address")
        if tgt and tgt in callgraph and tgt not in seen:
            seen.add(tgt)
            tid = _mermaid_node_id(tgt)
            lines.append(f'    {tid}["{_mermaid_escape(callgraph[tgt]["name"])}"]')
            lines.append(f"    {nid} --> {tid}")
    for caller in entry.get("called_by", []):
        caddr = caller.get("address")
        if caddr and caddr in callgraph and caddr not in seen:
            seen.add(caddr)
            cid = _mermaid_node_id(caddr)
            lines.append(f'    {cid}["{_mermaid_escape(callgraph[caddr]["name"])}"]')
            lines.append(f"    {cid} --> {nid}")
    lines.append("    classDef focus fill:#f96,stroke:#333")
    return "\n".join(lines) + "\n"


def _render_mermaid_paths(callgraph: dict, paths: list[list[str]]) -> str:
    """Render path subgraph with source/dest/path coloring."""
    if not paths:
        return "flowchart TD\n"
    source = paths[0][0]
    dest = paths[0][-1]
    nodes: set[str] = set()
    edges: set[tuple[str, str]] = set()
    for path in paths:
        for addr in path:
            nodes.add(addr)
        for i in range(len(path) - 1):
            edges.add((path[i], path[i + 1]))
    lines = ["flowchart TD"]
    for addr in sorted(nodes):
        nid = _mermaid_node_id(addr)
        label = _mermaid_escape(callgraph[addr]["name"])
        if addr == source:
            cls = ":::source"
        elif addr == dest:
            cls = ":::dest"
        else:
            cls = ":::path"
        lines.append(f'    {nid}["{label}"]{cls}')
    for src, dst in sorted(edges):
        lines.append(f"    {_mermaid_node_id(src)} --> {_mermaid_node_id(dst)}")
    lines.append("    classDef source fill:#6f6,stroke:#333")
    lines.append("    classDef dest fill:#f66,stroke:#333")
    lines.append("    classDef path fill:#ff6,stroke:#333")
    return "\n".join(lines) + "\n"


def _render_mermaid_neighborhood(callgraph: dict, address: str, depth: int = 2) -> str:
    """Render N-hop neighborhood as Mermaid flowchart."""
    visited, edges = _neighborhood_bfs(callgraph, address, depth)
    lines = ["flowchart TD"]
    for addr in sorted(visited):
        nid = _mermaid_node_id(addr)
        label = _mermaid_escape(callgraph[addr]["name"])
        cls = ":::focus" if addr == address else ""
        lines.append(f'    {nid}["{label}"]{cls}')
    for src, dst in sorted(edges):
        lines.append(f"    {_mermaid_node_id(src)} --> {_mermaid_node_id(dst)}")
    lines.append("    classDef focus fill:#f96,stroke:#333")
    return "\n".join(lines) + "\n"


def _render_mermaid_condensed(callgraph: dict, condensed: dict) -> str:
    """Render condensed whole-graph with placeholder for hidden middle."""
    lines = ["flowchart TD"]
    for addr in sorted(condensed["kept"]):
        nid = _mermaid_node_id(addr)
        lines.append(f'    {nid}["{_mermaid_escape(callgraph[addr]["name"])}"]')
    pid = "HIDDEN"
    lines.append(f'    {pid}["{condensed["placeholder"]}"]:::hidden')
    for src, dst in sorted(condensed["edges"]):
        lines.append(f"    {_mermaid_node_id(src)} --> {_mermaid_node_id(dst)}")
    for addr in sorted(condensed["to_placeholder"]):
        lines.append(f"    {_mermaid_node_id(addr)} --> {pid}")
    for addr in sorted(condensed["from_placeholder"]):
        lines.append(f"    {pid} --> {_mermaid_node_id(addr)}")
    lines.append("    classDef hidden fill:#999,stroke:#333,stroke-dasharray: 5 5")
    return "\n".join(lines) + "\n"
