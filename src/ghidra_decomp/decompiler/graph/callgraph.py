"""Callgraph traversal and query helpers.

Pure dict algorithms — no Ghidra dependency.
"""

from __future__ import annotations


def _callgraph_successors(callgraph: dict, address: str):
    """Yield resolved successor addresses from a callgraph entry."""
    entry = callgraph.get(address)
    if not entry:
        return
    for call in entry["calls"]:
        tgt = call.get("target_function_address") or call.get("target_address")
        if tgt and tgt in callgraph:
            yield tgt


def _callgraph_predecessors(callgraph: dict, address: str):
    """Yield predecessor addresses from a callgraph entry."""
    entry = callgraph.get(address)
    if not entry:
        return
    for caller in entry.get("called_by", []):
        addr = caller.get("address")
        if addr and addr in callgraph:
            yield addr


def _resolve_function(callgraph: dict, identifier: str) -> str:
    """Resolve a name or address to a callgraph address."""
    if identifier in callgraph:
        return identifier
    matches = [addr for addr, e in callgraph.items() if e["name"] == identifier]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ValueError(f"Ambiguous name {identifier!r}: matches {', '.join(matches)}")
    raise ValueError(f"Function not found: {identifier!r}")


def _is_reachable(callgraph: dict, source: str, dest: str) -> bool:
    """BFS reachability test. O(V+E)."""
    if source not in callgraph or dest not in callgraph:
        return False
    if source == dest:
        return True
    from collections import deque

    visited = {source}
    queue = deque([source])
    while queue:
        current = queue.popleft()
        for neighbor in _callgraph_successors(callgraph, current):
            if neighbor == dest:
                return True
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append(neighbor)
    return False


def _find_all_paths(
    callgraph: dict, source: str, dest: str, max_depth: int = 50
) -> list[list[str]]:
    """DFS backtracking to find all simple paths, depth-bounded."""
    if source not in callgraph or dest not in callgraph:
        return []
    if source == dest:
        return [[source]]
    paths: list[list[str]] = []
    path_set = {source}

    def dfs(current: str, path: list[str]) -> None:
        if len(path) > max_depth:
            return
        for neighbor in _callgraph_successors(callgraph, current):
            if neighbor == dest:
                paths.append(path + [neighbor])
            elif neighbor not in path_set:
                path_set.add(neighbor)
                path.append(neighbor)
                dfs(neighbor, path)
                path.pop()
                path_set.discard(neighbor)

    dfs(source, [source])
    return paths


def _find_endpoints(callgraph: dict) -> dict:
    """Find root functions (no callers) and leaf functions (no callees)."""
    roots: list[dict] = []
    leaves: list[dict] = []
    for address, entry in sorted(callgraph.items()):
        has_callers = any(True for _ in _callgraph_predecessors(callgraph, address))
        has_callees = any(True for _ in _callgraph_successors(callgraph, address))
        rec = {"address": address, "name": entry["name"]}
        if not has_callers:
            roots.append(rec)
        if not has_callees:
            leaves.append(rec)
    return {"roots": roots, "leaves": leaves}


def _neighborhood_bfs(
    callgraph: dict, address: str, depth: int = 2
) -> tuple[dict[str, int], set[tuple[str, str]]]:
    """BFS both directions to depth N. Returns (visited, edges)."""
    from collections import deque

    visited: dict[str, int] = {address: 0}
    queue = deque([(address, 0)])
    edges: set[tuple[str, str]] = set()
    while queue:
        current, d = queue.popleft()
        if d >= depth:
            continue
        for neighbor in _callgraph_successors(callgraph, current):
            edges.add((current, neighbor))
            if neighbor not in visited:
                visited[neighbor] = d + 1
                queue.append((neighbor, d + 1))
        for pred in _callgraph_predecessors(callgraph, current):
            edges.add((pred, current))
            if pred not in visited:
                visited[pred] = d + 1
                queue.append((pred, d + 1))
    return visited, edges


def _condense_graph(callgraph: dict, threshold: int) -> dict | None:
    """Condense large callgraphs by collapsing middle layers."""
    from collections import deque

    edge_count = sum(
        sum(1 for _ in _callgraph_successors(callgraph, addr)) for addr in callgraph
    )
    if edge_count <= threshold:
        return None

    endpoints = _find_endpoints(callgraph)
    root_addrs = {r["address"] for r in endpoints["roots"]}
    if not root_addrs and callgraph:
        root_addrs = {next(iter(callgraph))}

    depth: dict[str, int] = {}
    queue: deque[str] = deque()
    for r in root_addrs:
        depth[r] = 0
        queue.append(r)
    while queue:
        current = queue.popleft()
        for neighbor in _callgraph_successors(callgraph, current):
            if neighbor not in depth:
                depth[neighbor] = depth[current] + 1
                queue.append(neighbor)

    max_depth = max(depth.values()) if depth else 0

    leaf_addrs = {item["address"] for item in endpoints["leaves"]}
    if not leaf_addrs:
        leaf_addrs = root_addrs
    height: dict[str, int] = {}
    queue = deque()
    for item in leaf_addrs:
        height[item] = 0
        queue.append(item)
    while queue:
        current = queue.popleft()
        for pred in _callgraph_predecessors(callgraph, current):
            if pred not in height:
                height[pred] = height[current] + 1
                queue.append(pred)

    keep_top = min(2, max_depth)
    keep_bottom = min(2, max(height.values()) if height else 0)
    top_nodes = {a for a, d in depth.items() if d <= keep_top}
    bottom_nodes = {a for a, h in height.items() if h <= keep_bottom} - top_nodes
    kept = top_nodes | bottom_nodes | root_addrs

    hidden_count = len(callgraph) - len(kept)
    if hidden_count <= 0:
        return None

    placeholder = f"... {hidden_count} hidden functions ..."
    condensed_edges: list[tuple[str, str]] = []
    to_placeholder: set[str] = set()
    from_placeholder: set[str] = set()
    for addr in callgraph:
        for succ in _callgraph_successors(callgraph, addr):
            if addr in kept and succ in kept:
                condensed_edges.append((addr, succ))
            elif addr in kept and succ not in kept:
                to_placeholder.add(addr)
            elif addr not in kept and succ in kept:
                from_placeholder.add(succ)

    return {
        "kept": kept,
        "placeholder": placeholder,
        "edges": condensed_edges,
        "to_placeholder": to_placeholder,
        "from_placeholder": from_placeholder,
        "hidden_count": hidden_count,
    }
