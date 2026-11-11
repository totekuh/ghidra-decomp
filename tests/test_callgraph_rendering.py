"""Unit tests for callgraph algorithms and Mermaid rendering."""

import pytest

from ghidra_decomp.decompiler import (
    _callgraph_predecessors,
    _callgraph_successors,
    _condense_graph,
    _find_all_paths,
    _find_endpoints,
    _is_reachable,
    _mermaid_escape,
    _mermaid_node_id,
    _neighborhood_bfs,
    _render_mermaid_condensed,
    _render_mermaid_function,
    _render_mermaid_neighborhood,
    _render_mermaid_paths,
    _render_mermaid_whole,
    _resolve_function,
)


def _call(target_addr, target_name="target"):
    return {
        "call_site": "00000000",
        "target_address": target_addr,
        "target_function_address": target_addr,
        "target_name": target_name,
        "reference_type": "UNCONDITIONAL_CALL",
        "address": target_addr,
        "name": target_name,
    }


def _entry(name, address, calls=None, called_by=None):
    return {
        "name": name,
        "address": address,
        "calls": calls or [],
        "called_by": called_by or [],
    }


def _caller(address, name):
    return {
        "call_site": "00000000",
        "address": address,
        "name": name,
        "reference_type": "UNCONDITIONAL_CALL",
    }


# --- _mermaid_escape ---


@pytest.mark.parametrize(
    ("char", "expected"),
    [
        ('"', "#34;"),
        ("<", "#60;"),
        (">", "#62;"),
        ("&", "#38;"),
        ("|", "#124;"),
        ("{", "#123;"),
        ("}", "#125;"),
        ("(", "#40;"),
        (")", "#41;"),
    ],
)
def test_mermaid_escape_special_chars(char, expected):
    assert expected in _mermaid_escape(char)


def test_mermaid_escape_preserves_normal_text():
    assert _mermaid_escape("main") == "main"


# --- _mermaid_node_id ---


def test_mermaid_node_id_alphanumeric():
    assert _mermaid_node_id("00101234") == "00101234"


def test_mermaid_node_id_replaces_special():
    result = _mermaid_node_id("EXTERNAL:00000001")
    assert ":" not in result
    assert result == "EXTERNAL_00000001"


# --- _render_mermaid_whole ---


def test_render_empty_graph():
    assert _render_mermaid_whole({}) == "flowchart TD\n"


def test_render_single_node_no_edges():
    graph = {"001": _entry("main", "001")}
    result = _render_mermaid_whole(graph)
    assert "flowchart TD" in result
    assert '"main"' in result
    assert "-->" not in result


def test_render_linear_chain():
    graph = {
        "001": _entry("A", "001", calls=[_call("002", "B")]),
        "002": _entry("B", "002", calls=[_call("003", "C")]),
        "003": _entry("C", "003"),
    }
    result = _render_mermaid_whole(graph)
    lines = result.strip().split("\n")
    edge_lines = [l for l in lines if "-->" in l]
    assert len(edge_lines) == 2


def test_render_diamond():
    graph = {
        "001": _entry("A", "001", calls=[_call("002", "B"), _call("003", "C")]),
        "002": _entry("B", "002", calls=[_call("004", "D")]),
        "003": _entry("C", "003", calls=[_call("004", "D")]),
        "004": _entry("D", "004"),
    }
    result = _render_mermaid_whole(graph)
    edge_lines = [l for l in result.strip().split("\n") if "-->" in l]
    assert len(edge_lines) == 4


def test_render_self_loop():
    graph = {
        "001": _entry("recurse", "001", calls=[_call("001", "recurse")]),
    }
    result = _render_mermaid_whole(graph)
    assert "001 --> 001" in result


def test_render_deduplicates_edges():
    graph = {
        "001": _entry(
            "A",
            "001",
            calls=[_call("002", "B"), _call("002", "B")],
        ),
        "002": _entry("B", "002"),
    }
    result = _render_mermaid_whole(graph)
    edge_lines = [l for l in result.strip().split("\n") if "-->" in l]
    assert len(edge_lines) == 1


def test_render_skips_external_targets():
    graph = {
        "001": _entry("A", "001", calls=[_call("999", "external")]),
    }
    result = _render_mermaid_whole(graph)
    assert "-->" not in result


def test_render_deterministic():
    graph = {
        "003": _entry("C", "003"),
        "001": _entry("A", "001", calls=[_call("002", "B")]),
        "002": _entry("B", "002", calls=[_call("003", "C")]),
    }
    assert _render_mermaid_whole(graph) == _render_mermaid_whole(graph)


# --- _render_mermaid_function ---


def test_render_function_neighborhood():
    graph = {
        "001": _entry("caller", "001", calls=[_call("002", "focus")]),
        "002": _entry(
            "focus",
            "002",
            calls=[_call("003", "callee")],
            called_by=[_caller("001", "caller")],
        ),
        "003": _entry("callee", "003"),
    }
    result = _render_mermaid_function(graph, "002")
    assert '"caller"' in result
    assert '"callee"' in result
    assert '"focus"' in result


def test_render_function_focus_class():
    graph = {"001": _entry("main", "001")}
    result = _render_mermaid_function(graph, "001")
    assert ":::focus" in result
    assert "classDef focus" in result


def test_render_special_char_name():
    graph = {"001": _entry("operator<<", "001")}
    result = _render_mermaid_whole(graph)
    assert "operator" in result
    assert "<<" not in result


# ── Shared test graph fixtures ───────────────────────────────────────

CHAIN = {
    "001": _entry("A", "001", calls=[_call("002", "B")]),
    "002": _entry(
        "B", "002", calls=[_call("003", "C")], called_by=[_caller("001", "A")]
    ),
    "003": _entry("C", "003", called_by=[_caller("002", "B")]),
}
DIAMOND = {
    "001": _entry("A", "001", calls=[_call("002", "B"), _call("003", "C")]),
    "002": _entry(
        "B", "002", calls=[_call("004", "D")], called_by=[_caller("001", "A")]
    ),
    "003": _entry(
        "C", "003", calls=[_call("004", "D")], called_by=[_caller("001", "A")]
    ),
    "004": _entry("D", "004", called_by=[_caller("002", "B"), _caller("003", "C")]),
}
CYCLE = {
    "001": _entry(
        "A", "001", calls=[_call("002", "B")], called_by=[_caller("002", "B")]
    ),
    "002": _entry(
        "B", "002", calls=[_call("001", "A")], called_by=[_caller("001", "A")]
    ),
}
DISCONNECTED = {
    "001": _entry("A", "001"),
    "002": _entry("B", "002"),
}


# ── _callgraph_successors ───────────────────────────────────────────


def test_successors_empty_graph():
    assert list(_callgraph_successors({}, "001")) == []


def test_successors_no_calls():
    assert list(_callgraph_successors({"001": _entry("A", "001")}, "001")) == []


def test_successors_chain():
    assert list(_callgraph_successors(CHAIN, "001")) == ["002"]


def test_successors_filters_external():
    graph = {"001": _entry("A", "001", calls=[_call("999", "ext")])}
    assert list(_callgraph_successors(graph, "001")) == []


def test_successors_fallback_target_address():
    call = {
        "call_site": "00000000",
        "target_address": "002",
        "target_function_address": None,
        "target_name": "B",
        "reference_type": "UNCONDITIONAL_CALL",
        "address": "002",
        "name": "B",
    }
    graph = {
        "001": _entry("A", "001", calls=[call]),
        "002": _entry("B", "002"),
    }
    assert list(_callgraph_successors(graph, "001")) == ["002"]


# ── _callgraph_predecessors ─────────────────────────────────────────


def test_predecessors_empty():
    assert list(_callgraph_predecessors({}, "001")) == []


def test_predecessors_yields_caller():
    graph = {
        "001": _entry("A", "001"),
        "002": _entry("B", "002", called_by=[_caller("001", "A")]),
    }
    assert list(_callgraph_predecessors(graph, "002")) == ["001"]


def test_predecessors_filters_external():
    graph = {"001": _entry("A", "001", called_by=[_caller("999", "ext")])}
    assert list(_callgraph_predecessors(graph, "001")) == []


# ── _resolve_function ────────────────────────────────────────────────


def test_resolve_exact_address():
    assert _resolve_function(CHAIN, "001") == "001"


def test_resolve_by_name():
    assert _resolve_function(CHAIN, "B") == "002"


def test_resolve_not_found():
    with pytest.raises(ValueError, match="not found"):
        _resolve_function(CHAIN, "Z")


def test_resolve_ambiguous():
    graph = {
        "001": _entry("dup", "001"),
        "002": _entry("dup", "002"),
    }
    with pytest.raises(ValueError, match="Ambiguous"):
        _resolve_function(graph, "dup")


def test_resolve_address_preferred_over_name():
    graph = {
        "001": _entry("002", "001"),
        "002": _entry("B", "002"),
    }
    assert _resolve_function(graph, "002") == "002"


# ── _is_reachable ───────────────────────────────────────────────────


def test_reachable_chain_forward():
    assert _is_reachable(CHAIN, "001", "003") is True


def test_reachable_chain_backward_fails():
    assert _is_reachable(CHAIN, "003", "001") is False


def test_reachable_self():
    assert _is_reachable(CHAIN, "001", "001") is True


def test_reachable_missing_source():
    assert _is_reachable(CHAIN, "999", "001") is False


def test_reachable_missing_dest():
    assert _is_reachable(CHAIN, "001", "999") is False


def test_reachable_cycle_no_hang():
    assert _is_reachable(CYCLE, "001", "002") is True


def test_reachable_diamond():
    assert _is_reachable(DIAMOND, "001", "004") is True


def test_reachable_disconnected():
    assert _is_reachable(DISCONNECTED, "001", "002") is False


# ── _find_all_paths ──────────────────────────────────────────────────


def test_paths_chain():
    paths = _find_all_paths(CHAIN, "001", "003")
    assert paths == [["001", "002", "003"]]


def test_paths_diamond():
    paths = _find_all_paths(DIAMOND, "001", "004")
    assert len(paths) == 2
    assert ["001", "002", "004"] in paths
    assert ["001", "003", "004"] in paths


def test_paths_no_path():
    assert _find_all_paths(DISCONNECTED, "001", "002") == []


def test_paths_self():
    assert _find_all_paths(CHAIN, "001", "001") == [["001"]]


def test_paths_max_depth():
    paths = _find_all_paths(CHAIN, "001", "003", max_depth=1)
    assert paths == []


def test_paths_cycle_no_hang():
    paths = _find_all_paths(CYCLE, "001", "002")
    assert paths == [["001", "002"]]


def test_paths_missing():
    assert _find_all_paths(CHAIN, "999", "001") == []


# ── _find_endpoints ──────────────────────────────────────────────────


def test_endpoints_chain():
    ep = _find_endpoints(CHAIN)
    assert [r["name"] for r in ep["roots"]] == ["A"]
    assert [l["name"] for l in ep["leaves"]] == ["C"]


def test_endpoints_diamond():
    ep = _find_endpoints(DIAMOND)
    assert [r["name"] for r in ep["roots"]] == ["A"]
    assert [l["name"] for l in ep["leaves"]] == ["D"]


def test_endpoints_isolated():
    graph = {"001": _entry("alone", "001")}
    ep = _find_endpoints(graph)
    assert len(ep["roots"]) == 1
    assert len(ep["leaves"]) == 1
    assert ep["roots"][0]["name"] == "alone"
    assert ep["leaves"][0]["name"] == "alone"


def test_endpoints_empty():
    ep = _find_endpoints({})
    assert ep == {"roots": [], "leaves": []}


# ── _neighborhood_bfs ────────────────────────────────────────────────


def test_neighborhood_depth_1():
    visited, _edges = _neighborhood_bfs(CHAIN, "002", depth=1)
    assert "002" in visited
    assert "001" in visited or "003" in visited


def test_neighborhood_depth_2_reaches_more():
    v1, _ = _neighborhood_bfs(CHAIN, "002", depth=1)
    v2, _ = _neighborhood_bfs(CHAIN, "002", depth=2)
    assert len(v2) >= len(v1)


def test_neighborhood_cycle_no_hang():
    visited, _edges = _neighborhood_bfs(CYCLE, "001", depth=5)
    assert len(visited) == 2


def test_neighborhood_edges():
    _, edges = _neighborhood_bfs(CHAIN, "002", depth=1)
    assert ("001", "002") in edges or ("002", "003") in edges


# ── _condense_graph ──────────────────────────────────────────────────


def test_condense_below_threshold():
    assert _condense_graph(CHAIN, threshold=100) is None


def _big_chain(n=20):
    big = {}
    for i in range(n):
        addr = f"{i:03d}"
        calls = [_call(f"{i + 1:03d}", f"F{i + 1}")] if i < n - 1 else []
        cb = [_caller(f"{i - 1:03d}", f"F{i - 1}")] if i > 0 else []
        big[addr] = _entry(f"F{i}", addr, calls=calls, called_by=cb)
    return big


def test_condense_above_threshold():
    big = _big_chain(20)
    result = _condense_graph(big, threshold=5)
    assert result is not None
    assert result["hidden_count"] > 0
    assert "hidden" in result["placeholder"]


def test_condense_preserves_roots():
    big = _big_chain(20)
    result = _condense_graph(big, threshold=5)
    assert "000" in result["kept"]


# ── _render_mermaid_paths ────────────────────────────────────────────


def test_render_paths_classes():
    paths = [["001", "002", "003"]]
    result = _render_mermaid_paths(CHAIN, paths)
    assert ":::source" in result
    assert ":::dest" in result
    assert "classDef source" in result
    assert "classDef dest" in result


def test_render_paths_multiple():
    paths = [["001", "002", "004"], ["001", "003", "004"]]
    result = _render_mermaid_paths(DIAMOND, paths)
    edge_lines = [l for l in result.strip().split("\n") if "-->" in l]
    assert len(edge_lines) == 4


def test_render_paths_empty():
    result = _render_mermaid_paths(CHAIN, [])
    assert result == "flowchart TD\n"


# ── _render_mermaid_neighborhood ─────────────────────────────────────


def test_render_neighborhood_focus():
    result = _render_mermaid_neighborhood(CHAIN, "002", depth=1)
    assert ":::focus" in result
    assert "classDef focus" in result


def test_render_neighborhood_depth2_more_nodes():
    r1 = _render_mermaid_neighborhood(CHAIN, "002", depth=1)
    r2 = _render_mermaid_neighborhood(CHAIN, "002", depth=2)
    assert len(r2) >= len(r1)


# ── _render_mermaid_condensed ────────────────────────────────────────


def test_render_condensed_has_placeholder():
    big = _big_chain(20)
    condensed = _condense_graph(big, threshold=5)
    result = _render_mermaid_condensed(big, condensed)
    assert "HIDDEN" in result
    assert "hidden" in result
    assert "classDef hidden" in result
