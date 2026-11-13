"""End-to-end tests for ``ghidra-decomp-query`` against a live export.

Each fixture binary is decompiled in-process through ``decompile_binary``
(embedded Ghidra, no subprocess), and the ``query`` click group is then driven
through ``CliRunner`` against the real ``callgraph.json`` it produced.

The expected graph comes from tests/fixtures/callgraph_test.c: a diamond
(merge_point -> mid_alpha/mid_beta -> leaves), a four-deep chain
(chain_a..chain_d -> leaf_add), a ping/pong cycle, and an isolated node, all
reached from ``entry``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from conftest import FIXTURES, require_ghidra

from ghidra_decomp.cli import query
from ghidra_decomp.decompiler import decompile_binary


@pytest.fixture(scope="module", params=["callgraph_x86_64", "callgraph_x86_32"])
def export_dir(request, tmp_path_factory) -> Path:
    """Decompile one callgraph fixture in-process and return its output dir."""
    ghidra_path = require_ghidra()
    output = tmp_path_factory.mktemp(request.param) / "corpus"
    decompile_binary(
        FIXTURES / request.param,
        output,
        ghidra_path=ghidra_path,
        timeout=30,
    )
    assert (output / "callgraph.json").is_file()
    return output


@pytest.fixture(scope="module")
def addresses(export_dir) -> dict[str, str]:
    callgraph = json.loads((export_dir / "callgraph.json").read_text("utf-8"))
    return {entry["name"]: address for address, entry in callgraph.items()}


def _run(*arguments: str | Path, exit_code: int = 0) -> str:
    result = CliRunner().invoke(query, [str(a) for a in arguments])
    assert result.exit_code == exit_code, (
        f"query {arguments} exited {result.exit_code}:\n{result.output}"
        f"\n{result.exception!r}"
    )
    return result.output


def _path_lines(output: str) -> set[str]:
    return {line.strip() for line in output.splitlines()[1:] if line.strip()}


# ── endpoints ────────────────────────────────────────────────────────


def test_endpoints_lists_entry_as_the_only_root(export_dir, addresses):
    output = _run("endpoints", export_dir)

    lines = output.splitlines()
    leaves_at = lines.index("Leaves (4):")
    assert lines[0] == "Roots (1):"
    assert lines[1:leaves_at] == [f"  {addresses['entry']}  entry"]


def test_endpoints_lists_every_function_without_callees_as_a_leaf(
    export_dir, addresses
):
    output = _run("endpoints", export_dir)

    lines = output.splitlines()
    leaves = set(lines[lines.index("Leaves (4):") + 1 :])
    assert leaves == {
        f"  {addresses[name]}  {name}"
        for name in ("leaf_hash", "leaf_add", "leaf_xor", "isolated_node")
    }


# ── reachable ────────────────────────────────────────────────────────


def test_reachable_through_the_diamond_reports_both_branches(export_dir):
    output = _run("reachable", export_dir, "entry", "leaf_hash")

    assert output.splitlines()[0] == "Reachable: entry -> leaf_hash (2 path(s))"
    assert _path_lines(output) == {
        "entry -> merge_point -> mid_alpha -> leaf_hash",
        "entry -> merge_point -> mid_beta -> leaf_hash",
    }


def test_reachable_follows_the_deep_chain(export_dir):
    output = _run("reachable", export_dir, "chain_a", "leaf_add")

    assert output.splitlines() == [
        "Reachable: chain_a -> leaf_add (1 path(s))",
        "  chain_a -> chain_b -> chain_c -> chain_d -> leaf_add",
    ]


def test_reachable_is_directional(export_dir):
    output = _run("reachable", export_dir, "leaf_hash", "entry")

    assert output.strip() == "Not reachable: leaf_hash -> entry"


def test_isolated_node_reaches_nothing(export_dir):
    output = _run("reachable", export_dir, "isolated_node", "leaf_add")

    assert output.strip() == "Not reachable: isolated_node -> leaf_add"


def test_reachable_accepts_addresses(export_dir, addresses):
    output = _run(
        "reachable", export_dir, addresses["merge_point"], addresses["leaf_xor"]
    )

    assert output.splitlines() == [
        "Reachable: merge_point -> leaf_xor (1 path(s))",
        "  merge_point -> mid_beta -> leaf_xor",
    ]


def test_reachable_terminates_on_the_ping_pong_cycle(export_dir):
    forward = _run("reachable", export_dir, "ping", "pong")
    backward = _run("reachable", export_dir, "pong", "ping")

    assert forward.splitlines()[0] == "Reachable: ping -> pong (1 path(s))"
    assert backward.splitlines()[0] == "Reachable: pong -> ping (1 path(s))"


def test_reachable_unknown_function_is_a_clean_error(export_dir):
    output = _run("reachable", export_dir, "entry", "no_such_function", exit_code=1)

    assert "Error: Function not found: 'no_such_function'" in output
    assert "Traceback" not in output


# ── paths ────────────────────────────────────────────────────────────


def test_paths_enumerates_every_route_to_a_shared_leaf(export_dir):
    output = _run("paths", export_dir, "entry", "leaf_add")

    assert output.splitlines()[0] == "3 path(s) from entry to leaf_add:"
    assert _path_lines(output) == {
        "entry -> merge_point -> mid_alpha -> leaf_add",
        "entry -> chain_a -> chain_b -> chain_c -> chain_d -> leaf_add",
        "entry -> ping -> pong -> leaf_add",
    }


def test_paths_max_depth_prunes_the_deep_chain(export_dir):
    output = _run("paths", export_dir, "entry", "leaf_add", "--max-depth", "3")

    assert output.splitlines()[0] == "2 path(s) from entry to leaf_add:"
    assert _path_lines(output) == {
        "entry -> merge_point -> mid_alpha -> leaf_add",
        "entry -> ping -> pong -> leaf_add",
    }


def test_paths_reports_zero_when_unreachable(export_dir):
    output = _run("paths", export_dir, "leaf_add", "entry")

    assert output.strip() == "0 path(s) from leaf_add to entry:"


def test_paths_unknown_function_is_a_clean_error(export_dir):
    output = _run("paths", export_dir, "no_such_function", "entry", exit_code=1)

    assert "Error: Function not found: 'no_such_function'" in output
    assert "Traceback" not in output


# ── input validation ─────────────────────────────────────────────────


@pytest.mark.parametrize("command", ["endpoints", "reachable", "paths"])
def test_directory_without_callgraph_is_rejected(tmp_path, command):
    extra = [] if command == "endpoints" else ["entry", "leaf_add"]

    output = _run(command, tmp_path, *extra, exit_code=1)

    assert f"Error: No callgraph.json in {tmp_path}" in output
