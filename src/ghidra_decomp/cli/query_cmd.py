"""Query command group (standalone, no Ghidra needed)."""

import json
from pathlib import Path

import click

from .. import __version__
from ..decompiler import (
    _find_all_paths,
    _find_endpoints,
    _is_reachable,
    _resolve_function,
)


def _load_callgraph(output_dir: Path) -> dict:
    cg_path = output_dir / "callgraph.json"
    if not cg_path.is_file():
        raise click.ClickException(f"No callgraph.json in {output_dir}")
    return json.loads(cg_path.read_text(encoding="utf-8"))


def _resolve_or_fail(callgraph: dict, identifier: str) -> str:
    try:
        return _resolve_function(callgraph, identifier)
    except ValueError as error:
        raise click.ClickException(str(error)) from error


@click.group()
@click.version_option(version=__version__, prog_name="ghidra-decomp-query")
def query():
    """Query a previously exported callgraph (no Ghidra needed)."""


@query.command("reachable")
@click.argument(
    "output_dir", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.argument("source")
@click.argument("dest")
def query_reachable(output_dir: Path, source: str, dest: str):
    """Check if SOURCE can reach DEST in the call graph."""
    callgraph = _load_callgraph(output_dir)
    src = _resolve_or_fail(callgraph, source)
    dst = _resolve_or_fail(callgraph, dest)
    reached = _is_reachable(callgraph, src, dst)
    paths = _find_all_paths(callgraph, src, dst) if reached else []
    if reached:
        click.echo(
            f"Reachable: {callgraph[src]['name']} -> {callgraph[dst]['name']}"
            f" ({len(paths)} path(s))"
        )
        for p in paths[:10]:
            click.echo("  " + " -> ".join(callgraph[a]["name"] for a in p))
        if len(paths) > 10:
            click.echo(f"  ... and {len(paths) - 10} more")
    else:
        click.echo(
            f"Not reachable: {callgraph[src]['name']} -> {callgraph[dst]['name']}"
        )


@query.command("endpoints")
@click.argument(
    "output_dir", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
def query_endpoints(output_dir: Path):
    """Find root and leaf functions in the call graph."""
    callgraph = _load_callgraph(output_dir)
    ep = _find_endpoints(callgraph)
    click.echo(f"Roots ({len(ep['roots'])}):")
    for r in ep["roots"]:
        click.echo(f"  {r['address']}  {r['name']}")
    click.echo(f"Leaves ({len(ep['leaves'])}):")
    for item in ep["leaves"]:
        click.echo(f"  {item['address']}  {item['name']}")


@query.command("paths")
@click.argument(
    "output_dir", type=click.Path(exists=True, file_okay=False, path_type=Path)
)
@click.argument("source")
@click.argument("dest")
@click.option(
    "--max-depth", type=int, default=50, show_default=True, help="Maximum path depth."
)
def query_paths(output_dir: Path, source: str, dest: str, max_depth: int):
    """Find all paths from SOURCE to DEST in the call graph."""
    callgraph = _load_callgraph(output_dir)
    src = _resolve_or_fail(callgraph, source)
    dst = _resolve_or_fail(callgraph, dest)
    paths = _find_all_paths(callgraph, src, dst, max_depth=max_depth)
    click.echo(
        f"{len(paths)} path(s) from {callgraph[src]['name']}"
        f" to {callgraph[dst]['name']}:"
    )
    for p in paths:
        click.echo("  " + " -> ".join(callgraph[a]["name"] for a in p))
