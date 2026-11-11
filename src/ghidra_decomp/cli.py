"""CLI entry point for ghidra-decomp."""

import json
from pathlib import Path

import click

from .decompiler import (
    _find_all_paths,
    _find_endpoints,
    _is_reachable,
    _resolve_function,
    decompile_binary,
    list_languages,
)

# ── Export command (the main command) ────────────────────────────────


@click.command()
@click.argument(
    "binary",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=False,
)
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=None,
    help="Output directory. Defaults to <binary_name>_decomp/",
)
@click.option(
    "--timeout",
    type=click.IntRange(min=1),
    default=60,
    show_default=True,
    help="Decompilation timeout per function (seconds).",
)
@click.option(
    "--combined",
    is_flag=True,
    default=False,
    help="Also emit all_functions.c containing every function.",
)
@click.option(
    "--ghidra-path",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    envvar="GHIDRA_INSTALL_DIR",
    default=None,
    help="Path to Ghidra installation. Falls back to GHIDRA_INSTALL_DIR env var.",
)
@click.option(
    "--base-addr",
    type=str,
    default=None,
    help="Rebase the binary to this address before analysis (e.g. 0x80000000).",
)
@click.option(
    "--entry",
    type=str,
    default=None,
    help="Mark this address as the program entry point and disassemble from it "
    "before analysis (e.g. 0x31000). Useful for raw binaries.",
)
@click.option(
    "--language",
    type=str,
    default=None,
    help="Force Ghidra language/processor ID (e.g. ARM:LE:32:v7). "
    "Use when auto-detect fails. See --list-languages.",
)
@click.option(
    "--compiler",
    type=str,
    default=None,
    help="Force compiler spec ID (e.g. gcc, default, windows). "
    "Requires --language. See --list-languages.",
)
@click.option(
    "--list-languages",
    "list_langs",
    is_flag=True,
    default=False,
    help="List all available Ghidra language IDs and their compiler specs, then exit.",
)
@click.option(
    "--resume",
    is_flag=True,
    default=False,
    help="Reuse per-function artifacts from an existing output whose hashes "
    "still match, re-running only missing, failed, and fallback functions.",
)
@click.option(
    "--workers",
    type=click.IntRange(min=1),
    default=None,
    help="Number of decompiler threads. Defaults to min(4, CPU count); JVM "
    "memory, not CPU count, is usually the limit.",
)
@click.option(
    "--include",
    multiple=True,
    help="Export only functions whose name matches this regular expression. "
    "Repeatable; a function matching any pattern is kept.",
)
@click.option(
    "--exclude",
    multiple=True,
    help="Skip functions whose name matches this regular expression. "
    "Repeatable; applied after --include.",
)
@click.option(
    "--gdt",
    multiple=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Apply a Ghidra data type archive (.gdt) before analysis. Repeatable; "
    "changes the analysis fingerprint.",
)
@click.option(
    "--pdb",
    type=str,
    default=None,
    help="PDB symbol source: 'auto' (fetch from symbol server), "
    "'none' (suppress detection), or a local file path. "
    "Default: detect and prompt interactively.",
)
@click.option(
    "--gzf",
    is_flag=True,
    default=False,
    help="Also export program.gzf so the analyzed program can be reopened in "
    "the Ghidra GUI.",
)
@click.option(
    "--semgrep-config",
    "semgrep_config",
    default=None,
    help="Scan the exported pseudocode with semgrep after the corpus is built "
    "and write semgrep.sarif (e.g. 'auto' or a rules path).",
)
@click.option(
    "--function",
    multiple=True,
    help="Export the function at this entry address regardless of name "
    "filters (e.g. 00101234). Repeatable.",
)
@click.option(
    "--verbose-analysis",
    is_flag=True,
    default=False,
    help="Attach a console monitor to auto-analysis so progress is printed.",
)
@click.option(
    "--mermaid",
    is_flag=True,
    default=False,
    help="Render the call graph as Mermaid flowcharts in callgraphs/.",
)
@click.option(
    "--cpp-export",
    is_flag=True,
    default=False,
    help="Export a single C source file and header via Ghidra's CppExporter.",
)
@click.option(
    "--max-ram-percent",
    type=click.FloatRange(min=1.0, max=100.0),
    default=50.0,
    show_default=True,
    help="JVM MaxRAMPercentage for heap sizing (1.0-100.0).",
)
@click.option(
    "--print-jvm-flags",
    is_flag=True,
    default=False,
    help="Print JVM flag values at startup (-XX:+PrintFlagsFinal).",
)
@click.option(
    "--callgraph-depth",
    type=click.IntRange(min=1, max=10),
    default=1,
    show_default=True,
    help="Neighborhood hops for per-function Mermaid callgraphs.",
)
@click.option(
    "--condense-threshold",
    type=click.IntRange(min=1),
    default=None,
    help="Collapse Mermaid whole-graph when edges exceed this count.",
)
@click.option(
    "--reachable",
    nargs=2,
    type=str,
    default=None,
    metavar="FROM TO",
    help="Check if FROM can reach TO in the call graph.",
)
@click.option(
    "--no-polish",
    "no_polish",
    is_flag=True,
    default=False,
    help="Skip post-processing that cleans up decompiled pseudocode.",
)
def main(
    binary: Path | None,
    output: Path | None,
    timeout: int,
    combined: bool,
    ghidra_path: Path | None,
    base_addr: str | None,
    entry: str | None,
    language: str | None,
    compiler: str | None,
    list_langs: bool,
    resume: bool,
    workers: int | None,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    function: tuple[str, ...],
    gdt: tuple[Path, ...],
    pdb: str | None,
    gzf: bool,
    semgrep_config: str | None,
    verbose_analysis: bool,
    mermaid: bool,
    cpp_export: bool,
    max_ram_percent: float,
    print_jvm_flags: bool,
    callgraph_depth: int,
    condense_threshold: int | None,
    reachable: tuple[str, str] | None,
    no_polish: bool,
):
    """Decompile BINARY into a browsable source tree.

    Produces one .c file per function, plus JSON indexes for strings,
    call graph, imports, and exports.
    """
    if list_langs:
        list_languages(ghidra_path=ghidra_path)
        return

    if binary is None:
        raise click.UsageError("Missing argument 'BINARY'.")

    if compiler is not None and language is None:
        raise click.UsageError("--compiler requires --language.")

    binary = binary.resolve()
    if output is None:
        output = Path.cwd() / f"{binary.stem}_decomp"

    output = output.resolve()

    click.echo(f"Binary:  {binary}")
    click.echo(f"Output:  {output}")
    if base_addr is not None:
        click.echo(f"Base:    {base_addr}")
    if entry is not None:
        click.echo(f"Entry:   {entry}")
    if language is not None:
        click.echo(f"Lang:    {language}")
    if compiler is not None:
        click.echo(f"CSpec:   {compiler}")
    if pdb is not None:
        click.echo(f"PDB:     {pdb}")

    decompile_binary(
        binary,
        output,
        timeout=timeout,
        combined=combined,
        ghidra_path=ghidra_path,
        base_addr=base_addr,
        entry=entry,
        language=language,
        compiler=compiler,
        resume=resume,
        workers=workers,
        include=include,
        exclude=exclude,
        function=function,
        gdt=tuple(str(path) for path in gdt),
        pdb=pdb,
        gzf=gzf,
        semgrep_config=semgrep_config,
        verbose_analysis=verbose_analysis,
        mermaid=mermaid,
        cpp_export=cpp_export,
        max_ram_percent=max_ram_percent,
        print_jvm_flags=print_jvm_flags,
        callgraph_depth=callgraph_depth,
        condense_threshold=condense_threshold,
        reachable=reachable,
        polish=not no_polish,
    )

    click.echo(f"\nDone. Output at: {output}")


# ── Query command (standalone, no Ghidra) ────────────────────────────


def _load_callgraph(output_dir: Path) -> dict:
    cg_path = output_dir / "callgraph.json"
    if not cg_path.is_file():
        raise click.ClickException(f"No callgraph.json in {output_dir}")
    return json.loads(cg_path.read_text(encoding="utf-8"))


@click.group()
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
    src = _resolve_function(callgraph, source)
    dst = _resolve_function(callgraph, dest)
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
    src = _resolve_function(callgraph, source)
    dst = _resolve_function(callgraph, dest)
    paths = _find_all_paths(callgraph, src, dst, max_depth=max_depth)
    click.echo(
        f"{len(paths)} path(s) from {callgraph[src]['name']}"
        f" to {callgraph[dst]['name']}:"
    )
    for p in paths:
        click.echo("  " + " -> ".join(callgraph[a]["name"] for a in p))


if __name__ == "__main__":
    main()
