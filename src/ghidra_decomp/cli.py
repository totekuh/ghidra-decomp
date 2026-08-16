"""CLI entry point for ghidra-decomp."""

from pathlib import Path

import click

from .decompiler import decompile_binary, list_languages


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
    "--no-cache",
    "no_cache",
    is_flag=True,
    default=False,
    help="Do not retain or reuse a Ghidra project. Every run re-imports and "
    "re-analyzes the binary.",
)
@click.option(
    "--cache-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Directory holding retained Ghidra projects. "
    "Defaults to $XDG_CACHE_HOME/ghidra-decomp.",
)
@click.option(
    "--resume",
    is_flag=True,
    default=False,
    help="Reuse per-function artifacts from an existing output whose hashes "
    "still match, re-running only missing, failed, and fallback functions.",
)
@click.option(
    "--force-analysis",
    "force_analysis",
    is_flag=True,
    default=False,
    help="Ignore any retained project and analyze the binary again.",
)
@click.option(
    "--force-export",
    "force_export",
    is_flag=True,
    default=False,
    help="Reuse the retained project but rebuild every artifact from scratch.",
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
    "changes the analysis, so it changes the cache key.",
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
    no_cache: bool,
    cache_dir: Path | None,
    resume: bool,
    force_analysis: bool,
    force_export: bool,
    workers: int | None,
    include: tuple[str, ...],
    exclude: tuple[str, ...],
    function: tuple[str, ...],
    gdt: tuple[Path, ...],
    gzf: bool,
    semgrep_config: str | None,
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

    if no_cache and cache_dir is not None:
        raise click.UsageError("--cache-dir cannot be combined with --no-cache.")

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
        cache_enabled=not no_cache,
        cache_dir=cache_dir,
        resume=resume,
        force_analysis=force_analysis,
        force_export=force_export,
        workers=workers,
        include=include,
        exclude=exclude,
        function=function,
        gdt=tuple(str(path) for path in gdt),
        gzf=gzf,
        semgrep_config=semgrep_config,
    )

    click.echo(f"\nDone. Output at: {output}")


if __name__ == "__main__":
    main()
