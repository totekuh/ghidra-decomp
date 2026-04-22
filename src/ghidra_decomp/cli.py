"""CLI entry point for ghidra-decomp."""

import click
from pathlib import Path

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
    type=int,
    default=60,
    show_default=True,
    help="Decompilation timeout per function (seconds).",
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
def main(
    binary: Path | None,
    output: Path | None,
    timeout: int,
    ghidra_path: Path | None,
    base_addr: str | None,
    entry: str | None,
    language: str | None,
    compiler: str | None,
    list_langs: bool,
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

    decompile_binary(
        binary,
        output,
        timeout=timeout,
        ghidra_path=ghidra_path,
        base_addr=base_addr,
        entry=entry,
        language=language,
        compiler=compiler,
    )

    click.echo(f"\nDone. Output at: {output}")


if __name__ == "__main__":
    main()
