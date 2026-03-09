"""CLI entry point for ghidra-decomp."""

import click
from pathlib import Path

from .decompiler import decompile_binary


@click.command()
@click.argument("binary", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-o", "--output",
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
    type=click.Path(exists=True, path_type=Path),
    envvar="GHIDRA_INSTALL_DIR",
    default=None,
    help="Path to Ghidra installation. Falls back to GHIDRA_INSTALL_DIR env var.",
)
def main(binary: Path, output: Path | None, timeout: int, ghidra_path: Path | None):
    """Decompile BINARY into a browsable source tree.

    Produces one .c file per function, plus JSON indexes for strings,
    call graph, imports, and exports.
    """
    binary = binary.resolve()
    if output is None:
        output = Path.cwd() / f"{binary.stem}_decomp"

    output = output.resolve()

    click.echo(f"Binary:  {binary}")
    click.echo(f"Output:  {output}")

    decompile_binary(binary, output, timeout=timeout, ghidra_path=ghidra_path)

    click.echo(f"\nDone. Output at: {output}")


if __name__ == "__main__":
    main()
