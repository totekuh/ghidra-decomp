"""CLI entry point for ghidra-decomp."""

import click
from pathlib import Path

from .decompiler import decompile_binary


@click.command()
@click.argument("binary", type=click.Path(exists=True, dir_okay=False, path_type=Path))
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
@click.option(
    "--base-addr",
    type=str,
    default=None,
    help="Rebase the binary to this address before exporting (e.g. 0x80000000).",
)
def main(binary: Path, output: Path | None, timeout: int, ghidra_path: Path | None, base_addr: str | None):
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
    if base_addr is not None:
        click.echo(f"Base:    {base_addr}")

    decompile_binary(binary, output, timeout=timeout, ghidra_path=ghidra_path, base_addr=base_addr)

    click.echo(f"\nDone. Output at: {output}")


if __name__ == "__main__":
    main()
