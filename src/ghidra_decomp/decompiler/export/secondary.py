"""Secondary export helpers: GZF, CppExporter, semgrep."""

from __future__ import annotations

from pathlib import Path

import click


def _export_gzf(program, destination: Path) -> None:
    """Write a Ghidra zip file so the analyzed program can be reopened in the GUI.

    `DomainFile.packFile` is used rather than `GzfExporter`. Auto-analysis leaves
    a database transaction open for the lifetime of the program, and the
    exporter's own locking rejects that with "Unable to lock due to active
    transaction"; packing the domain file does not take that lock.
    """
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File as JavaFile

    domain_file = program.getDomainFile()
    if domain_file is None:
        raise click.ClickException(
            "The program has no domain file, so no GZF export is possible."
        )
    try:
        domain_file.packFile(JavaFile(str(destination)), ConsoleTaskMonitor())
    except Exception as e:  # noqa: BLE001 - Java exceptions have no stable base class
        raise click.ClickException(f"Ghidra could not write {destination}: {e}")


def _export_cpp(program, destination: Path) -> None:
    """Export a single C file and header via Ghidra's CppExporter."""
    from ghidra.app.util.exporter import CppExporter
    from ghidra.util.task import ConsoleTaskMonitor
    from java.io import File as JavaFile

    monitor = ConsoleTaskMonitor()
    exporter = CppExporter()

    click.echo("Exporting C/header via CppExporter...")
    exporter.export(JavaFile(str(destination)), program, program.getMemory(), monitor)


def _run_semgrep(config: str, corpus: Path, destination: Path) -> dict:
    """Scan the exported pseudocode, writing SARIF beside the corpus.

    A scan failure is reported but never invalidates the corpus: the pseudocode
    is the product, and the scan is a secondary view of it.
    """
    import subprocess

    command = [
        "semgrep",
        "scan",
        "--config",
        config,
        "--sarif",
        "--sarif-output",
        str(destination),
        "--quiet",
        str(corpus / "functions"),
    ]
    click.echo(f"Scanning pseudocode with semgrep --config {config}")
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError:
        raise click.ClickException(
            "semgrep is not installed. Install it with: pip install semgrep"
        )
    if not destination.is_file():
        raise click.ClickException(
            f"semgrep produced no SARIF output (exit {result.returncode}):\n"
            f"{result.stderr.strip()}"
        )
    return {"config": config, "exit_code": result.returncode}
