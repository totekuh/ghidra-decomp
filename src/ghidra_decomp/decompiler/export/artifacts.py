"""Phase 2 of _export_all: write per-function artifacts and build records."""

from __future__ import annotations

import shutil
from pathlib import Path

import click

from ghidra_decomp.artifacts import (
    SCHEMA_VERSION,
    atomic_write_json,
    atomic_write_text,
    sha256_file,
)
from ghidra_decomp.decompiler.constants import (
    STATUS_FAILED,
    STATUS_FALLBACK,
    STATUS_SUCCESS,
)
from ghidra_decomp.decompiler.extract.functions import (
    _disassemble_function,
    _extract_function_record,
    _extract_function_references,
    _extract_strings,
    _extract_symbols,
)
from ghidra_decomp.decompiler.naming import _artifact_stem
from ghidra_decomp.decompiler.worker import (
    _decompiler_notes,
    _failure_comment,
    _func_header_comment,
)


def write_function_artifacts(
    program,
    functions: list,
    output: Path,
    outcomes: dict,
    *,
    pcode: bool,
    polish: bool,
    reusable: dict,
    resume_source: Path | None,
) -> tuple[list[dict], dict[str, dict], list[dict], dict[str, dict]]:
    """Write per-function .c/.s/.json files, return records and alloc data."""
    func_dir = output / "functions"
    assembly_dir = output / "assembly"

    strings = _extract_strings(program)
    symbols = _extract_symbols(program)
    string_addresses = {item["address"]: item for item in strings}
    symbol_addresses: dict[str, list[dict]] = {}
    for item in symbols:
        symbol_addresses.setdefault(item["address"], []).append(item)

    records: list[dict] = []
    record_by_address: dict[str, dict] = {}
    all_alloc_entries: list[dict] = []
    wrapper_candidates: dict[str, dict] = {}

    for func in functions:
        addr = func.getEntryPoint().toString()
        name = func.getName()
        stem = _artifact_stem(addr, name)
        c_path = func_dir / f"{stem}.c"
        assembly_path = assembly_dir / f"{stem}.s"
        pcode_path = func_dir / f"{stem}.pcode.json"

        reused = reusable.get(stem)
        if reused is not None and resume_source is not None:
            shutil.copyfile(resume_source / reused["artifacts"]["pseudocode"], c_path)
            shutil.copyfile(
                resume_source / reused["artifacts"]["assembly"], assembly_path
            )
            reused_pcode = reused["artifacts"].get("pcode")
            if reused_pcode is not None:
                shutil.copyfile(resume_source / reused_pcode, pcode_path)
            record = dict(reused)
            record["decompilation"] = {
                **record["decompilation"],
                "reused": True,
            }
            record["called_by"] = []
            records.append(record)
            record_by_address[addr] = record
            continue

        header = _func_header_comment(func)
        assembly = _disassemble_function(program, func)
        atomic_write_text(assembly_path, assembly)

        status: str
        error: str | None
        decompiled_locals: list[dict] = []
        pcode_payload: dict | None = None
        notes: list[dict] = []
        polished = False
        if not assembly:
            status = STATUS_FALLBACK
            error = "function contains no instructions"
            content = header + _failure_comment(error)
        else:
            (
                status,
                error,
                c_code,
                decompiled_locals,
                pcode_payload,
                alloc_entries,
                w_info,
            ) = outcomes[addr]
            if alloc_entries:
                all_alloc_entries.extend(alloc_entries)
            if w_info is not None:
                wrapper_candidates[name] = w_info
            notes = _decompiler_notes(c_code)
            polished = False
            if status == STATUS_SUCCESS and polish:
                from ghidra_decomp.polish import polish as polish_code

                c_code, polished = polish_code(c_code)
            if status == STATUS_SUCCESS:
                content = header + c_code
            else:
                if status == STATUS_FAILED:
                    click.echo(
                        f"\nWarning: could not decompile {name} at {addr}: {error}",
                        err=True,
                    )
                content = header + _failure_comment(error)

        atomic_write_text(c_path, content)
        pcode_artifacts: dict[str, str] = {}
        if pcode and pcode_payload is not None:
            atomic_write_json(pcode_path, pcode_payload)
            pcode_artifacts = {
                "pcode": str(pcode_path.relative_to(output)),
                "pcode_sha256": sha256_file(pcode_path),
            }
        references, calls = _extract_function_references(program, func)
        record = _extract_function_record(
            program, func, locals_=decompiled_locals or None
        )
        related_strings = {
            ref["to_address"]: string_addresses[ref["to_address"]]
            for ref in references
            if ref["to_address"] in string_addresses
        }
        related_globals = {
            (
                symbol["address"],
                symbol["name"],
                symbol["namespace"],
                symbol["type"],
            ): symbol
            for ref in references
            for symbol in symbol_addresses.get(ref["to_address"], ())
        }
        record.update(
            {
                "schema_version": SCHEMA_VERSION,
                "calls": calls,
                "called_by": [],
                "references": references,
                "strings": list(related_strings.values()),
                "globals": list(related_globals.values()),
                "artifacts": {
                    "pseudocode": str(c_path.relative_to(output)),
                    "pseudocode_sha256": sha256_file(c_path),
                    "assembly": str(assembly_path.relative_to(output)),
                    "assembly_sha256": sha256_file(assembly_path),
                    **pcode_artifacts,
                },
                "decompilation": {
                    "status": status,
                    "error": error,
                    "reused": False,
                    "warnings": notes,
                    "polished": polished,
                },
            }
        )
        records.append(record)
        record_by_address[addr] = record

    _backfill_callers(records, record_by_address)

    for record in records:
        sidecar_path = (
            output
            / "functions"
            / (f"{_artifact_stem(record['address'], record['name'])}.json")
        )
        record["artifacts"]["sidecar"] = str(sidecar_path.relative_to(output))
        atomic_write_json(sidecar_path, record)
        record["artifacts"]["sidecar_sha256"] = sha256_file(sidecar_path)

    return records, record_by_address, all_alloc_entries, wrapper_candidates


def _backfill_callers(records: list[dict], record_by_address: dict[str, dict]) -> None:
    """Populate called_by from calls, then deduplicate."""
    for caller in records:
        for call in caller["calls"]:
            target = record_by_address.get(
                call["target_function_address"] or call["target_address"]
            )
            if target is not None:
                target["called_by"].append(
                    {
                        "call_site": call["call_site"],
                        "address": caller["address"],
                        "name": caller["name"],
                        "reference_type": call["reference_type"],
                    }
                )

    for record in records:
        record["called_by"] = list(
            {
                (
                    item["call_site"],
                    item["address"],
                    item["reference_type"],
                ): item
                for item in record["called_by"]
            }.values()
        )
