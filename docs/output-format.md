# Output format

## Function artifacts

Each `.c` file includes a metadata header. Its adjacent JSON sidecar records body
ranges, signature and variable storage, calls, references, related strings and
globals, decompilation status, artifact paths, and hashes. Assembly files contain
instruction addresses, raw bytes, mnemonics, and operands.

```c
// Function: parse_config
// Address:  00010234
// Size:     284 bytes
// Calling:  __stdcall
// Params:   3

void parse_config(char *param_1, int param_2, int param_3) {
    ...
}
```

Local variables come from the decompiler's own model, so the `uVar1` you read in the
pseudocode carries its type and storage. A thunk records the name and address of what
it forwards to, and the decompiler's own warnings — "Subroutine does not return",
"Unknown calling convention" — are structured under `decompilation.warnings` instead of
being left as prose inside the C:

```json
"is_thunk": true,
"thunk": {"name": "getenv", "address": "EXTERNAL:00000001"},
"decompilation": {
  "status": "success",
  "warnings": [{"kind": "warning", "text": "Subroutine does not return"}]
}
```

## Type records

Every type record says where it came from, how it is laid out, and who uses it, so a
consumer can tell a layout the compiler described from one Ghidra reconstructed off the
bytes before trusting an offset. `source_archive.archive_type` is `PROGRAM` for a type
recovered from this binary and `FILE` or `PROJECT` for one imported from an archive; on
`/usr/bin/true`, 11 of 28 types come from `generic_clib_64` and the other 17 from the
binary itself. `used_by` reaches back to the data and functions that use the type,
including through pointers and arrays, so `types.json` is not a dead end:

```json
{
  "kind": "struct",
  "name": "Elf32_Sym",
  "path": "/ELF/Elf32_Sym",
  "category_path": "/ELF",
  "alignment": {"value": 1, "type": "DEFAULT", "minimum": null},
  "packing": {"type": "DISABLED", "value": null},
  "source_archive": {"name": "binary", "archive_type": "PROGRAM"},
  "usage_count": 1,
  "usage_truncated": false,
  "used_by": [
    {
      "kind": "data",
      "address": ".symtab::00000000",
      "name": "Elf32_Sym_ARRAY_.symtab__00000000",
      "ordinal": null,
      "via": "Elf32_Sym[10]"
    }
  ]
}
```

`packing` and `alignment.type` are null for a kind with no members to pack. `via` is the
declaration at the use site, so a pointer or array use stays distinguishable from a
direct one. `usage_count` is always the true total; `used_by` is capped at 200 entries
and sets `usage_truncated` when it is cut, so a bounded list never reads as a small one.

## Filenames

Schema 6 artifact filenames include a stable digest and bounded ASCII components so
segmented addresses, long symbols, and platform-reserved names remain safe. Consumers
must follow the artifact paths in `functions.json` rather than constructing filenames.

## Manifest

`manifest.json` is the corpus completion marker. It fingerprints the snapshotted input
bytes and analysis configuration, records Ghidra/PyGhidra/tool versions, summarizes
function statuses, and hashes every generated index. Exports are built in a hidden
sibling staging directory whose `.run-state.json` marks that staging corpus incomplete.
The existing completed output remains untouched if analysis fails. Publication is
serialized by a destination lock and occurs only after the staged manifest, artifacts,
and indexes are durable.

## Timeout and failure

Each function receives at most the configured `--timeout`, never multiplied by worker
count or retries. A function that the decompiler declines is recorded as `fallback`; a
timeout or exception is recorded as `failed`, which `--resume` retries on a later run.
Either way the C artifact contains the error and the normal assembly artifact remains
available for analysis.

`successful`, `fallback`, and `failed` partition the discovered functions. `skipped`
counts the reused subset and overlaps them: it answers how much work a run avoided,
not how a function ended.
