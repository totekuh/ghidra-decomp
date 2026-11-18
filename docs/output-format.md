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
  "polished": true,
  "warnings": [{"kind": "warning", "text": "Subroutine does not return"}]
}
```

`decompilation.polished` is `true` when the readability pipeline rewrote the
function's pseudocode and `false` under `--no-polish` or when a function fell
back to raw output. See [polish.md](polish.md).

## Pcode export (`--pcode`)

With `--pcode`, each function also gets a `<stem>.pcode.json` sidecar, registered
in the function record's `artifacts` map as `pcode`/`pcode_sha256` next to
`pseudocode` and `assembly`. It is large and off by default; it exists so a
data-flow consumer gets Ghidra's recovered facts directly instead of
re-deriving them from the C text or disassembly. The export emits facts only —
no sink list, no slicing, no bug judgement.

Everything is sourced from the decompiler's **high** function
(`HighFunction.getPcodeOps()`), so varnodes are recovered variables and constants
are folded. One envelope per function:

```json
{
  "schema_version": 7,
  "function": "RTMPDeFragmentDataFrame",
  "entry": "00087514",
  "body_ranges": [{"start": "00087514", "end": "000878ff"}],
  "arch": "MIPS:LE:32:default",
  "ops": [ ... ], "varnodes": [ ... ], "blocks": [ ... ],
  "calls": [ ... ], "locals": [ ... ], "rodata": [ ... ]
}
```

- **`ops`** — every SSA pcode op in program order. Each has a stable integer
  `seq`, the instruction `addr`, the exact Ghidra opcode `op`, an `output`
  varnode (or `null`), and `inputs` in exact operand order. Def-use is implicit:
  an op's `output.vn` id reappears as some later op's `input.vn`. Signedness is
  **not** on the varnode — it is carried by the opcode (`INT_LESS` vs
  `INT_SLESS`, `INT_ZEXT` vs `INT_SEXT`), so the opcode is kept verbatim.
- **Varnode shape** — a non-constant varnode is `{"vn", "size", "space"}` with a
  within-function stable `vn` id (`v0`, `v1`, …); `space` is
  register/unique/stack/ram/const. A ram varnode also carries its `addr`. A
  constant is inlined as `{"const": <int>, "size": <bytes>}` and has no id.
- **`varnodes`** — one entry per varnode that resolves to a recovered variable:
  its `highvar` name, `type`, `size`, and `storage` (storage comes from the
  variable's symbol; an unnamed temporary falls back to its architectural
  register). Array types also carry `{"elem_size", "count"}`.
- **`blocks`** — the pcode basic-block CFG (not the instruction CFG). Each block
  has its index, `start`/`end`, the `seq` indices of its `ops`, and `succ`/`pred`
  block indices. Loop back-edges are detected by DFS and reported both as a raw
  `back_edges` edge list on the source block and a `loop_header` flag on the
  target.
- **`calls`** — each `CALL`/`CALLIND` with its resolved `callee`/`callee_addr`
  (null when indirect or unresolved) and positional `args`. The arguments are the
  op's inputs after input[0] (the call target), i.e. Ghidra's own parameter
  analysis — no per-architecture calling-convention recovery downstream.
- **`locals`** — stack-resident variables with base `stack_offset`, byte `size`,
  and array `{"elem_size", "count"}`: stack-buffer capacity, the alloc side for
  stack overflows. Empty when a function keeps no buffers on the stack.
- **`rodata`** — ram operands resolved from provably read-only memory as
  `{"addr", "size", "value"}`. Writable globals are never resolved.

A function with no high function (a thunk, or a decompiler error) is skipped;
when a record is written for it, it carries `{"function", "error"}` instead of
the envelope, mirroring `decompilation.status`.

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

Schema 7 artifact filenames include a stable digest and bounded ASCII components so
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
