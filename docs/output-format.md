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

## Allocation map (`--alloc-map`)

With `--alloc-map`, the export produces `alloc_map.json` recording every allocation
call site in the binary — where the result pointer is stored, how it flows forward,
and the resolved size. The flag implies `--pcode`.

The map knows 35+ built-in allocators (libc `malloc`/`calloc`/`realloc`/`strdup` and
Linux kernel `kmalloc`/`kzalloc`/`kcalloc`/`vmalloc`/`devm_kmalloc`/etc.), plus a
fallback heuristic for functions whose name contains "alloc". Extend the list with
`--alloc-map-config` pointing to a JSON file that maps function names to size-argument
specs.

```json
{
  "schema_version": 1,
  "binary": "dnsmasq",
  "functions_analyzed": 349,
  "entries": [
    {
      "function": "rehash",
      "entry": "00112200",
      "callee": "safe_malloc",
      "callee_addr": "00110640",
      "size": 512,
      "size_expr": "const",
      "size_vn": null,
      "unwrapped_via": "safe_malloc -> calloc",
      "stores": [
        {
          "kind": "field",
          "base_vn": "v12",
          "field_offset": 8,
          "store_vn": "v7",
          "seq": 42
        }
      ],
      "forwarded_to": ["process_reply"]
    }
  ]
}
```

- **`size_expr`** — `"const"` (literal), `"variable"` (runtime), `"product"`
  (two-arg product, e.g. calloc), or `"unknown"` (implicit/unresolvable).
- **`size_vn`** — when `size_expr` is `"variable"`, the varnode id in this
  function's pcode that holds the size, for backward slicing.
- **`struct_type`** — when the allocator's return value is cast to or stored into a
  known struct pointer type, the struct name (e.g. `"mwifiex_private"`); `null`
  when the output is untyped or not a struct pointer.
- **`stores`** — where the allocation result pointer is written: `"field"` (struct
  field at a fixed offset), `"global"` (known address), or `"array"` (indexed store).
- **`forwarded_to`** — functions the result pointer is passed to as an argument.

### Allocator wrapper unwrapping

When a call targets a function that is not in the known allocator list but is a
simple wrapper — it calls exactly one known allocator, returns the result, and passes
a parameter as the size without arithmetic — the alloc map resolves the size through
the wrapper chain. `unwrapped_via` documents the chain
(`"safe_malloc -> calloc"`, `"opt_malloc -> safe_malloc -> calloc"`); it is `null`
for direct allocator calls.

Multi-path wrappers are supported: a function with up to 4 allocator call sites
qualifies when every site is store-free, returns its result, and derives the same
size spec. Unwrap depth is uncapped with cycle protection.

## Struct map (`--struct-map`)

With `--struct-map`, the export produces `struct_map.json` recording every resolved
struct and union type referenced by decompiled code. The flag implies `--alloc-map`
(which implies `--pcode`).

A type is included when it appears as `struct_type` on an alloc_map entry, as
`base_type` on a store, or in function signatures (parameters, locals, return types).

```json
{
  "schema_version": 1,
  "structs": {
    "mwifiex_private": {
      "size": 8192,
      "kind": "struct",
      "fields": [
        {"name": "adapter", "size": 8, "type": "mwifiex_adapter *", "offset": 0},
        {"name": "wmm_ie", "size": 50, "type": "IEEEtypes_WmmParameter_t", "offset": 498},
        {"name": "wmm_enabled", "size": 1, "type": "uint8_t", "offset": 548}
      ]
    },
    "net_data": {
      "size": 8,
      "kind": "union",
      "fields": [
        {"name": "raw", "size": 8, "type": "uint8_t[8]"},
        {"name": "value", "size": 8, "type": "uint64_t"}
      ]
    }
  }
}
```

- Struct fields are sorted by `offset`. Union fields have no offset.
- Only struct/union kinds are included; enums, typedefs, and function definitions
  are filtered out.
- Pairs with `alloc_map.json` to give downstream tools field-level layout needed
  for struct-field overflow detection.

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
