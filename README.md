# ghidra-decomp

Bulk-decompile binaries into browsable source trees using Ghidra.

Takes a binary, runs Ghidra's decompiler on every function, and produces a directory of `.c` files and JSON indexes — ready for grep, code review, or AI-assisted analysis.

## Why

Reverse engineering through Ghidra's GUI (or MCP) means looking at one function at a time. This tool dumps everything upfront so you can treat the binary like a normal codebase: grep for patterns, read call graphs, search strings — all without waiting for decompilation round-trips.

`--resume` rebuilds only the functions whose artifacts no longer match their recorded hashes.

## Install

Requires [Ghidra](https://ghidra-sre.org/) 12.0+ and PyGhidra 3.0+.

```bash
pip install -e .
```

Set `GHIDRA_INSTALL_DIR` to your Ghidra installation, or pass `--ghidra-path`.

## Usage

```bash
ghidra-decomp ./firmware.bin -o ./firmware_decomp
```

Options:

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output directory | `<binary>_decomp/` |
| `--timeout` | Per-function decompilation timeout (seconds) | 60 |
| `--combined` | Also emit `all_functions.c` | off |
| `--ghidra-path` | Path to Ghidra install | `$GHIDRA_INSTALL_DIR` |
| `--base-addr` | Rebase binary to this address before analysis (e.g. `0x80000000`) | none |
| `--entry` | Mark this address as the entry point and disassemble from it before analysis (e.g. `0x31000`). Useful for raw binaries. | none |
| `--language` | Force Ghidra language ID (e.g. `ARM:LE:32:v7`). Use when auto-detect fails. | auto |
| `--compiler` | Force compiler spec ID (e.g. `gcc`, `default`, `windows`). Requires `--language`. | auto |
| `--list-languages` | List all available language IDs and compiler specs, then exit. | |
| `--workers` | Decompiler threads. JVM memory, not CPU count, is usually the limit. | `min(4, CPU count)` |
| `--resume` | Reuse per-function artifacts from an existing output whose hashes still match. | off |
| `--include` / `--exclude` | Name regexes selecting which functions to export. Repeatable. | all |
| `--function` | Export the function at this entry address regardless of name filters. Repeatable. | |
| `--gdt` | Apply a Ghidra data type archive before analysis. Repeatable. | none |
| `--gzf` | Also export `program.gzf` for reopening in the Ghidra GUI. | off |
| `--semgrep-config` | Scan the exported pseudocode with semgrep and write `semgrep.sarif`. | off |

### Resume

`--resume` reuses per-function artifacts from an existing output. A function is
reused only when its sidecar records a successful decompilation *and* its
pseudocode, assembly, and sidecar all still hash to what the previous run
recorded; anything else is decompiled again.

```bash
ghidra-decomp ./firmware.bin -o ./firmware_decomp            # full run
ghidra-decomp ./firmware.bin -o ./firmware_decomp --resume   # reuse valid artifacts
```

For raw binaries or unknown formats, Ghidra will refuse to auto-load. Discover the right spec then pass it:

```bash
ghidra-decomp --list-languages | grep -i arm
ghidra-decomp ./firmware.bin --language ARM:LE:32:v7 --compiler default
```

Raw binaries typically also need a known image base and an entry point for auto-analysis to reach every function. Both are applied *before* analysis runs, so function boundaries, xrefs, and switch-table recovery all happen at the real addresses:

```bash
ghidra-decomp ./dal_ivm.mod \
  --language x86:LE:32:default \
  --compiler gcc \
  --base-addr 0x00031000 \
  --entry   0x00031000
```

## Output

```
firmware_decomp/
├── manifest.json       # fingerprint, versions, counts, artifact hashes
├── functions/
│   ├── 00010000_<digest>_main.c
│   ├── 00010000_<digest>_main.json
│   ├── 00010234_<digest>_parse_config.c
│   └── ...
├── assembly/
│   ├── 00010000_<digest>_main.s
│   └── ...
├── xrefs.jsonl         # call-site-aware code and data references
├── all_functions.c     # optional; enabled with --combined
├── program.gzf         # optional; enabled with --gzf
├── semgrep.sarif       # optional; enabled with --semgrep-config
├── types.json          # structs, enums, unions, typedefs + provenance and users
├── functions.json      # function index with address ranges + signatures
├── callgraph.json      # who calls who
├── strings.json        # strings + xrefs to functions
├── imports.json        # external library functions
├── exports.json        # exported entry points
├── symbols.json        # globals, labels, data
├── sections.json       # memory map with r/w/x permissions
└── metadata.json       # binary info + stats
```

Each `.c` file includes a metadata header. Its adjacent JSON sidecar records body
ranges, signature and variable storage, calls, references, related strings and
globals, decompilation status, artifact paths, and hashes. Assembly files contain
instruction addresses, raw bytes, mnemonics, and operands.

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

Schema 6 artifact filenames include a stable digest and bounded ASCII components so
segmented addresses, long symbols, and platform-reserved names remain safe. Consumers
must follow the artifact paths in `functions.json` rather than constructing filenames.

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

`manifest.json` is the corpus completion marker. It fingerprints the snapshotted input
bytes and analysis configuration, records Ghidra/PyGhidra/tool versions, summarizes
function statuses, and hashes every generated index. Exports are built in a hidden
sibling staging directory whose `.run-state.json` marks that staging corpus incomplete.
The existing completed output remains untouched if analysis fails. Publication is
serialized by a destination lock and occurs only after the staged manifest, artifacts,
and indexes are durable.

Each function receives at most the configured `--timeout`, never multiplied by worker
count or retries. A function that the decompiler declines is recorded as `fallback`; a
timeout or exception is recorded as `failed`, which `--resume` retries on a later run.
Either way the C artifact contains the error and the normal assembly artifact remains
available for analysis.

`successful`, `fallback`, and `failed` partition the discovered functions. `skipped`
counts the reused subset and overlaps them: it answers how much work a run avoided,
not how a function ended.

## Intended workflow

1. **Dump** the binary with `ghidra-decomp`
2. **Analyze** the output like source code — grep, glob, read
3. **Re-run** with `--resume`, or narrow to one function with `--include`/`--function`,
   as the objective sharpens.
4. **Write back** renames/annotations to Ghidra via MCP (separate tool, not yet built)

## Development

Fast checks:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/ghidra_decomp/ --ignore-missing-imports
pytest tests/test_artifacts.py tests/test_decompiler_helpers.py \
       tests/test_filters.py tests/test_parallel.py
pytest tests/test_multiarch_e2e.py::test_checked_in_fixture_hashes_and_provenance
```

CI installs the project and pytest before running these fast unit/CLI tests and the
checked-in fixture checksum/provenance validation. It does not start embedded Ghidra.

The complete suite starts embedded Ghidra and decompiles the original repository
fixture, the host's `true` executable, and six stored ELF fixtures covering x86-32,
ARMv7, AArch64, MIPS32LE, PowerPC32BE, and RISC-V64:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/
```

The system-binary integration test verifies manifest and artifact hashes, sidecars,
addressed assembly bytes, call-site-aware xrefs, storage metadata, stack frames, and
combined output. It skips when the host does not provide `true` or a Ghidra install.
See `tests/fixtures/README.md` for the pinned LLVM 21 regeneration and reproducibility
procedure for the multi-architecture binaries.

## License

MIT
