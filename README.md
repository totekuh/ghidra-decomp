# ghidra-decomp

Bulk-decompile binaries into browsable source trees using Ghidra.

Takes a binary, runs Ghidra's decompiler on every function, and produces a directory of `.c` files and JSON indexes — ready for grep, code review, or AI-assisted analysis.

## Why

Reverse engineering through Ghidra's GUI (or MCP) means looking at one function at a time. This tool dumps everything upfront so you can treat the binary like a normal codebase: grep for patterns, read call graphs, search strings — all without waiting for decompilation round-trips.

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
| `--no-cache` | Do not retain or reuse a Ghidra project. | off |
| `--cache-dir` | Where retained Ghidra projects live. | `$XDG_CACHE_HOME/ghidra-decomp` |
| `--resume` | Reuse per-function artifacts from an existing output whose hashes still match. | off |
| `--force-analysis` | Ignore any retained project and analyze again. | off |
| `--force-export` | Reuse the retained project but rebuild every artifact. | off |
| `--include` / `--exclude` | Name regexes selecting which functions to export. Repeatable. | all |
| `--function` | Export the function at this entry address regardless of name filters. Repeatable. | |
| `--gdt` | Apply a Ghidra data type archive before analysis. Repeatable. | none |
| `--gzf` | Also export `program.gzf` for reopening in the Ghidra GUI. | off |
| `--semgrep-config` | Scan the exported pseudocode with semgrep and write `semgrep.sarif`. | off |

### Caching and resume

Analysis is the expensive part, so the analyzed Ghidra project is retained under
`$XDG_CACHE_HOME/ghidra-decomp/<fingerprint>/` and reused when the input bytes,
base address, entry point, language, compiler, data type archives, Ghidra
version, PyGhidra version, exporter version, and schema version all match. Any
mismatch re-analyzes rather than failing, and `manifest.json` records the
decision under `cache`:

```json
{"enabled": true, "hit": false, "path": "...", "reason": "cached analysis was built with a different ghidra_version"}
```

`--resume` additionally reuses per-function artifacts from an existing output.
A function is reused only when its sidecar records a successful decompilation
*and* its pseudocode, assembly, and sidecar all still hash to what the previous
run recorded; anything else is decompiled again.

```bash
ghidra-decomp ./firmware.bin -o ./firmware_decomp            # cold: analyze and export
ghidra-decomp ./firmware.bin -o ./firmware_decomp --resume   # warm: reuse both
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
├── manifest.json       # fingerprint, versions, completion status, artifact hashes
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
├── types.json          # recovered structs, enums, unions, typedefs
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

Schema 2 artifact filenames include a stable digest and bounded ASCII components so
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

Each function receives at most the configured `--timeout`. A failed decompilation is
recorded as `fallback`; its C artifact contains the error while its normal assembly
artifact remains available for analysis.

## Intended workflow

1. **Dump** the binary with `ghidra-decomp`
2. **Analyze** the output like source code — grep, glob, read
3. **Write back** renames/annotations to Ghidra via MCP (separate tool)

## Development

Fast checks:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/ghidra_decomp/ --ignore-missing-imports
pytest tests/test_artifacts.py tests/test_cache.py \
       tests/test_decompiler_helpers.py tests/test_filters.py tests/test_parallel.py
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
