# ghidra-decomp

Bulk-decompile binaries into browsable source trees using Ghidra.

Takes a binary, runs Ghidra's decompiler on every function, and produces a directory of `.c` files and JSON indexes — ready for grep, code review, or AI-assisted analysis.

## Why

Reverse engineering through Ghidra's GUI (or MCP) means looking at one function at a time. This tool dumps everything upfront so you can treat the binary like a normal codebase: grep for patterns, read call graphs, search strings — all without waiting for decompilation round-trips.

## Install

Requires [Ghidra](https://ghidra-sre.org/) 12.0+ and PyGhidra 3.0+.

```bash
make install
```

Or manually: `pip install -e .`

Set `GHIDRA_INSTALL_DIR` to your Ghidra installation, or pass `--ghidra-path`.

## Usage

```bash
ghidra-decomp ./firmware.bin -o ./firmware_decomp
```

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output` | Output directory | `<binary>_decomp/` |
| `--timeout` | Per-function decompilation timeout (seconds) | 60 |
| `--combined` | Also emit `all_functions.c` | off |
| `--ghidra-path` | Path to Ghidra install | `$GHIDRA_INSTALL_DIR` |
| `--base-addr` | Rebase binary to this address before analysis | none |
| `--entry` | Mark address as entry point before analysis | none |
| `--language` | Force Ghidra language ID (e.g. `ARM:LE:32:v7`) | auto |
| `--compiler` | Force compiler spec ID. Requires `--language`. | auto |
| `--list-languages` | List all available language/compiler IDs, then exit | |
| `--workers` | Decompiler threads | `min(4, CPU count)` |
| `--resume` | Reuse hash-valid per-function artifacts from existing output | off |
| `--include` / `--exclude` | Function name regexes. Repeatable. | all |
| `--function` | Export function at this address. Repeatable. | |
| `--gdt` | Apply a Ghidra data type archive. Repeatable. | none |
| `--pdb` | PDB source: `auto` (fetch from symbol server), `none`, or local path | detect+prompt |
| `--gzf` | Also export `program.gzf` | off |
| `--semgrep-config` | Scan pseudocode with semgrep, write `semgrep.sarif` | off |
| `--verbose-analysis` | Attach console monitor to Ghidra auto-analysis | off |
| `--mermaid` | Render call graphs as Mermaid flowcharts in `callgraphs/` | off |
| `--cpp-export` | Export single `.c` + `.h` via Ghidra's CppExporter | off |
| `--max-ram-percent` | JVM MaxRAMPercentage for heap sizing (1.0–100.0) | 50.0 |
| `--print-jvm-flags` | Print JVM flag values at startup | off |
| `--callgraph-depth` | Neighborhood hops for per-function Mermaid (1–10) | 1 |
| `--condense-threshold` | Collapse whole-graph Mermaid when edges exceed N | none |
| `--reachable FROM TO` | Check if FROM can reach TO in the call graph | none |
| `--no-polish` | Skip the readability post-processing pipeline; emit raw Ghidra output | polish on |
| `--aggressive` | Enable Ghidra's off-by-default Decompiler Parameter ID analyzer for better parameter/return types (slower) | off |
| `--max-payload-mb` | Raise Ghidra's per-function decompiler payload cap (MB) to rescue very large functions | Ghidra default (~50MB) |

## Polish

By default, decompiled pseudocode is run through a post-processing pipeline that
rewrites Ghidra's output into more readable C without changing semantics —
`while`→`for` loops, `x = x + 1`→`x += 1`, `if (c) { return 1; } return 0;`→
`return c;`, struct-field and vtable synthesis on stripped binaries, and more.
Pass `--no-polish` to get Ghidra's raw output instead. Each function's sidecar
records whether it was polished.

See [docs/polish.md](docs/polish.md) for the full transform list and guarantees.

## Output

```
firmware_decomp/
├── manifest.json
├── functions/
│   ├── 00010000_<digest>_main.c
│   ├── 00010000_<digest>_main.json
│   └── ...
├── assembly/
│   ├── 00010000_<digest>_main.s
│   └── ...
├── xrefs.jsonl
├── all_functions.c     # --combined
├── program.gzf         # --gzf
├── semgrep.sarif       # --semgrep-config
├── types.json
├── functions.json
├── callgraph.json
├── callgraphs/          # --mermaid
│   ├── callgraph.md
│   ├── endpoints.json
│   ├── reachability.json  # --reachable
│   ├── paths.md           # --reachable --mermaid
│   └── <function>.md
├── export.c             # --cpp-export
├── export.h             # --cpp-export
├── strings.json
├── imports.json
├── exports.json
├── symbols.json
├── sections.json
└── metadata.json
```

See [docs/output-format.md](docs/output-format.md) for the full artifact contract, sidecar structure, type records, and manifest semantics.

## Callgraph Queries (no Ghidra needed)

Query a previous export's `callgraph.json` without starting Ghidra:

```bash
# Find root and leaf functions
ghidra-decomp-query endpoints ./firmware_decomp

# Check if main can reach encrypt_data
ghidra-decomp-query reachable ./firmware_decomp main encrypt_data

# Find all paths between two functions
ghidra-decomp-query paths ./firmware_decomp main encrypt_data --max-depth 50
```

## Docker

```bash
docker compose run --rm ghidra-decomp ./firmware.bin -o /output/firmware_decomp
```

## Workflow

1. **Dump** the binary with `ghidra-decomp`
2. **Analyze** the output like source code — grep, glob, read
3. **Re-run** with `--resume`, or narrow with `--include`/`--function`
4. **Write back** renames/annotations to Ghidra via MCP (separate tool, not yet built)

## Docs

- [Output format](docs/output-format.md) — artifact contract, sidecars, types, manifest
- [Polish](docs/polish.md) — the readability post-processing pipeline and its transforms
- [Raw binaries](docs/raw-binaries.md) — language/compiler selection, rebasing, entry points
- [Development](docs/development.md) — testing, CI, fixture regeneration

## License

MIT
