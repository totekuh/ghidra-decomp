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
| `--gzf` | Also export `program.gzf` | off |
| `--semgrep-config` | Scan pseudocode with semgrep, write `semgrep.sarif` | off |

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
├── strings.json
├── imports.json
├── exports.json
├── symbols.json
├── sections.json
└── metadata.json
```

See [docs/output-format.md](docs/output-format.md) for the full artifact contract, sidecar structure, type records, and manifest semantics.

## Workflow

1. **Dump** the binary with `ghidra-decomp`
2. **Analyze** the output like source code — grep, glob, read
3. **Re-run** with `--resume`, or narrow with `--include`/`--function`
4. **Write back** renames/annotations to Ghidra via MCP (separate tool, not yet built)

## Docs

- [Output format](docs/output-format.md) — artifact contract, sidecars, types, manifest
- [Raw binaries](docs/raw-binaries.md) — language/compiler selection, rebasing, entry points
- [Development](docs/development.md) — testing, CI, fixture regeneration

## License

MIT
