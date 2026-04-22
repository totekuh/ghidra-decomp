# ghidra-decomp

Bulk-decompile binaries into browsable source trees using Ghidra.

Takes a binary, runs Ghidra's decompiler on every function, and produces a directory of `.c` files and JSON indexes — ready for grep, code review, or AI-assisted analysis.

## Why

Reverse engineering through Ghidra's GUI (or MCP) means looking at one function at a time. This tool dumps everything upfront so you can treat the binary like a normal codebase: grep for patterns, read call graphs, search strings — all without waiting for decompilation round-trips.

## Install

Requires [Ghidra](https://ghidra-sre.org/) 11.0+ (which bundles pyghidra).

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
| `--ghidra-path` | Path to Ghidra install | `$GHIDRA_INSTALL_DIR` |
| `--base-addr` | Rebase binary to this address before analysis (e.g. `0x80000000`) | none |
| `--entry` | Mark this address as the entry point and disassemble from it before analysis (e.g. `0x31000`). Useful for raw binaries. | none |
| `--language` | Force Ghidra language ID (e.g. `ARM:LE:32:v7`). Use when auto-detect fails. | auto |
| `--compiler` | Force compiler spec ID (e.g. `gcc`, `default`, `windows`). Requires `--language`. | auto |
| `--list-languages` | List all available language IDs and compiler specs, then exit. | |

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
├── functions/
│   ├── 00010000_main.c
│   ├── 00010234_parse_config.c
│   └── ...
├── all_functions.c     # everything in one file
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

Each `.c` file includes a metadata header:

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

## Intended workflow

1. **Dump** the binary with `ghidra-decomp`
2. **Analyze** the output like source code — grep, glob, read
3. **Write back** renames/annotations to Ghidra via MCP (separate tool)

## License

MIT
