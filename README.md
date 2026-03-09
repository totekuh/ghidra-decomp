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

## Output

```
firmware_decomp/
├── functions/
│   ├── 00010000_main.c
│   ├── 00010234_parse_config.c
│   └── ...
├── all_functions.c     # everything in one file
├── callgraph.json      # who calls who
├── strings.json        # strings + xrefs to functions
├── imports.json        # external library functions
├── exports.json        # exported entry points
├── symbols.json        # globals, labels, data
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
