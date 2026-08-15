# Handoff: autonomous reverse-engineering corpus

## Objective

Make `ghidra-decomp` the primary ingestion backend for autonomous binary analysis. The user supplies a binary and an objective; the agent runs the exporter, searches the resulting corpus, validates pseudocode against assembly, and performs follow-up analysis without requiring manual Ghidra interaction.

The common path must remain filesystem-first. MCP or another live bridge is optional and should be reserved for information absent from the corpus and for writing names, types, comments, or patches back to a persistent Ghidra project.

## Workspace boundary

Do not broadly scan `/home/witchtape`. Work inside this repository or another explicitly relevant path under `/home/witchtape/tools` or `/home/witchtape/projects`. Internet research is allowed when needed.

## Repository state

- Repository: `/home/witchtape/tools/ghidra-decomp`
- Package: Python 3.10+, Click, PyGhidra, MIT licensed
- CLI entry point: `ghidra-decomp = ghidra_decomp.cli:main`
- Core implementation: `src/ghidra_decomp/decompiler.py`
- Artifact helpers: `src/ghidra_decomp/artifacts.py`
- End-to-end tests: `tests/test_e2e.py` and `tests/test_system_e2e.py`
- Milestone 1, artifact correctness, is complete and covered by unit and live-Ghidra tests.
- `ROADMAP.md` contains the remaining feature backlog and external-tool survey.

## Current pipeline

```text
binary
  -> start embedded Ghidra through PyGhidra
  -> import into an isolated writable temporary project
  -> optional rebase and entry-point creation
  -> run auto-analysis
  -> serially decompile every discovered function
  -> atomically export C, assembly, sidecars, xrefs, and global indexes
  -> publish manifest.json as the completion marker
  -> delete the temporary Ghidra project through ExitStack cleanup
```

Current output:

```text
<output>/
|-- manifest.json
|-- functions.json
|-- functions/<address>_<name>.c
|-- functions/<address>_<name>.json
|-- assembly/<address>_<name>.s
|-- xrefs.jsonl
|-- callgraph.json
|-- strings.json
|-- symbols.json
|-- types.json
|-- imports.json
|-- exports.json
|-- sections.json
|-- metadata.json
`-- all_functions.c                 # only with --combined
```

Useful existing controls are `--timeout`, `--combined`, `--base-addr`, `--entry`, `--language`, `--compiler`, `--list-languages`, and `--ghidra-path`. `--timeout` must be positive and is no longer silently multiplied by retries.

## Verified weaknesses

### Performance

- `_export_all()` uses one `DecompInterface` and processes functions serially.
- Every invocation imports and analyzes the binary from scratch.
- The temporary project is deleted after every run, preventing incremental analysis and writeback.
- Per-function C, assembly, sidecars, and related global records may still produce a large corpus.

### Corpus quality

- Type records are shallow and omit category paths, packing, provenance, and usage references.
- Function locals are limited to variables Ghidra materializes on the function object; richer decompiler-only temporaries are not exported.
- Legacy `end_address` remains for compatibility, but consumers should use `body_ranges` for non-contiguous functions.

### Reliability

- Interrupted output is marked by `.run-state.json` and has no valid completion manifest, but function-level resume is not implemented.
- Existing valid per-function artifacts are rebuilt rather than hash-validated and reused.
- The fingerprint is recorded but is not yet used as a project or output cache key.

## Current artifact contract

```text
<output>/
|-- manifest.json
|-- functions.json
|-- callgraph.json
|-- functions/
|   |-- <address>_<name>.c
|   `-- <address>_<name>.json
|-- assembly/
|   `-- <address>_<name>.s
|-- xrefs.jsonl
|-- strings.json
|-- symbols.json
|-- types.json
|-- imports.json
|-- exports.json
|-- sections.json
|-- metadata.json
`-- all_functions.c          # optional
```

Each function sidecar contains at least:

```json
{
  "schema_version": 1,
  "name": "parse_config",
  "address": "00100234",
  "body_ranges": [{"start": "00100234", "end": "0010034f"}],
  "size": 284,
  "signature": {
    "return_type": "int",
    "calling_convention": "__cdecl",
    "parameters": [],
    "locals": []
  },
  "calls": [],
  "called_by": [],
  "references": [],
  "strings": [],
  "globals": [],
  "artifacts": {
    "pseudocode": "functions/00100234_parse_config.c",
    "assembly": "assembly/00100234_parse_config.s"
  },
  "decompilation": {
    "status": "success",
    "error": null
  }
}
```

Call edges must include the call-site address, target address/name when resolved, and reference type. Parameter and local records should include data type, storage kind, register or stack offset, size, and Ghidra source/provenance where available. Assembly lines should include instruction address, raw bytes, mnemonic, and operands.

`manifest.json` includes:

- Schema version and completion status.
- Input path, SHA-256, and size.
- Tool, PyGhidra, Ghidra, language, and compiler versions/IDs.
- Image base, entry points, loader, and relevant analysis options.
- Export options and timeout/worker settings.
- Counts for discovered, successful, fallback, failed, and skipped functions.
- Paths and hashes for generated indexes.

Use a temporary run-state file while work is incomplete. Publish `manifest.json` atomically only after all required indexes are durable.

## Implementation sequence

### Milestone 1: artifact correctness (complete)

- [x] Introduce schema constants and a full input/analysis fingerprint.
- [x] Add atomic text and JSON writers using sibling temporary files plus `Path.replace()`.
- [x] Add per-function status, error, artifact paths, body ranges, and hashes to `functions.json`.
- [x] Emit per-function JSON sidecars.
- [x] Emit addressed assembly with raw instruction bytes for every function.
- [x] Export call-site-aware calls and generic code/data references.
- [x] Export parameter/local storage and stack-frame details.
- [x] Make `all_functions.c` opt-in through `--combined`; stream it when enabled.
- [x] Validate `--timeout` as a positive integer.

Keep this milestone serial. Establish deterministic output before adding concurrency or reuse.

### Milestone 2: resumable output and project reuse

- Derive a cache key from the complete input/analysis fingerprint, not a shortened digest or filename.
- Retain a Ghidra project in an explicit cache location.
- Reopen the project only when the fingerprint matches exactly.
- Add `--resume`, `--force-analysis`, and `--force-export` semantics with clear separation.
- Skip a function only when its sidecar says success and its artifact hashes still match.
- Retry fallback and failed functions without rebuilding valid output.
- Put project cleanup in `finally`; never delete an unrelated directory inferred from output paths.

### Milestone 3: bounded parallel decompilation

- Add `--workers`, defaulting conservatively rather than blindly using every CPU.
- Use one opened `DecompInterface` per worker; do not share one interface concurrently.
- Keep Ghidra metadata extraction serial unless its APIs are proven safe for concurrent access.
- Collect worker results and write deterministic indexes sorted by address.
- Give each function a bounded timeout. Do not silently multiply the user-facing timeout.
- Compare serial and parallel corpora for identical function status, pseudocode, sidecars, and indexes.
- Benchmark wall time, peak JVM memory, and failure behavior on large binaries.

### Milestone 4: analysis inputs and secondary products

- Add function-name/address filters and targeted re-export.
- Add optional symbol-server/PDB resolution.
- Add optional GDT application before analysis.
- Add optional GZF and BSim output.
- Add optional Semgrep scanning with SARIF output after corpus completion.
- Evaluate `ghidra-cli` or MCP only for live queries and writeback.

## External-tool conclusion

`ghidrecomp` 0.5.9 is the strongest directly comparable turnkey utility. It provides threaded decompilation, persistent projects, basic resume, regex filtering, symbol servers/PDBs, GDTs, GZF, BSim, callgraph rendering, and Semgrep/SARIF.

It is not a replacement for this project because it lacks the structured function/string/symbol/type/section corpus, generic xrefs, normal assembly, stack storage, robust fingerprints, and raw-binary base/entry/language/compiler controls required here. It is GPL-3.0 while this project is MIT. Reimplement useful concepts; do not copy its source unless the licensing decision changes.

Official Ghidra `analyzeHeadless` plus a custom Java exporter is the fallback execution architecture if PyGhidra lifecycle or performance becomes a blocker. `ghidra-cli` is the most relevant optional conventional live-query layer. Ghidra MCP projects are useful for writeback but should not replace bulk filesystem output.

See `ROADMAP.md` for links and the complete survey table.

## Test status

- Implemented unit tests for fingerprinting, atomic writes, filename sanitization, positive timeout validation, and combined-output CLI forwarding.
- Implemented fixture end-to-end assertions for per-function C, JSON, assembly, hashes, body ranges, and call-site addresses.
- Implemented a system-binary integration test that decompiles the host's `true` executable and validates manifest/index hashes, sidecars, addressed assembly bytes, xrefs, storage metadata, stack frames, and combined output.
- Verified locally against Ghidra 12.1: 59 tests pass.

Remaining tests:

- Interrupted-run and resume tests proving stale top-level indexes are never published.
- Cache invalidation tests for changed bytes, base, entry, language, compiler, Ghidra version, and export schema.
- Failed-function tests covering timeout, fallback assembly, retry, and later resume.
- Determinism tests comparing serial and parallel output after removing intentionally variable timestamps.
- A non-contiguous function-body fixture or targeted unit test.

Existing local verification commands:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/ghidra_decomp/ --ignore-missing-imports
pytest tests/
```

The end-to-end suite requires Ghidra and can take several minutes. CI currently runs formatting, linting, and type checking but not the real Ghidra suite.

## Next coding slice

Implement Milestone 2 without adding parallelism yet:

1. Define explicit cache and retained-project locations.
2. Compare the complete stored fingerprint before reusing a project or corpus.
3. Add `--resume`, `--force-analysis`, and `--force-export` with separate semantics.
4. Validate successful sidecar and artifact hashes before skipping a function.
5. Add interrupted-run, invalidation, and fallback retry tests.

Do not add worker concurrency until resume and invalidation semantics are proven deterministic.
