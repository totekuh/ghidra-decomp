# Handoff: autonomous reverse-engineering corpus

## Objective

Make `ghidra-decomp` the primary ingestion backend for autonomous binary analysis. The user supplies a binary and an objective; the agent runs the exporter, searches the resulting corpus, validates pseudocode against assembly, and performs follow-up analysis without requiring manual Ghidra interaction.

The common path must remain filesystem-first. MCP or another live bridge is optional and should be reserved for information absent from the corpus and for writing names, types, comments, or patches back to a persistent Ghidra project.

## Workspace boundary

Do not broadly scan `/home/witchtape`. Work inside this repository or another explicitly relevant path under `/home/witchtape/tools` or `/home/witchtape/projects`. Internet research is allowed when needed.

## Repository state

- Repository: `/home/witchtape/tools/ghidra-decomp`
- Package: version 0.4.0, Python 3.10+, Click, PyGhidra 3.0+, Ghidra 12+, MIT licensed
- CLI entry point: `ghidra-decomp = ghidra_decomp.cli:main`
- Core implementation: `src/ghidra_decomp/decompiler.py`
- Artifact helpers: `src/ghidra_decomp/artifacts.py`
- Analysis cache: `src/ghidra_decomp/cache.py`
- Unit tests: `tests/test_artifacts.py`, `tests/test_cache.py`, `tests/test_decompiler_helpers.py`, `tests/test_filters.py`, `tests/test_parallel.py`
- End-to-end tests: `tests/test_e2e.py`, `tests/test_cache_e2e.py`, `tests/test_multiarch_e2e.py`, and `tests/test_system_e2e.py`, with shared helpers in `tests/conftest.py`
- Milestones 1 through 3 are complete and covered by unit and live-Ghidra tests. Milestone 4 is partial.
- `ROADMAP.md` contains the remaining feature backlog and external-tool survey.

## Current pipeline

```text
binary
  -> start embedded Ghidra through PyGhidra
  -> resolve the fingerprinted cache entry and take its ownership lock
  -> reopen the retained project, or import into a fresh one on a miss
  -> on a miss: optional rebase, entry-point creation, GDT application, auto-analysis
  -> select functions through --include/--exclude/--function
  -> decompile on a bounded thread pool, one DecompInterface per worker
  -> reuse hash-valid per-function artifacts when --resume is given
  -> export C, assembly, sidecars, xrefs, and indexes in sibling staging
  -> optional GZF export and semgrep SARIF scan
  -> publish manifest.json as the staged completion marker
  -> serialize replacement of the previous owned corpus
  -> mark the cache entry complete once the project is durable
```

Current output:

```text
<output>/
|-- manifest.json
|-- functions.json
|-- functions/<safe-address>_<digest>_<safe-name>.c
|-- functions/<safe-address>_<digest>_<safe-name>.json
|-- assembly/<safe-address>_<digest>_<safe-name>.s
|-- xrefs.jsonl
|-- callgraph.json
|-- strings.json
|-- symbols.json
|-- types.json
|-- imports.json
|-- exports.json
|-- sections.json
|-- metadata.json
|-- all_functions.c                 # only with --combined
|-- program.gzf                     # only with --gzf
`-- semgrep.sarif                   # only with --semgrep-config
```

Useful existing controls are `--timeout`, `--combined`, `--base-addr`, `--entry`, `--language`, `--compiler`, `--list-languages`, `--ghidra-path`, `--workers`, `--no-cache`, `--cache-dir`, `--resume`, `--force-analysis`, `--force-export`, `--include`, `--exclude`, `--function`, `--gdt`, `--gzf`, and `--semgrep-config`. `--timeout` must be positive and is never multiplied by retries or worker count.

## Verified weaknesses

### Performance

- Per-function C, assembly, sidecars, and related global records may still produce a large corpus.
- Resolved: decompilation runs on a bounded thread pool with one `DecompInterface` per worker.
- Resolved: the analyzed project is retained under a fingerprinted cache entry and reused.

### Corpus quality

- Type records are shallow and omit category paths, packing, provenance, and usage references.
- Resolved: locals come from the decompiler's own symbol map, falling back to Ghidra's function object when a function was not decompiled this run.
- Legacy `end_address` remains for compatibility, but consumers should use `body_ranges` for non-contiguous functions.

### Reliability

- Replacing an existing output uses two serialized directory renames, so readers can briefly observe the output path as absent.
- Writeback into a persistent Ghidra project (renames, types, comments, patches) is still absent.
- Symbol-server/PDB resolution and BSim export are still absent; both need infrastructure this repository has no fixture for.
- Resolved: `--resume` hash-validates and reuses per-function artifacts.
- Resolved: the complete fingerprint is the cache key.
- Resolved: an abandoned staging directory is swept on the next run, and a live run's staging is protected by an ownership lock.

## Current artifact contract

```text
<output>/
|-- manifest.json
|-- functions.json
|-- callgraph.json
|-- functions/
|   |-- <safe-address>_<digest>_<safe-name>.c
|   `-- <safe-address>_<digest>_<safe-name>.json
|-- assembly/
|   `-- <safe-address>_<digest>_<safe-name>.s
|-- xrefs.jsonl
|-- strings.json
|-- symbols.json
|-- types.json
|-- imports.json
|-- exports.json
|-- sections.json
|-- metadata.json
|-- all_functions.c          # optional, --combined
|-- program.gzf              # optional, --gzf
`-- semgrep.sarif            # optional, --semgrep-config
```

Each function sidecar contains at least:

```json
{
  "schema_version": 4,
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
    "pseudocode": "functions/00100234_<digest>_parse_config.c",
    "assembly": "assembly/00100234_<digest>_parse_config.s"
  },
  "is_thunk": false,
  "thunk": null,
  "decompilation": {
    "status": "success",
    "error": null,
    "reused": false,
    "warnings": [{"kind": "warning", "text": "Subroutine does not return"}]
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
- Counts for discovered, successful, fallback, failed, and skipped functions. `successful`, `fallback`, and `failed` partition the discovered total; `skipped` counts the reused subset and overlaps them.
- A `cache` block recording whether the analysis was reused and why.
- Export filters, the pre-filter discovered count, and any secondary products.
- Paths and hashes for generated indexes.

Use a temporary run-state file inside sibling staging while work is incomplete. Publish `manifest.json` there only after all required indexes are durable, then replace only an ownership-validated destination under the publication lock.

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

### Milestone 2: resumable output and project reuse (complete)

- [x] Derive a cache key from the complete input/analysis fingerprint, not a shortened digest or filename.
- [x] Retain a Ghidra project in an explicit cache location (`$XDG_CACHE_HOME/ghidra-decomp/<fingerprint>/`).
- [x] Reopen the project only when the fingerprint and every resolved version match exactly.
- [x] Add `--resume`, `--force-analysis`, and `--force-export` semantics with clear separation.
- [x] Skip a function only when its sidecar says success and its artifact hashes still match.
- [x] Retry fallback and failed functions without rebuilding valid output.
- [x] Put project cleanup in `finally`; never delete an unrelated directory inferred from output paths.

### Milestone 3: bounded parallel decompilation (complete)

- [x] Add `--workers`, defaulting to `min(4, CPU count)` rather than blindly using every CPU.
- [x] Use one opened `DecompInterface` per worker; do not share one interface concurrently.
- [x] Keep Ghidra metadata extraction serial. Only `decompileFunction` runs on the pool.
- [x] Collect worker results and write deterministic indexes sorted by address.
- [x] Give each function a bounded timeout. The user-facing timeout is never multiplied.
- [x] Compare serial and parallel corpora for identical function status, pseudocode, sidecars, and indexes.
- [ ] Benchmark wall time, peak JVM memory, and failure behavior on large binaries. The checked-in fixtures are too small to measure.

### Corpus enrichment slice 1 (complete)

- [x] Record a thunk's target name and address. Measured on `/usr/bin/true`: 105 of 197
  functions are thunks, and all 105 now name a target where none did before.
- [x] Structure the decompiler's own `/* WARNING: ... */` output under
  `decompilation.warnings`. Same binary: 135 warnings across 100 functions, previously
  reachable only by reading the C.
- [x] Take local variables from `HighFunction.getLocalSymbolMap()`. Functions reporting
  any local went from 31 to 96 of 197, and from zero to all five on every checked-in
  architecture fixture.

Remaining enrichment items are listed in `ROADMAP.md`.

### Milestone 4: analysis inputs and secondary products (partial)

- [x] Add function-name/address filters and targeted re-export (`--include`, `--exclude`, `--function`).
- [x] Add optional GDT application before analysis (`--gdt`), hashed into the analysis fingerprint.
- [x] Add optional GZF output (`--gzf`). Written through `DomainFile.packFile`, because auto-analysis leaves a database transaction open that `GzfExporter` refuses to lock around.
- [x] Add optional Semgrep scanning with SARIF output after corpus completion (`--semgrep-config`).
- [ ] Add optional symbol-server/PDB resolution. Needs a PE fixture with a matching PDB and network access to a symbol server; neither exists in this repository.
- [ ] Add optional BSim output. Needs a BSim database to sign into; out of scope without one.
- [ ] Evaluate `ghidra-cli` or MCP only for live queries and writeback.

## External-tool conclusion

`ghidrecomp` 0.5.9 is the strongest directly comparable turnkey utility. It provides threaded decompilation, persistent projects, basic resume, regex filtering, symbol servers/PDBs, GDTs, GZF, BSim, callgraph rendering, and Semgrep/SARIF.

It is not a replacement for this project because it lacks the structured function/string/symbol/type/section corpus, generic xrefs, normal assembly, stack storage, robust fingerprints, and raw-binary base/entry/language/compiler controls required here. It is GPL-3.0 while this project is MIT. Reimplement useful concepts; do not copy its source unless the licensing decision changes.

Official Ghidra `analyzeHeadless` plus a custom Java exporter is the fallback execution architecture if PyGhidra lifecycle or performance becomes a blocker. `ghidra-cli` is the most relevant optional conventional live-query layer. Ghidra MCP projects are useful for writeback but should not replace bulk filesystem output.

See `ROADMAP.md` for links and the complete survey table.

## Test status

- Implemented unit tests for fingerprinting, atomic writes, filename sanitization, positive timeout validation, and combined-output CLI forwarding.
- Implemented fixture end-to-end assertions for per-function C, JSON, assembly, hashes, body ranges, and call-site addresses.
- Implemented a checked-in, reproducible LLVM 21 fixture matrix for x86-32, ARMv7, AArch64, MIPS32LE, PowerPC32BE, and RISC-V64. Each target uses an exact Ghidra language/compiler ID and validates functions, complete assembly byte coverage, calls/xrefs, exports, symbols, strings, sidecars, fingerprints, and index hashes.
- Implemented a system-binary integration test that decompiles the host's `true` executable and validates manifest/index hashes, sidecars, addressed assembly bytes, xrefs, storage metadata, stack frames, and combined output.
- Verified locally against Ghidra 12.1: 278 tests pass, 1 skipped (semgrep absent).

- Implemented cache unit tests in `tests/test_cache.py`: key stability, every invalidation input, XDG resolution, entry locking, and the resume predicate.
- Implemented parallel unit tests in `tests/test_parallel.py`: one interface per worker, never shared across threads, timeout never multiplied, and isolated per-function failures.
- Implemented filter unit tests in `tests/test_filters.py`.
- Implemented cache and resume end-to-end tests in `tests/test_cache_e2e.py`, including the determinism gate comparing `--workers 1` against `--workers 4`.
- Shared e2e helpers live in `tests/conftest.py`.

Remaining tests:

- Failed-function tests covering a real decompiler timeout, then retry on a later resume. The current coverage fakes the timeout because no checked-in fixture reliably exceeds a bounded timeout.
- A large-binary benchmark for the parallel path.

Existing local verification commands:

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/ghidra_decomp/ --ignore-missing-imports
pytest tests/
```

The end-to-end suite requires Ghidra 12+ and can take several minutes. CI installs the project and test dependency, then runs the fast unit/CLI and fixture-integrity tests in addition to formatting, linting, and type checking, but not the real Ghidra suite. Fixture regeneration is documented in `tests/fixtures/README.md`.

## Next coding slice

Milestones 2 and 3 are complete and Milestone 4 is partial. What remains, in order of value:

1. Benchmark parallel decompilation on a large binary: wall time, peak JVM memory, and failure behavior. The checked-in fixtures have five functions each and cannot show the difference. Until this is measured, `--workers` defaults conservatively on purpose.
2. Deepen type records with category paths, packing, alignment, provenance, and usage references.
3. Export decompiler-only local variables, not just those Ghidra materializes on the function object.
4. Close the publication gap where readers can briefly observe the output path as absent between the two renames.
5. Add symbol-server/PDB resolution and BSim export once fixtures and infrastructure exist for them.
6. Evaluate `ghidra-cli` or MCP for live queries and writeback into a persistent project.
