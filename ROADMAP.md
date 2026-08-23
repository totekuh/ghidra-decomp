# Roadmap

## Function context artifacts

- [x] Emit digest-qualified, platform-safe per-function C artifacts.
- [x] Emit adjacent JSON sidecars with the function signature, callers, callees, call-site addresses, referenced strings and globals, parameters, local variables, and stack/register storage.
- [x] Emit digest-qualified assembly artifacts with instruction addresses, raw bytes, and disassembly for every function.
- [x] Link every artifact from `functions.json`, including decompilation status and errors.
- [x] Export generic code and data references rather than limiting xrefs to strings.
- [x] Prepare the completed artifact contract as package version 0.3.0.

## Reproducible analysis

- [x] Add `manifest.json` with a schema version, input SHA-256 and size, Ghidra and tool versions, language/compiler IDs, image base, entry points, analysis settings, output paths, function status counts, and completion status.
- [x] Cache completed analysis by binary hash and analysis settings.
- [x] Add resumable output so interrupted runs keep valid artifacts and retry only missing or failed functions.
- [x] Write the completion manifest last and replace generated indexes atomically.
- [x] Retain a fingerprinted Ghidra project, disabled with `--no-cache`.

## Output efficiency

- [x] Make `all_functions.c` opt-in to avoid duplicate search results, disk use, and peak memory.
- [x] Stream optional combined output instead of retaining every decompiled function in memory.
- [x] Keep per-function artifacts independently readable so analysis does not require joining large global JSON files.
- [ ] Add a local query command that resolves a function by name or address and returns its complete context packet.

## Corpus enrichment

Additive sidecar and index fields that raise analysis quality without changing the
pipeline. Ordered simplest first; each is a separate slice with its own tests.

- [x] Record the thunked function's name and address in the sidecar. `is_thunk` is
  already exported and `getThunkedFunction(True)` is already called when building the
  C header comment, but the target reaches only that comment, so a thunk is a dead end
  in the callgraph.
- [x] Parse the decompiler's own `/* WARNING: ... */` lines out of the emitted C into a
  structured `decompilation.warnings` list. They already appear in the pseudocode as
  prose, where a consumer has to notice them; as a field they tell an agent exactly
  where to distrust the output.
- [x] Export decompiler-only local variables from `HighFunction.getLocalSymbolMap()`.
  `signature.locals` currently comes from `Function.getLocalVariables()`, so a function
  whose C says `Unresolved local var` still reports an empty locals list.
- [x] Deepen type records with category path, alignment, packing, and source archive.
  Shipped with the data and functions that use each type, reached through pointer,
  array, and typedef declarations, and with the built-in name list replaced by a
  `BuiltInDataType` check. On `/usr/bin/true` all 28 types now name a category path and
  a source archive, 11 of them imported from `generic_clib_64` and 17 recovered from the
  binary, and 20 of 28 name at least one user.
- [ ] Add a normalized function hash over the mnemonic sequence, ignoring operands and
  addresses, so identical or statically linked functions can be recognized across
  binaries without a BSim database.
- [ ] Export listing comments (plate, pre, post, end-of-line), which currently carry
  DWARF and analyzer findings that the corpus drops entirely. Likely opt-in, since they
  add bulk on large binaries.
- [ ] Export basic blocks and control-flow edges per function. Larger than the rest and
  a new Ghidra API surface, so it belongs in its own slice.

Every item above ships with unit tests against faked Ghidra objects and an end-to-end
assertion against the checked-in multi-architecture binaries, so a field is proven to
be populated from a real analysis rather than only from a stub.

## Agent integration

- Keep bulk, read-only analysis filesystem-first so agents can use normal search and read tools without interactive Ghidra round-trips.
- Add optional MCP integration only for live queries, renaming, retyping, comments, reanalysis, and writeback to a persistent Ghidra project.
- Batch MCP reads and writes to avoid one tool call per symbol, reference, or instruction.

## Backend evaluation

- Compare maintained Ghidra-based bulk CLI decompilers against the current PyGhidra implementation.
- Evaluate output quality, metadata coverage, caching, project persistence, filtering, parallelism, maintenance, licensing, and integration cost.
- Treat alternative backends as replacements only when they improve the autonomous pipeline rather than merely producing another monolithic C dump.

## Internet survey

Surveyed on 2026-08-15. All candidates use Ghidra's decompiler, so the useful differences are analysis lifecycle, corpus structure, automation, and licensing rather than core pseudocode quality.

| Candidate | Advantages | Gaps for this pipeline | Decision |
| --- | --- | --- | --- |
| [`ghidrecomp`](https://github.com/clearbluejar/ghidrecomp) 0.5.9 | Threaded per-function decompilation, persistent projects, file-level resume, regex filters, PDB symbol servers, GDT application, GZF and BSim export, callgraph rendering, Semgrep/SARIF integration | No structured function/string/symbol/type/section indexes, generic xrefs, normal assembly, stack storage, analysis fingerprint, or raw-binary base/entry/language/compiler controls; cache validity is weak; GPL-3.0 | Do not replace the current exporter. Reimplement its project reuse, bounded parallelism, filtering, symbol/GDT support, GZF/BSim, and optional SAST concepts without copying GPL code. |
| [Official Ghidra `analyzeHeadless`](https://github.com/NationalSecurityAgency/ghidra) with a custom post-script | Supported persistent-project lifecycle, recursive import and processing, analyzer controls, CPU limits, full Java API, Apache-2.0 | No stock AI-readable bulk corpus or resumable per-function manifest; requires maintaining a Java exporter | Keep as a possible execution backend if PyGhidra lifecycle or performance becomes limiting. The current custom exporter remains necessary either way. |
| [`ghidra-cli`](https://github.com/akiselev/ghidra-cli) | Persistent project, structured functions/symbols/types/strings/xrefs, decompile and callgraph commands, conventional CLI suited to agent queries | Function-at-a-time rather than a resumable decompile-all corpus | Evaluate as an optional live-query layer, not as the bulk exporter. |
| [`ghidra-mcp`](https://github.com/bethington/ghidra-mcp) | Persistent projects, broad structured analysis and editing API, batch decompilation, headless operation | MCP overhead and no turnkey filesystem corpus or artifact checkpointing | Candidate for optional writeback and exceptional live queries after the filesystem corpus is built. |
| [`mecha_ghidra`](https://github.com/ghidra-user-jp/mecha_ghidra) | PyGhidra-based multi-target MCP sessions and bounded handling of oversized results | No durable bulk corpus, manifest, or resume system | Borrow context-compaction ideas only. |
| [`Black Widow`](https://github.com/berketez/black-widow) | Broad workspace/report pipeline with native Ghidra analysis and several output formats | Pre-release, limited adoption, unclear resume guarantees, and a much larger dependency surface | Reassess only after independent output and reliability benchmarks. |
| [`Ghidraaas`](https://github.com/Cisco-Talos/Ghidraaas) | Simple REST wrapper around headless Ghidra | Unmaintained and pinned to obsolete Ghidra-era dependencies | Reject. |

### `ghidrecomp` comparison

`ghidrecomp` is the strongest directly comparable turnkey tool, but it optimizes C-file production rather than an evidence-rich analysis corpus. Its best features should become roadmap items here:

- [x] Add bounded parallel decompilation with one `DecompInterface` per worker and explicit per-function timeouts.
- [x] Reuse a fingerprinted persistent Ghidra project and support selective forced reanalysis.
- [x] Add function-name filters and resume only artifacts whose status and fingerprint are valid.
- [x] Add optional GDT application before decompilation. Symbol-server/PDB lookup is still open.
- [x] Add optional GZF export. BSim is still open; it needs a BSim database.
- [x] Add optional Semgrep scanning with SARIF output after corpus generation.
- [x] Benchmark threaded output against serial output for correctness and deterministic indexes. JVM memory use and wall-clock time on a large binary are still unmeasured.

### Pipeline decision

- Keep `ghidra-decomp` as the primary bulk exporter because its machine-readable indexes are already a better base for autonomous analysis.
- Build reproducible caching and resume on top of the completed function artifact contract before adding an interactive bridge.
- Use normal filesystem search and reads for the common path.
- Add `ghidra-cli` or MCP only for queries absent from the corpus and for writeback to persistent projects.
- Benchmark alternatives on the same stripped ELF, PE/PDB, and raw firmware fixtures before adopting any backend.
