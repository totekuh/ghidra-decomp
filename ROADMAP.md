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
- [~] ~~Cache completed analysis by binary hash and analysis settings.~~ Removed: each run uses a fresh temporary project.
- [x] Add resumable output so interrupted runs keep valid artifacts and retry only missing or failed functions.
- [x] Write the completion manifest last and replace generated indexes atomically.
- [~] ~~Retain a fingerprinted Ghidra project, disabled with `--no-cache`.~~ Removed.

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

## Decompilation polish

Post-decompilation transforms that improve C readability without changing semantics.
Applied by default; `--no-polish` emits raw Ghidra output. Each transform is a pure
function (C string in, C string out) in the `ghidra_decomp.polish` subpackage, tested
independently with C snippets and no Ghidra dependency. Transforms run in sequence
after decompilation, before writing the per-function artifact. The sidecar records
`polished: true|false`. A transform that produces unparseable output falls back to the
original and logs a warning.

Parsing uses tree-sitter-c for AST-level rewrites. Transforms are applied in the order
listed; earlier passes may simplify later ones.

### Core transforms

- [ ] **Dead variable elimination.** Remove locals that are assigned but never read.
  Single-pass liveness on the tree-sitter AST. Simplest transform; reduces noise in
  every function.
- [ ] **Redundant cast removal.** Strip casts where the operand type already matches the
  target type (`(int)int_var`, `(long)(long)x`, identity casts through typedefs).
  Syntax-only pass on cast expressions.
- [ ] **Boolean simplification.** `x != 0` to `x`, `x == 0` to `!x` in boolean
  contexts (if/while/for conditions, logical operators). Collapse double negation
  (`!!x` to `x`, `!(a != b)` to `a == b`).
- [x] **Loop normalization.** Detect while/do-while loops with an initializer before the
  loop, a condition check, and an increment at the loop bottom, and rewrite as `for`
  loops. Also fills empty for-initializers and converts `while(1) { if(c) break; }`
  to `while(!c)`. Highest readability impact; most complex transform.

### Extended transforms

- [ ] **Goto reduction.** Apply structured control-flow recovery (Yakdan's "No More
  Gotos" algorithm or a subset) to eliminate reducible gotos. Larger, depends on
  dominance/post-dominance analysis on the C AST.
- [ ] **vtable reconstruction.** Detect contiguous function-pointer arrays in
  `.rodata`/`.data.rel.ro`, synthesize named structs, rewrite indirect calls like
  `*(code **)(*(long *)obj + 0x18))(obj)` as `obj->vtable->method(obj)`. Needs
  section data from the sidecar; C++ binaries only.
- [ ] **Struct field synthesis.** When repeated `*(type *)(base + offset)` patterns
  appear across functions, synthesize struct definitions and rewrite accesses as
  `s->field_0x10`.

### Pre-decompilation quality flags

- [ ] **Decompiler timeout control.** `--decompile-timeout` to override Ghidra's default
  per-function decompiler timeout. Complex functions get better output at the cost of
  wall-clock time.
- [ ] **Aggressive analyzer preset.** `--aggressive` enables Aggressive Instruction
  Finder, Decompiler Parameter ID, and other off-by-default analyzers before
  decompilation.

### LLM-assisted enrichment (optional, not on by default)

- [ ] **Semantic variable renaming.** Feed function context packets to an LLM for
  meaningful variable names. Post-process only; original names preserved in sidecar.
- [ ] **Idiom annotation.** Recognize crypto constants, hash loops, serialization
  patterns via LLM. Structured metadata in sidecar, not inline comments.

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
| [`ghidrecomp`](https://github.com/clearbluejar/ghidrecomp) 0.5.9 | Threaded per-function decompilation, persistent projects, file-level resume, regex filters, PDB symbol servers, GDT application, GZF and BSim export, callgraph rendering, Semgrep/SARIF integration | No structured function/string/symbol/type/section indexes, generic xrefs, normal assembly, stack storage, analysis fingerprint, or raw-binary base/entry/language/compiler controls; GPL-3.0 | Do not replace the current exporter. Reimplement its bounded parallelism, filtering, symbol/GDT support, GZF/BSim, and optional SAST concepts without copying GPL code. |
| [Official Ghidra `analyzeHeadless`](https://github.com/NationalSecurityAgency/ghidra) with a custom post-script | Supported persistent-project lifecycle, recursive import and processing, analyzer controls, CPU limits, full Java API, Apache-2.0 | No stock AI-readable bulk corpus or resumable per-function manifest; requires maintaining a Java exporter | Keep as a possible execution backend if PyGhidra lifecycle or performance becomes limiting. The current custom exporter remains necessary either way. |
| [`ghidra-cli`](https://github.com/akiselev/ghidra-cli) | Persistent project, structured functions/symbols/types/strings/xrefs, decompile and callgraph commands, conventional CLI suited to agent queries | Function-at-a-time rather than a resumable decompile-all corpus | Evaluate as an optional live-query layer, not as the bulk exporter. |
| [`ghidra-mcp`](https://github.com/bethington/ghidra-mcp) | Persistent projects, broad structured analysis and editing API, batch decompilation, headless operation | MCP overhead and no turnkey filesystem corpus or artifact checkpointing | Candidate for optional writeback and exceptional live queries after the filesystem corpus is built. |
| [`mecha_ghidra`](https://github.com/ghidra-user-jp/mecha_ghidra) | PyGhidra-based multi-target MCP sessions and bounded handling of oversized results | No durable bulk corpus, manifest, or resume system | Borrow context-compaction ideas only. |
| [`Black Widow`](https://github.com/berketez/black-widow) | Broad workspace/report pipeline with native Ghidra analysis and several output formats | Pre-release, limited adoption, unclear resume guarantees, and a much larger dependency surface | Reassess only after independent output and reliability benchmarks. |
| [`Ghidraaas`](https://github.com/Cisco-Talos/Ghidraaas) | Simple REST wrapper around headless Ghidra | Unmaintained and pinned to obsolete Ghidra-era dependencies | Reject. |

### `ghidrecomp` comparison

`ghidrecomp` is the strongest directly comparable turnkey tool, but it optimizes C-file production rather than an evidence-rich analysis corpus. Its best features should become roadmap items here:

- [x] Add bounded parallel decompilation with one `DecompInterface` per worker and explicit per-function timeouts.
- [~] ~~Reuse a fingerprinted persistent Ghidra project and support selective forced reanalysis.~~ Removed; each run uses a fresh project.
- [x] Add function-name filters and resume only artifacts whose status and fingerprint are valid.
- [x] Add optional GDT application before decompilation. Symbol-server/PDB lookup is still open.
- [x] Add optional GZF export. BSim is still open; it needs a BSim database.
- [x] Add optional Semgrep scanning with SARIF output after corpus generation.
- [x] Benchmark threaded output against serial output for correctness and deterministic indexes. JVM memory use and wall-clock time on a large binary are still unmeasured.

### Feature gaps vs ghidrecomp (2026-11-11)

Concrete features ghidrecomp ships that we lack, ordered by implementation effort.

#### Completed

- [x] **JVM memory tuning.** `--max-ram-percent` (default 50) and `--print-jvm-flags`
  passed to PyGhidra's HeadlessPyGhidraLauncher via `add_vmargs()`.

- [x] **Mermaid callgraph rendering.** `--mermaid` writes per-function `.md` flowcharts,
  a whole-graph `callgraph.md`, and `endpoints.json` from existing callgraph data.

- [x] **Verbose analysis monitor.** `--verbose-analysis` attaches a console TaskMonitor
  during Ghidra auto-analysis.

- [x] **CppExporter header mode.** `--cpp-export` invokes Ghidra's `CppExporter()`
  to produce a single `.c` + `.h` with all types.

- [x] **Docker packaging.** Dockerfile + docker-compose.yml with Ghidra pre-installed
  on eclipse-temurin:21-jdk-noble.

- [x] **Callgraph reachability and path queries.** BFS reachability, DFS all-paths,
  endpoint detection, multi-hop neighborhood BFS, graph condensation, extended Mermaid
  renderers (paths, neighborhood, condensed). Export-time: `--callgraph-depth`,
  `--condense-threshold`, `--reachable`. Standalone: `ghidra-decomp-query` with
  `reachable`, `endpoints`, `paths` subcommands (no Ghidra needed).

#### Medium effort

- [ ] **BSim signature export.** `--bsim` to generate feature-vector XML per function
  via `BSim.generateSignatures()`. Needs BSim module present in Ghidra install.
  Medium because the BSim Java API is underdocumented and signatures are only useful
  with a BSim database for queries (which ghidrecomp also lacks).

- [ ] **Analysis persistence option.** ghidrecomp keeps a persistent Ghidra project
  per binary (`<name>-<md5[:6]>`) so re-runs skip analysis. We removed this for
  Ghidra 12 dot-path issues, but a `--keep-project` flag that preserves the temp
  project after export would let users re-run faster. Medium because the dot-path
  rejection needs a workaround.

#### Larger effort

- [ ] **PDB symbol server integration.** Auto-configure Ghidra's local symbol store,
  register well-known remote servers (MS, Chrome, Mozilla, Intel, NVIDIA, AMD),
  enable remote PDB download during analysis. Flags: `--sym-file-path` (local PDB),
  `--symbols-path` (local store), `--skip-symbols`. This is the biggest practical
  gap for Windows RE work. Larger because it touches Ghidra's `PdbPlugin` and symbol
  server API, needs Windows PE test fixtures, and has network-dependent behavior.

- [ ] **Function similarity hashing (replaces BSim for offline use).** Normalized
  mnemonic-sequence hash per function (already in corpus enrichment above). Combined
  with per-function artifacts, this lets agents match functions across binaries
  without a BSim database. The hash computation is simple; the cross-binary query
  tooling is the work.

### Pipeline decision

- Keep `ghidra-decomp` as the primary bulk exporter because its machine-readable indexes are already a better base for autonomous analysis.
- Build on the completed function artifact contract and `--resume` before adding an interactive bridge.
- Use normal filesystem search and reads for the common path.
- Add `ghidra-cli` or MCP only for queries absent from the corpus and for writeback to persistent projects.
- Benchmark alternatives on the same stripped ELF, PE/PDB, and raw firmware fixtures before adopting any backend.
