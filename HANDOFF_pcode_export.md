# Handoff: high-pcode export for sem-boundcheck

**Audience:** an agent implementing a new export in `ghidra-decomp`.
**Consumer:** `sem-boundcheck` (binary overflow finder). It is being rewritten from
"semgrep + regex over decompiled C" to "data-flow over Ghidra high-pcode." That rewrite
needs facts `ghidra-decomp` does not emit yet. This document is the spec for emitting them.
Nothing here changes existing output; it is purely additive, behind a flag.

## Why

The consumer finds buffer overflows by, per function:

1. locating a **sink** — a memory write whose length is attacker-influenced
   (`memcpy`/`memmove`/`copy_from_user`/`strcpy`/`sprintf`, or an open-coded copy loop),
2. backward-slicing from the sink's **length operand** through the function's data-flow,
3. collecting the **guards** (branch conditions) that dominate the sink, and
4. comparing the permitted length against the **buffer capacity** (stack slot size, or the
   heap allocation size reached by data-flow).

Today ghidra-decomp emits decompiled C, disassembly, and per-function metadata JSON
(`calls`, `references`, `signature`, `stack_frame`, `body_ranges`). That is enough to
*locate* sinks (via `calls`) but **not** enough for steps 2–4: there is no SSA, no
def-use, no pcode. Reconstructing data-flow from the C text or the disassembly is exactly
the fragile approach being abandoned. Ghidra already has all of this in `HighFunction`;
the ask is to serialize it.

Design rule: **ghidra-decomp emits faithful facts, the consumer does the reasoning.** Do
not add a sink name-list, slicing, overflow logic, or any opinion about what is a bug.
Emit structure; the consumer decides.

## What to add

A new flag (suggested `--pcode`) that, for each exported function, writes a sibling file
`<addr>_<hash>_<name>.pcode.json` next to the existing `.c` / `.json` / `.s`. Gate it
behind the flag — this output is large and most runs will not want it. Source everything
from `DecompInterface` → `HighFunction` (i.e. **high** pcode via
`HighFunction.getPcodeOps()`, *not* raw pcode — raw pcode lacks recovered variables and
folded constants, which defeats the purpose).

### 1. SSA pcode op list — the spine

Every `PcodeOpAST` in program order. This alone yields def-use: an op's `output` varnode id
is consumed by any op that lists the same id in `inputs`.

```json
{
  "seq": 42,
  "addr": "0x00087620",
  "op": "INT_ADD",
  "output": {"vn": "u1203", "size": 4, "space": "unique"},
  "inputs": [
    {"vn": "u1200", "size": 4, "space": "register"},
    {"const": 2048, "size": 4}
  ]
}
```

- `seq`: stable integer index into this list (consumers reference ops by it).
- `addr`: the instruction address the op came from (`PcodeOp.getSeqnum().getTarget()`),
  hex string matching the convention used elsewhere. Needed to cross-reference the `.s`
  assembly and to hand an address to a downstream symbolic verifier (angr).
- `op`: pcode opcode mnemonic (`CALL`, `CALLIND`, `CBRANCH`, `LOAD`, `STORE`, `INT_ADD`,
  `INT_LESS`, `INT_SLESS`, `SUBPIECE`, `COPY`, …). Keep the exact Ghidra mnemonic.
- `output`: the output varnode, or `null` for ops without one.
- `inputs`: input varnodes in order. A constant varnode (`space == "const"`) is inlined as
  `{"const": <int>, "size": <bytes>}` rather than an id. Preserve operand order exactly —
  for `CBRANCH` the branch target is input[0] and the condition varnode is input[1], etc.

Varnode object shape (reused everywhere): a unique stable `vn` id string, `size` in bytes,
and `space` (`register` / `unique` / `stack` / `ram` / `const`). The `vn` id must be
stable within the function and must match the ids used in the varnode map below. Signedness
is **not** a varnode property in pcode — it lives in the opcode (`INT_LESS` vs `INT_SLESS`,
`INT_SEXT` vs `INT_ZEXT`); emitting the exact opcode is what carries it. This matters: the
richest real bugs are signed/unsigned and truncation (`SUBPIECE`) in the guard.

### 2. Varnode → HighVariable map

So a varnode resolves to a real recovered variable with a type and a storage location.

```json
{
  "vn": "u1200",
  "highvar": "__n",
  "type": "uint",
  "size": 4,
  "storage": {"kind": "register", "register": "a2"}
}
```

- Include every varnode that maps to a `HighVariable` (merged SSA varnodes can share a
  `highvar` name — that is fine and useful).
- `storage.kind` ∈ `register` / `stack` / `ram` / `unique`; include `register` name or
  `stack_offset` as applicable. Storage is what lets a downstream symbolic tool bind to the
  real operand at a call site.
- `type` as Ghidra renders it; if it is a pointer or array, see item 4.

### 3. Basic-block CFG

So the consumer can tell which guard **dominates** a sink without re-deriving control flow.

```json
{
  "block": 7,
  "start": "0x000875f0",
  "end": "0x0008760c",
  "ops": [40, 41, 42],
  "succ": [8, 12],
  "pred": [6],
  "loop_header": false,
  "back_edges": []
}
```

- One entry per `PcodeBlockBasic`. `ops` are `seq` indices into the op list.
- `succ`/`pred` are block indices (the pcode CFG, which is what matches the op list —
  not the instruction-level CFG).
- `loop_header` / `back_edges`: mark loop back-edges. This lets the consumer detect
  **copy-loop sinks** (a `STORE` inside a loop), not just `memcpy`-style calls — many
  driver overflows are open-coded loops with no call to anchor on. If marking back-edges
  is awkward, emitting the raw edge set is enough and the consumer can find them; say which
  you did.

### 4. Capacity-relevant facts (close the "alloc side" gap)

Comparing length to capacity needs the buffer's size. Two sources, both known to Ghidra,
both painful to reconstruct downstream:

- **Stack / typed-buffer extents.** For each local variable and typed buffer, emit base
  offset + byte size, and for arrays the element size and count. This gives stack-buffer
  capacity directly — the alloc side for stack overflows, which heap-focused analysis
  misses entirely.
  ```json
  {"name": "buf", "storage": {"kind": "stack", "stack_offset": -72},
   "type": "uchar[64]", "size": 64, "array": {"elem_size": 1, "count": 64}}
  ```
  This can extend the existing `signature.locals` rather than be a new block, if cleaner.

- **Resolved constant loads from read-only sections.** When a `LOAD` (or a guard operand)
  reads a global in `.rodata`/`.data` that is effectively constant, inline the resolved
  value on that input: `{"const": N, "from": "0x00123abc"}`. Guards frequently compare
  against a global max rather than an immediate; without this the consumer sees "compares
  against something" and loses the number. Only do this for read-only / provably-constant
  addresses — do not guess at mutable globals.

### 5. Pre-resolved CALL args (optional but high value)

For each `CALL` / `CALLIND`, the argument varnodes already mapped positionally, plus the
resolved callee when known. Saves the consumer from redoing calling-convention recovery
(MIPS a0–a3 + stack, etc.) — precisely the arch-specific logic that made the old consumer
fragile.

```json
{"seq": 51, "op": "CALL", "callee": "memcpy", "callee_addr": "0x00128104",
 "args": ["u1300", "u1200", {"const": 0}]}
```

Prefer Ghidra's own parameter analysis (`HighFunction`/`FunctionPrototype`) so this stays
correct across architectures.

## Envelope / conventions

Wrap the above in one object per function:

```json
{
  "schema_version": 1,
  "function": "RTMPDeFragmentDataFrame",
  "entry": "0x00087514",
  "body_ranges": [{"start": "0x00087514", "end": "0x000878ff"}],
  "arch": "MIPS:BE:32:default",
  "ops": [ ... ],
  "varnodes": [ ... ],
  "blocks": [ ... ],
  "calls": [ ... ]
}
```

- Match the existing filename convention (`<addr>_<hash>_<name>`), hex-string address
  format, and the `schema_version` pattern already used by the per-function JSON.
- Keep addresses as hex strings consistent with current output.
- If a function fails to produce a `HighFunction` (decompiler error, thunk), skip it or
  emit `{"function": ..., "error": "..."}` — mirror how the existing `.json` reports
  `decompilation.status`.
- Register the artifact in the per-function `.json` `artifacts` map (it currently lists
  `assembly` and `pseudocode`); add a `pcode` entry pointing at the new file so consumers
  discover it the same way.

## Acceptance check

Validate against the reference function `RTMPDeFragmentDataFrame` (addr `0x00087514`) in
the `mt_wifi.ko` sample, the one `sem-boundcheck` uses as its golden overflow:

- the `memmove` call sites appear as `CALL` ops with resolved `callee` and `args`,
- the length argument varnode of the overflowing `memmove` is traceable backward through
  `ops` to the guard comparison (`INT_LESS`/`INT_SLESS` against a constant near `0x92a`),
- the guard's `CBRANCH` block dominates the sink block in `blocks`,
- the `RTMP_AllocateFragPacketBuffer(..., 0x800)` call exposes its `0x800` size arg as a
  `const` input.

If a consumer can recover (sink, length operand, dominating guard, alloc size) for that
function from the `.pcode.json` **alone** — no `.c`, no `.s`, no regex — the export is
complete.

## Out of scope (do not add here)

Sink name-lists, the backward-slice algorithm, overflow/satisfiability decisions, symbolic
execution, any cross-function analysis. Those live in `sem-boundcheck`. This export is
facts only.
