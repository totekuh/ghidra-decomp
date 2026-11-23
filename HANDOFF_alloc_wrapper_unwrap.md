# Handoff: allocator wrapper unwrapping for `--alloc-map`

**Audience:** an agent working on `ghidra-decomp`.
**Consumer:** `binprobe` and any tool reading `alloc_map.json`.
**Depends on:** `--alloc-map` (HANDOFF_alloc_map.md), already implemented.

## Problem

`alloc_map.json` records allocation call sites, but when a binary uses wrapper
functions around `malloc`/`calloc`/etc., the alloc map sees the wrapper call and
reports `size: null, size_expr: "unknown"` because the wrapper's name isn't in the
known allocator list and its size argument isn't resolved.

Real-world example from dnsmasq v2.77 (CVE-2017-14491 test binary):

```c
// safe_malloc — trivial wrapper
void *safe_malloc(size_t param_1) {
    void *p = calloc(1, param_1);
    if (!p) die("could not get memory", 0, 4);
    return p;
}

// whine_malloc — trivial wrapper
void *whine_malloc(ulong param_1) {
    void *p = calloc(1, param_1);
    if (!p) my_syslog(3, "failed to allocate %d bytes", param_1 & 0xffffffff);
    return p;
}
```

Both call `calloc(1, param_1)` and return the result. The alloc map has 349 entries
for this binary but only 1 with a concrete size — every other allocation goes through
these wrappers.

The same pattern appears in kernel code (`__kmalloc` wrappers), embedded firmware
(custom `os_alloc_mem`), and userspace projects (`xmalloc`, `g_malloc`, etc.).

## Solution

When `--alloc-map` encounters a call to an unknown function whose name matches the
fallback heuristic (`*alloc*`), inspect the callee's decompiled pcode to determine
if it's a simple wrapper around a known allocator. If so, resolve the size argument
through the wrapper.

### Definition of "simple wrapper"

A function is a simple allocator wrapper if ALL of the following hold:

1. It calls exactly one known allocator (from the built-in list or `--alloc-map-config`).
2. The known allocator's return value reaches the wrapper's RETURN (possibly through
   COPY/CAST, an error check branch, or a NULL check — but not through a second
   allocation or a STORE to a global/field that's also read back).
3. The known allocator's size argument traces back (through COPY/CAST only, no
   arithmetic) to one of the wrapper's parameters.

When these hold:
- The wrapper's size argument index is the parameter that feeds the inner allocator's
  size argument.
- The wrapper is functionally equivalent to the inner allocator for sizing purposes.

### What to emit

When a wrapper is identified, the alloc map entry at the CALL SITE (in the caller)
should resolve through the wrapper:

```json
{
  "function": "rehash",
  "callee": "safe_malloc",
  "callee_addr": "00110640",
  "size": 512,
  "size_expr": "const",
  "size_vn": null,
  "unwrapped_via": "safe_malloc -> calloc",
  "stores": [...]
}
```

- `size` is now resolved (512, from the constant passed to `safe_malloc`).
- `size_expr` is `"const"` (the wrapper's argument at the call site is constant).
- `unwrapped_via` is a new field documenting the unwrap chain for debugging. Format:
  `"wrapper_name -> inner_allocator"`. Null when no unwrapping occurred.

When the wrapper's argument at the call site is variable, emit:

```json
{
  "size": null,
  "size_expr": "variable",
  "size_vn": "v42",
  "unwrapped_via": "safe_malloc -> calloc"
}
```

The `size_vn` now points to the caller's varnode for the wrapper's size argument
(the same varnode the consumer would backward-slice in the caller's pcode).

### Depth limit

Superseded during implementation: unwrap depth is uncapped, with cycle
protection (a wrapper chain that revisits a callee stops; unit-tested with a
5-level chain and a cyclic chain). The original 2-level cap was dropped
because bounded depth bought no safety the cycle check doesn't already
provide.

### Multi-path wrappers (opt_malloc shape)

A function with several allocator call sites is still a simple wrapper when
every site is store-free, returns its result, and derives the *same* size
spec (same param index, or same product pair). dnsmasq's `opt_malloc`
(`mem_recover ? whine_malloc(n) : safe_malloc(n)`) is the motivating shape.
Still rejected: arithmetic fallbacks (`tricky_alloc`: `malloc(n / 2)`) and
disagreeing size params (`pick_alloc(n, m)`). Bounded at 4 allocator sites
per wrapper.

### Product-sink wrappers (calloc-style)

`safe_malloc(n)` calls `calloc(1, n)` — the size is `1 * n = n`. When the inner
allocator is `calloc(count, size)` and one argument is constant 1, the effective
size is the other argument. This is already how binprobe handles `calloc` in
`ALLOC_SPECS`. The unwrap should compute the product when both inner args are
constant, or identify which wrapper param maps to the variable arg.

### Chained wrappers

`opt_malloc(n)` calls `safe_malloc(n)` which calls `calloc(1, n)`. The unwrap
should follow the chain:

1. `opt_malloc` calls `safe_malloc` — not a known allocator, check if it's a wrapper.
2. `safe_malloc` calls `calloc` — known allocator, size arg = param_1.
3. `safe_malloc`'s param_1 traces to `opt_malloc`'s param_0.
4. Result: `opt_malloc` is an allocator with size at param_0, through chain
   `opt_malloc -> safe_malloc -> calloc`.

### Edge cases to skip (not wrappers)

- Function calls multiple allocators (allocator + realloc on error path) — skip.
- Allocator result stored to global before returning — not a simple pass-through, skip.
- Size argument has arithmetic applied (`malloc(n + 16)` for a header) — skip for now.
  The consumer can't trust the outer size as the usable buffer size.
- Function doesn't return the allocator's result — skip (it's not a wrapper, it's a
  consumer).

## Test fixtures

Create these as C source files that can be compiled and decompiled to verify the
unwrap behavior. Each fixture should produce a specific `alloc_map.json` shape.

### Fixture 1: simple wrapper, constant size (`test_wrapper_const.c`)

```c
#include <stdlib.h>

void *safe_malloc(size_t n) {
    void *p = calloc(1, n);
    if (!p) abort();
    return p;
}

void use_buffer(void) {
    char *buf = safe_malloc(256);
    buf[0] = 'x';
}
```

**Expected alloc_map entry for `use_buffer`:**
```json
{
  "function": "use_buffer",
  "callee": "safe_malloc",
  "size": 256,
  "size_expr": "const",
  "unwrapped_via": "safe_malloc -> calloc"
}
```

### Fixture 2: simple wrapper, variable size (`test_wrapper_variable.c`)

```c
#include <stdlib.h>

void *safe_malloc(size_t n) {
    void *p = malloc(n);
    if (!p) abort();
    return p;
}

void copy_data(void *src, size_t len) {
    char *buf = safe_malloc(len);
    memcpy(buf, src, len);
}
```

**Expected alloc_map entry for `copy_data`:**
```json
{
  "function": "copy_data",
  "callee": "safe_malloc",
  "size": null,
  "size_expr": "variable",
  "size_vn": "<varnode for len>",
  "unwrapped_via": "safe_malloc -> malloc"
}
```

### Fixture 3: two-level wrapper chain (`test_wrapper_chain.c`)

```c
#include <stdlib.h>

void *safe_malloc(size_t n) {
    void *p = calloc(1, n);
    if (!p) abort();
    return p;
}

void *opt_malloc(size_t n) {
    return safe_malloc(n);
}

void use_opt(void) {
    char *buf = opt_malloc(128);
    buf[0] = 'y';
}
```

**Expected alloc_map entry for `use_opt`:**
```json
{
  "function": "use_opt",
  "callee": "opt_malloc",
  "size": 128,
  "size_expr": "const",
  "unwrapped_via": "opt_malloc -> safe_malloc -> calloc"
}
```

### Fixture 4: wrapper with field store (`test_wrapper_field_store.c`)

```c
#include <stdlib.h>
#include <string.h>

struct ctx {
    char *buf;
    int len;
};

void *safe_malloc(size_t n) {
    void *p = malloc(n);
    if (!p) abort();
    return p;
}

void init_ctx(struct ctx *c) {
    c->buf = safe_malloc(64);
    c->len = 64;
}
```

**Expected alloc_map entry for `init_ctx`:**
```json
{
  "function": "init_ctx",
  "callee": "safe_malloc",
  "size": 64,
  "size_expr": "const",
  "unwrapped_via": "safe_malloc -> malloc",
  "stores": [
    {
      "kind": "field",
      "field_offset": 0,
      "field_name": "buf"
    }
  ]
}
```

This is the key case for cross-function capacity recovery: `init_ctx` allocates 64
bytes and stores to field offset 0. Another function does `memcpy(c->buf, src, len)`
— the consumer matches field offset 0 to get capacity = 64.

### Fixture 5: NOT a wrapper — multiple allocators (`test_not_wrapper.c`)

```c
#include <stdlib.h>

void *tricky_alloc(size_t n) {
    void *p = malloc(n);
    if (!p) p = malloc(n / 2);  // fallback to smaller
    return p;
}

void use_tricky(void) {
    char *buf = tricky_alloc(512);
    buf[0] = 'z';
}
```

**Expected:** `tricky_alloc` is NOT unwrapped (two malloc calls). Entry has
`size: null, size_expr: "unknown", unwrapped_via: null`.

### Fixture 6: NOT a wrapper — arithmetic on size (`test_not_wrapper_arith.c`)

```c
#include <stdlib.h>

void *header_alloc(size_t payload) {
    return malloc(payload + 16);  // 16-byte header
}

void use_header(void) {
    char *buf = header_alloc(100);
    buf[0] = 'a';
}
```

**Expected:** `header_alloc` is NOT unwrapped (arithmetic on size arg). The usable
buffer is not `payload` bytes — it's `payload + 16` minus the header. Unsafe to
report `size: 100`. Entry has `size: null, size_expr: "unknown", unwrapped_via: null`.

### Fixture 7: calloc wrapper with product (`test_wrapper_calloc.c`)

```c
#include <stdlib.h>

void *safe_calloc(size_t count, size_t size) {
    void *p = calloc(count, size);
    if (!p) abort();
    return p;
}

void use_calloc(void) {
    int *arr = safe_calloc(10, sizeof(int));
    arr[0] = 42;
}
```

**Expected:**
```json
{
  "function": "use_calloc",
  "callee": "safe_calloc",
  "size": 40,
  "size_expr": "product",
  "unwrapped_via": "safe_calloc -> calloc"
}
```

## Acceptance criteria

1. All 7 fixtures compile, decompile, and produce the expected `alloc_map.json` shape.
2. Fixtures 5 and 6 are correctly identified as NOT wrappers.
3. The dnsmasq binary (`tests/e2e/cve/CVE-2017-14491/dnsmasq` in binprobe) produces
   alloc_map entries with resolved sizes through `safe_malloc`/`whine_malloc`/`opt_malloc`.
4. Unwrap depth is capped at 2 levels.
5. `unwrapped_via` field present on every entry (null when no unwrap, chain string
   when unwrapped).
6. No change to entries that already resolve directly (known allocators with constant
   size args remain unchanged).
7. Performance: wrapper analysis is per-function, bounded by function count. Should add
   negligible time on top of the existing `--alloc-map` pass.

## Implementation status (complete)

Implemented on branch `feature/alloc-wrapper-unwrap`. Deviations from the
spec above, all deliberate:

- Depth is uncapped with cycle protection (see above), not capped at 2.
- Multi-path wrappers are accepted (see above).
- The 7 fixture programs live in one `tests/fixtures/alloc_wrapper.c` compiled
  by the Docker crossbuild for 6 architectures, not 7 separate files.

## Verification against dnsmasq v2.77 (CVE-2017-14491 binary)

`ghidra-decomp <dnsmasq> --alloc-map`: 349 entries (matches the baseline
count), 169 unwrapped (`safe_malloc -> calloc` 103, `whine_malloc -> calloc`
66), concrete sizes 120 vs 1 before. `rehash`'s entry reproduces the example
shape exactly (`size: 512, size_expr: "const"`).

Known misses, both Ghidra-side, not wrapper-detection defects:

1. **84 sites stay `unknown`:** dnsmasq's `opt_malloc` macro expands to
   `mem_recover ? whine_malloc(n) : safe_malloc(n)`; on the `whine` branch
   the longjmp recovery path breaks the decompiler's dataflow, so the CALL op
   carries no size-argument varnode at all. There is nothing to resolve.
   `--aggressive` (Decompiler Parameter ID) is NOT a workaround: it commits
   14-parameter signatures and forwards whole register blobs, collapsing
   concrete sizes 120 -> 9 (8 of them invented `size: 0`). Default analysis is
   the right mode.
2. **`opt_malloc` itself is not detected in this binary:** Ghidra recovers it
   as `void opt_malloc(void)` — no parameters, no return value — so the
   return-reaches-RETURN check fails. Its 4 caller sites (constants 128/56/
   128) therefore stay `unknown`. The shape itself is supported and e2e-tested
   (`two_path_alloc` fixture, x86-32 + mipsel); well-formed pcode unwraps.

Consumer note (binprobe, CVE-2017-14491 refind): the reply buffer allocation
is visible — `main`'s `daemon->packet = safe_malloc(edns_pktsz)` is a field
store with `size_expr: "variable"` and chain `safe_malloc -> calloc`. The
xfail reason in `cve.toml` (caller-supplied destination, interprocedural
capacity linking) remains binprobe-side work; the allocation facts it needs
are now in `alloc_map.json`.

