# Polish pipeline

By default `ghidra-decomp` post-processes every decompiled function through a
pipeline of small, semantics-preserving rewrites that make Ghidra's pseudocode
easier to read. Pass `--no-polish` to disable it and keep Ghidra's raw output.

The pipeline parses each function's C with tree-sitter, applies the transforms
below in order, and re-parses the result; if the rewritten code no longer parses
cleanly, that function falls back to the raw output. Each function's sidecar
JSON records a `polished` boolean so you can tell which output you are reading.

## Transforms

Applied in this order:

1. **dead_vars** — remove variables that are declared and assigned but never read.
2. **bool_simplify** — drop redundant `!= 0` / `== 0` comparisons and double
   negations in boolean contexts.
3. **loop_normalize** — rewrite `while` loops with a clear initializer, condition,
   and bottom increment into `for` loops; fill empty `for` initializers; convert
   `while (1) { if (c) break; ... }` into `while (!c)`.
4. **struct_fields** — when a base pointer is accessed at several fixed offsets,
   synthesize a `struct` typedef and rewrite `*(T *)(base + 0x10)` as
   `((_struct_base *)base)->field_0x10`.
5. **compound_assign** — fold `x = x + 1` into `x += 1` for arithmetic, bitwise,
   and shift operators, including pointer derefs, subscripts, and field accesses.
6. **return_simplify** — collapse a trailing `if (cond) { return 1; } return 0;`
   into `return cond;` (negating for the inverted form).
7. **ternary_synthesis** — rewrite `if (c) { x = a; } else { x = b; }` as
   `x = c ? a : b;` when both branches assign the same variable with no side
   effects.
8. **goto_reduce** — invert the one provably safe goto shape: a same-block forward
   `if (cond) goto L; <S> L:` becomes `if (!cond) { <S> }`, keeping the label.
   No other goto patterns are touched.
9. **nested_if_flatten** — merge `if (a) { if (b) { ... } }` into
   `if (a && b) { ... }`.
10. **vtable_synthesis** — on stripped C++ binaries, detect double-deref
    `(**(code **)(*obj + 0x8))(...)` virtual dispatch, synthesize vtable/object
    typedefs, and rewrite calls as `((_vobj *)obj)->_vtable->vfunc_0x8(...)`.

## Guarantees

- **Semantics preserved.** Every transform is a syntactic rewrite that keeps the
  program's behavior; it never reorders side effects or changes control flow
  meaning.
- **Fail-safe.** If a rewrite would produce code that no longer parses, that
  function keeps its raw decompiled output. Polish never corrupts a function.
- **Opt-out.** `--no-polish` disables the whole pipeline. The decompiled output
  is otherwise identical to prior raw behavior.

## Related invocation options

These are not part of the rewrite pipeline but affect the pseudocode Ghidra
produces before polish runs:

- `--aggressive` — enable Ghidra's off-by-default Decompiler Parameter ID
  analyzer for better parameter and return-type recovery (slower).
- `--max-payload-mb` — raise Ghidra's per-function decompiler payload cap to
  rescue very large functions that otherwise fail to decompile.
