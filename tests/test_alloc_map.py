"""Unit tests for the alloc-map builder, driven entirely with fakes.

Reuses the pcode-test fake infrastructure: FakeVarnode, FakeOp, etc.
No embedded Ghidra needed.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

# ── reuse pcode fakes ────────────────────────────────────────────────────
from test_pcode import (
    FakeOp,
    FakeVarnode,
    const,
    fake_func,
    fake_high_function,
    fake_program,
)

from ghidra_decomp.alloc_map import (
    ALLOC_MAP_SCHEMA_VERSION,
    DEFAULT_ALLOCATORS,
    build_alloc_entries,
    build_wrapper_candidate,
    detect_wrappers_from_candidates,
    load_allocators,
    resolve_wrappers,
    serialize_alloc_map,
)
from ghidra_decomp.pcode import VarnodeNamer

# ── helpers ──────────────────────────────────────────────────────────────


def _callee_addr(name="malloc", addr="00406230"):
    """Make a FakeVarnode for a CALL target address."""
    vn = FakeVarnode(int(addr, 16), size=4, space="ram", addr=addr)
    return vn


def _program_with_function(name, addr):
    """Return a fake program whose function manager resolves one function."""
    func_obj = SimpleNamespace(getName=lambda: name)
    return fake_program(functions={addr: func_obj})


def _build(ops, func_name="test_func", callee_name="malloc", callee_addr="00406230"):
    """Run build_alloc_entries with a standard setup."""
    hf = fake_high_function(ops)
    func = fake_func(name=func_name)
    program = _program_with_function(callee_name, callee_addr)
    namer = VarnodeNamer()
    # Pre-populate namer by walking ops (simulates serialization ordering)
    for op in ops:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)
    return build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, ops)


# ── allocator catalogue ──────────────────────────────────────────────────


def test_default_allocators_complete():
    expected = {
        "malloc",
        "calloc",
        "realloc",
        "kmalloc",
        "kzalloc",
        "kcalloc",
        "devm_kmalloc",
        "devm_kzalloc",
        "devm_kcalloc",
        "alloc_skb",
        "strdup",
        "strndup",
        "valloc",
        "pvalloc",
    }
    assert expected <= set(DEFAULT_ALLOCATORS)


def test_load_allocators_no_config():
    result = load_allocators(None)
    assert result == DEFAULT_ALLOCATORS


def test_load_allocators_from_config(tmp_path):
    config = tmp_path / "alloc.json"
    config.write_text(json.dumps({"my_alloc": {"index": 0}}))
    result = load_allocators(config)
    assert "my_alloc" in result
    assert "malloc" in result  # defaults preserved


def test_load_allocators_config_overrides_default(tmp_path):
    config = tmp_path / "alloc.json"
    config.write_text(json.dumps({"malloc": {"index": 1}}))
    result = load_allocators(config)
    assert result["malloc"] == {"index": 1}


# ── size resolution ──────────────────────────────────────────────────────


def test_malloc_const_size():
    target = _callee_addr()
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(64)])
    entries = _build([call])

    assert len(entries) == 1
    e = entries[0]
    assert e["callee"] == "malloc"
    assert e["size"] == 64
    assert e["size_expr"] == "const"
    assert e["size_vn"] is None


def test_calloc_product():
    target = _callee_addr("calloc", "00406240")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(16), const(4)])
    entries = _build([call], callee_name="calloc", callee_addr="00406240")

    assert len(entries) == 1
    e = entries[0]
    assert e["callee"] == "calloc"
    assert e["size"] == 64
    assert e["size_expr"] == "product"


def test_variable_size():
    target = _callee_addr()
    size_vn = FakeVarnode(0x100, space="register")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, size_vn])
    entries = _build([call])

    assert len(entries) == 1
    e = entries[0]
    assert e["size"] is None
    assert e["size_expr"] == "variable"
    assert isinstance(e["size_vn"], str)


# ── store classification ─────────────────────────────────────────────────


def test_store_to_field():
    """CALL → COPY → PTRADD → STORE traces a struct field store."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(64)])

    copied = FakeVarnode(0x201)
    copy = FakeOp("COPY", copied, [alloc_out])

    struct_ptr = FakeVarnode(0x300, space="register")
    ptradd_out = FakeVarnode(0x301)
    ptradd = FakeOp("PTRADD", ptradd_out, [struct_ptr, const(32), const(1)])

    space_id = FakeVarnode(0x1B0, size=4, space="const", const=True)
    store = FakeOp("STORE", None, [space_id, ptradd_out, copied])

    entries = _build([call, copy, ptradd, store])
    assert len(entries) == 1
    assert len(entries[0]["stores"]) == 1
    s = entries[0]["stores"][0]
    assert s["kind"] == "field"
    assert s["field_offset"] == 32


def test_store_to_global():
    """CALL → STORE to a ram-space address is a global store."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(256)])

    global_addr = FakeVarnode(0x601000, space="ram", addr="00601000")
    space_id = FakeVarnode(0x1B0, size=4, space="const", const=True)
    store = FakeOp("STORE", None, [space_id, global_addr, alloc_out])

    entries = _build([call, store])
    assert len(entries) == 1
    assert len(entries[0]["stores"]) == 1
    s = entries[0]["stores"][0]
    assert s["kind"] == "global"


# ── forward flow ─────────────────────────────────────────────────────────


def test_passed_to_call():
    """Alloc result passed as arg to a subsequent CALL."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(64)])

    use_target = _callee_addr("use_buffer", "00407000")
    fake_program(functions={"00407000": SimpleNamespace(getName=lambda: "use_buffer")})
    use_call = FakeOp("CALL", FakeVarnode(0x999), [use_target, alloc_out, const(10)])

    # Build manually to use the multi-function program
    hf = fake_high_function([call, use_call])
    func = fake_func(name="test_func")
    program = fake_program(
        functions={
            "00406230": SimpleNamespace(getName=lambda: "malloc"),
            "00407000": SimpleNamespace(getName=lambda: "use_buffer"),
        }
    )
    namer = VarnodeNamer()
    for op in [call, use_call]:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)

    entries = build_alloc_entries(
        hf, func, program, namer, DEFAULT_ALLOCATORS, [call, use_call]
    )
    assert len(entries) == 1
    assert len(entries[0]["returns"]["passed_to"]) >= 1
    pt = entries[0]["returns"]["passed_to"][0]
    assert pt["callee"] == "use_buffer"
    assert pt["arg_index"] == 0


def test_returned():
    """Alloc result reaching RETURN is tracked."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(64)])

    ret = FakeOp("RETURN", None, [const(0), alloc_out])

    entries = _build([call, ret])
    assert len(entries) == 1
    assert entries[0]["returns"]["returned"] is True


# ── filtering ────────────────────────────────────────────────────────────


def test_non_allocator_ignored():
    """A CALL to printf produces no alloc map entry."""
    target = _callee_addr("printf", "00405000")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(0)])
    entries = _build([call], callee_name="printf", callee_addr="00405000")
    assert entries == []


def test_fallback_heuristic():
    """A callee named 'custom_alloc_buffer' matches the alloc heuristic."""
    target = _callee_addr("custom_alloc_buffer", "00408000")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(128)])

    hf = fake_high_function([call])
    func = fake_func(name="test_func")
    program = fake_program(
        functions={"00408000": SimpleNamespace(getName=lambda: "custom_alloc_buffer")}
    )
    namer = VarnodeNamer()
    namer.id_for(output)
    for inp in call.getInputs():
        if not inp.isConstant():
            namer.id_for(inp)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["callee"] == "custom_alloc_buffer"
    assert entries[0]["size_expr"] == "unknown"


def test_no_allocs_empty():
    """Function with no allocator calls produces empty list."""
    target = _callee_addr("printf", "00405000")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(0)])
    entries = _build([call], callee_name="printf", callee_addr="00405000")
    assert entries == []


def test_multiple_allocs():
    """Two malloc calls in one function produce two entries."""
    target1 = _callee_addr()
    out1 = FakeVarnode(0x200)
    call1 = FakeOp("CALL", out1, [target1, const(64)])

    target2 = _callee_addr()
    out2 = FakeVarnode(0x300)
    call2 = FakeOp("CALL", out2, [target2, const(128)])

    entries = _build([call1, call2])
    assert len(entries) == 2
    sizes = {e["size"] for e in entries}
    assert sizes == {64, 128}


# ── positive edge cases ──────────────────────────────────────────────────


def test_zero_size_malloc():
    """malloc(0) is a valid allocation — should produce an entry with size=0."""
    target = _callee_addr()
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(0)])
    entries = _build([call])

    assert len(entries) == 1
    e = entries[0]
    assert e["size"] == 0
    assert e["size_expr"] == "const"


def test_chained_malloc_then_realloc():
    """malloc followed by realloc in the same function → two entries."""
    malloc_target = _callee_addr("malloc", "00406230")
    realloc_target = _callee_addr("realloc", "00406240")
    p1 = FakeVarnode(0x200)
    call1 = FakeOp("CALL", p1, [malloc_target, const(16)])

    p2 = FakeVarnode(0x300)
    call2 = FakeOp("CALL", p2, [realloc_target, p1, const(256)])

    hf = fake_high_function([call1, call2])
    func = fake_func(name="alloc_chain")
    program = fake_program(
        functions={
            "00406230": SimpleNamespace(getName=lambda: "malloc"),
            "00406240": SimpleNamespace(getName=lambda: "realloc"),
        }
    )
    namer = VarnodeNamer()
    for op in [call1, call2]:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)

    entries = build_alloc_entries(
        hf, func, program, namer, DEFAULT_ALLOCATORS, [call1, call2]
    )
    assert len(entries) == 2
    callees = [e["callee"] for e in entries]
    assert "malloc" in callees
    assert "realloc" in callees
    malloc_entry = next(e for e in entries if e["callee"] == "malloc")
    assert malloc_entry["size"] == 16
    realloc_entry = next(e for e in entries if e["callee"] == "realloc")
    assert realloc_entry["size"] == 256


def test_alloc_through_cast():
    """CALL → CAST → STORE: alloc result flows through a CAST op."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(64)])

    casted = FakeVarnode(0x201)
    cast = FakeOp("CAST", casted, [alloc_out])

    struct_ptr = FakeVarnode(0x300, space="register")
    ptradd_out = FakeVarnode(0x301)
    ptradd = FakeOp("PTRADD", ptradd_out, [struct_ptr, const(8), const(1)])

    space_id = FakeVarnode(0x1B0, size=4, space="const", const=True)
    store = FakeOp("STORE", None, [space_id, ptradd_out, casted])

    entries = _build([call, cast, ptradd, store])
    assert len(entries) == 1
    assert len(entries[0]["stores"]) == 1
    assert entries[0]["stores"][0]["kind"] == "field"


def test_alloc_through_int_add():
    """CALL → INT_ADD → STORE: pointer arithmetic before store."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(128)])

    added = FakeVarnode(0x201)
    add = FakeOp("INT_ADD", added, [alloc_out, const(16)])

    global_addr = FakeVarnode(0x601000, space="ram", addr="00601000")
    space_id = FakeVarnode(0x1B0, size=4, space="const", const=True)
    store = FakeOp("STORE", None, [space_id, global_addr, added])

    entries = _build([call, add, store])
    assert len(entries) == 1
    assert len(entries[0]["stores"]) == 1


def test_alloc_passed_to_two_consumers():
    """Alloc result forwarded to two different calls (fan-out)."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(300)])

    consume_target = _callee_addr("consume", "00407000")
    consume_call = FakeOp("CALL", FakeVarnode(0x900), [consume_target, alloc_out])

    memset_target = _callee_addr("memset_fake", "00407100")
    memset_call = FakeOp(
        "CALL", FakeVarnode(0x901), [memset_target, alloc_out, const(0), const(300)]
    )

    hf = fake_high_function([call, consume_call, memset_call])
    func = fake_func(name="alloc_fanout")
    program = fake_program(
        functions={
            "00406230": SimpleNamespace(getName=lambda: "malloc"),
            "00407000": SimpleNamespace(getName=lambda: "consume"),
            "00407100": SimpleNamespace(getName=lambda: "memset_fake"),
        }
    )
    namer = VarnodeNamer()
    for op in [call, consume_call, memset_call]:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)

    entries = build_alloc_entries(
        hf, func, program, namer, DEFAULT_ALLOCATORS, [call, consume_call, memset_call]
    )
    assert len(entries) == 1
    passed = entries[0]["returns"]["passed_to"]
    callee_names = {pt["callee"] for pt in passed}
    assert "consume" in callee_names
    assert "memset_fake" in callee_names


def test_alloc_store_and_passed_to_same_entry():
    """Alloc result stored to field AND passed to a call in the same function."""
    target = _callee_addr()
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [target, const(512)])

    # Store to struct field
    copied = FakeVarnode(0x201)
    copy = FakeOp("COPY", copied, [alloc_out])
    struct_ptr = FakeVarnode(0x300, space="register")
    ptradd_out = FakeVarnode(0x301)
    ptradd = FakeOp("PTRADD", ptradd_out, [struct_ptr, const(32), const(1)])
    space_id = FakeVarnode(0x1B0, size=4, space="const", const=True)
    store = FakeOp("STORE", None, [space_id, ptradd_out, copied])

    # Also passed to memset_fake
    memset_target = _callee_addr("memset_fake", "00407100")
    memset_call = FakeOp(
        "CALL", FakeVarnode(0x901), [memset_target, copied, const(0), const(512)]
    )

    hf = fake_high_function([call, copy, ptradd, store, memset_call])
    func = fake_func(name="alloc_via_local")
    program = fake_program(
        functions={
            "00406230": SimpleNamespace(getName=lambda: "malloc"),
            "00407100": SimpleNamespace(getName=lambda: "memset_fake"),
        }
    )
    namer = VarnodeNamer()
    for op in [call, copy, ptradd, store, memset_call]:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)

    entries = build_alloc_entries(
        hf,
        func,
        program,
        namer,
        DEFAULT_ALLOCATORS,
        [call, copy, ptradd, store, memset_call],
    )
    assert len(entries) == 1
    assert entries[0]["stores"], "expected a field store"
    assert entries[0]["returns"]["passed_to"], "expected a passed_to entry"


def test_kernel_allocator_kzalloc():
    """kzalloc(size, flags) — size at arg 0, flags at arg 1."""
    target = _callee_addr("kzalloc", "00406300")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(4096), const(0xCC0)])

    hf = fake_high_function([call])
    func = fake_func(name="kern_init")
    program = fake_program(
        functions={
            "00406300": SimpleNamespace(getName=lambda: "kzalloc"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    e = entries[0]
    assert e["callee"] == "kzalloc"
    assert e["size"] == 4096
    assert e["size_expr"] == "const"


def test_devm_kmalloc_size_at_arg1():
    """devm_kmalloc(dev, size, flags) — size is arg 1, not arg 0."""
    target = _callee_addr("devm_kmalloc", "00406400")
    dev_vn = FakeVarnode(0x100, space="register")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, dev_vn, const(256), const(0xCC0)])

    hf = fake_high_function([call])
    func = fake_func(name="probe")
    program = fake_program(
        functions={
            "00406400": SimpleNamespace(getName=lambda: "devm_kmalloc"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)
    namer.id_for(dev_vn)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["size"] == 256
    assert entries[0]["size_expr"] == "const"


def test_kcalloc_product_with_flags():
    """kcalloc(count, size, flags) — product of args 0 and 1."""
    target = _callee_addr("kcalloc", "00406500")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(10), const(32), const(0xCC0)])

    hf = fake_high_function([call])
    func = fake_func(name="kern_alloc")
    program = fake_program(
        functions={
            "00406500": SimpleNamespace(getName=lambda: "kcalloc"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["size"] == 320
    assert entries[0]["size_expr"] == "product"


def test_calloc_one_variable_arg_is_variable():
    """calloc(var, 4) — one variable arg makes the whole size variable."""
    target = _callee_addr("calloc", "00406240")
    count_vn = FakeVarnode(0x100, space="register")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, count_vn, const(4)])

    hf = fake_high_function([call])
    func = fake_func(name="dyn_calloc")
    program = fake_program(
        functions={
            "00406240": SimpleNamespace(getName=lambda: "calloc"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)
    namer.id_for(count_vn)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["size"] is None
    assert entries[0]["size_expr"] == "variable"


# ── negative cases ───────────────────────────────────────────────────────


def test_free_not_treated_as_allocator():
    """free() must not produce an entry even though it takes a pointer."""
    target = _callee_addr("free", "00405100")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, FakeVarnode(0x100, space="register")])

    hf = fake_high_function([call])
    func = fake_func(name="cleanup")
    program = fake_program(
        functions={
            "00405100": SimpleNamespace(getName=lambda: "free"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert entries == []


def test_memcpy_not_treated_as_allocator():
    """memcpy must not match the alloc heuristic."""
    target = _callee_addr("memcpy", "00405200")
    output = FakeVarnode(0x200)
    call = FakeOp(
        "CALL",
        output,
        [
            target,
            FakeVarnode(0x100, space="register"),
            FakeVarnode(0x101, space="register"),
            const(64),
        ],
    )

    hf = fake_high_function([call])
    func = fake_func(name="copier")
    program = fake_program(
        functions={
            "00405200": SimpleNamespace(getName=lambda: "memcpy"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert entries == []


def test_dealloc_not_treated_as_allocator():
    """'dealloc' contains 'alloc' but the heuristic should still match it —
    this tests that the heuristic fires on substring match.  The consumer
    decides whether to trust it."""
    target = _callee_addr("dealloc", "00405300")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, FakeVarnode(0x100, space="register")])

    hf = fake_high_function([call])
    func = fake_func(name="cleanup2")
    program = fake_program(
        functions={
            "00405300": SimpleNamespace(getName=lambda: "dealloc"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    # 'dealloc' contains 'alloc' → heuristic fires, entry with unknown size
    assert len(entries) == 1
    assert entries[0]["size_expr"] == "unknown"


def test_unresolved_callee_produces_no_entry():
    """CALL with no resolved callee name → no entry (can't match allocator list)."""
    target = _callee_addr("malloc", "00406230")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(64)])

    hf = fake_high_function([call])
    func = fake_func(name="test_func")
    # Empty function manager — callee name won't resolve
    program = fake_program(functions={})
    namer = VarnodeNamer()
    namer.id_for(output)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert entries == []


def test_mixed_alloc_and_non_alloc_calls():
    """Only the malloc call produces an entry; printf and free do not."""
    malloc_target = _callee_addr("malloc", "00406230")
    printf_target = _callee_addr("printf", "00405000")
    free_target = _callee_addr("free", "00405100")

    out1 = FakeVarnode(0x200)
    call_malloc = FakeOp("CALL", out1, [malloc_target, const(64)])
    out2 = FakeVarnode(0x201)
    call_printf = FakeOp("CALL", out2, [printf_target, const(0)])
    out3 = FakeVarnode(0x202)
    call_free = FakeOp("CALL", out3, [free_target, out1])

    hf = fake_high_function([call_malloc, call_printf, call_free])
    func = fake_func(name="mixed")
    program = fake_program(
        functions={
            "00406230": SimpleNamespace(getName=lambda: "malloc"),
            "00405000": SimpleNamespace(getName=lambda: "printf"),
            "00405100": SimpleNamespace(getName=lambda: "free"),
        }
    )
    namer = VarnodeNamer()
    for op in [call_malloc, call_printf, call_free]:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)

    entries = build_alloc_entries(
        hf,
        func,
        program,
        namer,
        DEFAULT_ALLOCATORS,
        [call_malloc, call_printf, call_free],
    )
    assert len(entries) == 1
    assert entries[0]["callee"] == "malloc"


def test_empty_ops_list():
    """Empty function (no ops at all) → empty entries."""
    hf = fake_high_function([])
    func = fake_func(name="empty")
    program = fake_program()
    namer = VarnodeNamer()
    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [])
    assert entries == []


def test_strdup_produces_entry_with_null_size():
    """strdup has no explicit size arg → size=None, size_expr=unknown."""
    target = _callee_addr("strdup", "00406600")
    str_vn = FakeVarnode(0x100, space="register")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, str_vn])

    hf = fake_high_function([call])
    func = fake_func(name="dup_str")
    program = fake_program(
        functions={
            "00406600": SimpleNamespace(getName=lambda: "strdup"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)
    namer.id_for(str_vn)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["callee"] == "strdup"
    assert entries[0]["size"] is None
    assert entries[0]["size_expr"] == "unknown"


def test_realloc_size_at_index_1():
    """realloc(ptr, size) — ptr is arg 0, size is arg 1."""
    target = _callee_addr("realloc", "00406240")
    old_ptr = FakeVarnode(0x100, space="register")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, old_ptr, const(1024)])

    hf = fake_high_function([call])
    func = fake_func(name="grow_buf")
    program = fake_program(
        functions={
            "00406240": SimpleNamespace(getName=lambda: "realloc"),
        }
    )
    namer = VarnodeNamer()
    namer.id_for(output)
    namer.id_for(old_ptr)

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["size"] == 1024
    assert entries[0]["size_expr"] == "const"


# ── serialization ────────────────────────────────────────────────────────


def test_serialize_alloc_map_envelope():
    entries = [{"function": "foo", "callee": "malloc"}]
    result = serialize_alloc_map(entries)
    assert result["schema_version"] == ALLOC_MAP_SCHEMA_VERSION
    assert result["entries"] == entries


def test_serialize_alloc_map_empty():
    result = serialize_alloc_map([])
    assert result["schema_version"] == ALLOC_MAP_SCHEMA_VERSION
    assert result["entries"] == []


# ── wrapper detection ───────────────────────────────────────────────────


def _build_wrapper(
    ops, func_name="safe_malloc", callee_name="calloc", callee_addr="00406240"
):
    """Build alloc entries + detect wrapper info for a wrapper function."""
    hf = fake_high_function(ops)
    func = fake_func(name=func_name)
    program = _program_with_function(callee_name, callee_addr)
    namer = VarnodeNamer()
    for op in ops:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)
    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, ops)
    cand = build_wrapper_candidate(entries, ops, DEFAULT_ALLOCATORS)
    wrapper = None
    if cand is not None:
        db = detect_wrappers_from_candidates({func_name: cand}, DEFAULT_ALLOCATORS)
        wrapper = db.get(func_name)
    return entries, wrapper


def test_detect_wrapper_simple():
    """safe_malloc(n) calling calloc(1, n) and returning is a wrapper."""
    param_n = FakeVarnode(0x100, space="register")  # function param, no def
    calloc_target = _callee_addr("calloc", "00406240")
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [calloc_target, const(1), param_n])
    ret = FakeOp("RETURN", None, [const(0), alloc_out])

    entries, wrapper = _build_wrapper([call, ret])
    assert len(entries) == 1
    assert wrapper is not None
    assert wrapper["inner_allocator"] == "calloc"
    assert wrapper["size_spec"] == {"index": 0}
    assert wrapper["chain"] == ["calloc"]


def test_detect_wrapper_malloc():
    """safe_malloc(n) calling malloc(n) is a wrapper with index 0."""
    param_n = FakeVarnode(0x100, space="register")
    malloc_target = _callee_addr("malloc", "00406230")
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [malloc_target, param_n])
    ret = FakeOp("RETURN", None, [const(0), alloc_out])

    _entries, wrapper = _build_wrapper(
        [call, ret], callee_name="malloc", callee_addr="00406230"
    )
    assert wrapper is not None
    assert wrapper["inner_allocator"] == "malloc"
    assert wrapper["size_spec"] == {"index": 0}


def test_detect_wrapper_calloc_passthrough():
    """safe_calloc(count, size) calling calloc(count, size) is a product wrapper."""
    param_count = FakeVarnode(0x100, space="register")
    param_size = FakeVarnode(0x101, space="register")
    calloc_target = _callee_addr("calloc", "00406240")
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [calloc_target, param_count, param_size])
    ret = FakeOp("RETURN", None, [const(0), alloc_out])

    _entries, wrapper = _build_wrapper([call, ret])
    assert wrapper is not None
    assert wrapper["size_spec"] == {"product": [0, 1]}


def test_detect_wrapper_copy_chain():
    """Wrapper with COPY between param and calloc arg still detects."""
    param_n = FakeVarnode(0x100, space="register")
    copied = FakeVarnode(0x101)
    copy_op = FakeOp("COPY", copied, [param_n])
    calloc_target = _callee_addr("calloc", "00406240")
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [calloc_target, const(1), copied])
    ret = FakeOp("RETURN", None, [const(0), alloc_out])

    _entries, wrapper = _build_wrapper([copy_op, call, ret])
    assert wrapper is not None
    assert wrapper["size_spec"] == {"index": 0}


def test_not_wrapper_multiple_allocs():
    """Two malloc calls → not a wrapper."""
    param_n = FakeVarnode(0x100, space="register")
    malloc_target = _callee_addr("malloc", "00406230")
    out1 = FakeVarnode(0x200)
    call1 = FakeOp("CALL", out1, [malloc_target, param_n])
    out2 = FakeVarnode(0x300)
    call2 = FakeOp("CALL", out2, [malloc_target, param_n])
    ret = FakeOp("RETURN", None, [const(0), out1])

    hf = fake_high_function([call1, call2, ret])
    func = fake_func(name="tricky_alloc")
    program = _program_with_function("malloc", "00406230")
    namer = VarnodeNamer()
    for op in [call1, call2, ret]:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)
    entries = build_alloc_entries(
        hf, func, program, namer, DEFAULT_ALLOCATORS, [call1, call2, ret]
    )
    cand = build_wrapper_candidate(entries, [call1, call2, ret], DEFAULT_ALLOCATORS)
    assert cand is None


def test_not_wrapper_no_return():
    """Alloc result neither returned nor stored → not a wrapper."""
    param_n = FakeVarnode(0x100, space="register")
    malloc_target = _callee_addr("malloc", "00406230")
    alloc_out = FakeVarnode(0x200)
    call = FakeOp("CALL", alloc_out, [malloc_target, param_n])
    ret = FakeOp("RETURN", None, [const(0)])

    _entries, wrapper = _build_wrapper(
        [call, ret], callee_name="malloc", callee_addr="00406230"
    )
    assert wrapper is None


# ── wrapper resolution (post-pass) ──────────────────────────────────────


def test_resolve_wrapper_const():
    """Call to safe_malloc(256) resolves to size=256 through wrapper."""
    entry = {
        "function": "use_buffer",
        "function_addr": "00500000",
        "callee": "safe_malloc",
        "callee_addr": "00400100",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"const": 256}],
    }
    wrapper_db = {
        "safe_malloc": {
            "inner_allocator": "calloc",
            "inner_spec": {"product": [0, 1]},
            "size_spec": {"index": 0},
            "chain": ["calloc"],
        },
    }
    resolve_wrappers([entry], wrapper_db, DEFAULT_ALLOCATORS)
    assert entry["size"] == 256
    assert entry["size_expr"] == "const"
    assert entry["unwrapped_via"] == "safe_malloc -> calloc"
    assert "_call_args" not in entry


def test_resolve_wrapper_variable():
    """Call to safe_malloc(len) resolves to variable size through wrapper."""
    entry = {
        "function": "copy_data",
        "function_addr": "00500100",
        "callee": "safe_malloc",
        "callee_addr": "00400100",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"vn": "v5"}],
    }
    wrapper_db = {
        "safe_malloc": {
            "inner_allocator": "calloc",
            "inner_spec": {"product": [0, 1]},
            "size_spec": {"index": 0},
            "chain": ["calloc"],
        },
    }
    resolve_wrappers([entry], wrapper_db, DEFAULT_ALLOCATORS)
    assert entry["size"] is None
    assert entry["size_expr"] == "variable"
    assert entry["size_vn"] == "v5"
    assert entry["unwrapped_via"] == "safe_malloc -> calloc"


def test_resolve_wrapper_chain():
    """opt_malloc(128) → safe_malloc → calloc resolves through 2-level chain."""
    entry = {
        "function": "use_opt",
        "function_addr": "00500200",
        "callee": "opt_malloc",
        "callee_addr": "00400200",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"const": 128}],
    }
    wrapper_db = {
        "opt_malloc": {
            "inner_allocator": "safe_malloc",
            "inner_spec": None,
            "size_spec": {"index": 0},
            "chain": ["safe_malloc"],
        },
        "safe_malloc": {
            "inner_allocator": "calloc",
            "inner_spec": {"product": [0, 1]},
            "size_spec": {"index": 0},
            "chain": ["calloc"],
        },
    }
    resolve_wrappers([entry], wrapper_db, DEFAULT_ALLOCATORS)
    assert entry["size"] == 128
    assert entry["size_expr"] == "const"
    assert entry["unwrapped_via"] == "opt_malloc -> safe_malloc -> calloc"


def test_resolve_wrapper_product():
    """safe_calloc(10, 4) resolves to size=40, product."""
    entry = {
        "function": "use_safe_calloc",
        "function_addr": "00500300",
        "callee": "safe_calloc",
        "callee_addr": "00400300",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"const": 10}, {"const": 4}],
    }
    wrapper_db = {
        "safe_calloc": {
            "inner_allocator": "calloc",
            "inner_spec": {"product": [0, 1]},
            "size_spec": {"product": [0, 1]},
            "chain": ["calloc"],
        },
    }
    resolve_wrappers([entry], wrapper_db, DEFAULT_ALLOCATORS)
    assert entry["size"] == 40
    assert entry["size_expr"] == "product"
    assert entry["unwrapped_via"] == "safe_calloc -> calloc"


def test_resolve_no_unwrap_for_direct():
    """Direct malloc entry has unwrapped_via=null, no _call_args."""
    entry = {
        "function": "test_func",
        "function_addr": "00500000",
        "callee": "malloc",
        "callee_addr": "00406230",
        "call_seq": 1,
        "size": 64,
        "size_expr": "const",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
    }
    resolve_wrappers([entry], {}, DEFAULT_ALLOCATORS)
    assert entry["unwrapped_via"] is None
    assert "_call_args" not in entry


def test_resolve_no_unwrap_for_unknown_heuristic():
    """Heuristic-matched callee not in wrapper_db → stays unknown."""
    entry = {
        "function": "caller",
        "function_addr": "00500000",
        "callee": "tricky_alloc",
        "callee_addr": "00400500",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"const": 512}],
    }
    resolve_wrappers([entry], {}, DEFAULT_ALLOCATORS)
    assert entry["unwrapped_via"] is None
    assert entry["size"] is None
    assert entry["size_expr"] == "unknown"


def test_resolve_wrapper_preserves_stores():
    """Stores at the call site survive unwrapping."""
    stores = [
        {
            "kind": "field",
            "field_offset": 32,
            "field_name": None,
            "base_type": None,
            "store_seq": 2,
            "store_vn": "v3",
        }
    ]
    entry = {
        "function": "wrapper_init_ctx",
        "function_addr": "00500000",
        "callee": "safe_malloc",
        "callee_addr": "00400100",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": stores,
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"const": 64}],
    }
    wrapper_db = {
        "safe_malloc": {
            "inner_allocator": "calloc",
            "inner_spec": {"product": [0, 1]},
            "size_spec": {"index": 0},
            "chain": ["calloc"],
        },
    }
    resolve_wrappers([entry], wrapper_db, DEFAULT_ALLOCATORS)
    assert entry["size"] == 64
    assert entry["unwrapped_via"] == "safe_malloc -> calloc"
    assert entry["stores"] == stores


def test_resolve_wrapper_5_levels():
    """5-level chain: w5 -> w4 -> w3 -> w2 -> w1 -> malloc. Must resolve."""
    entry = {
        "function": "caller",
        "function_addr": "00500000",
        "callee": "w5_alloc",
        "callee_addr": "00400600",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"const": 77}],
    }
    wrapper_db = {}
    for i in range(5, 0, -1):
        name = f"w{i}_alloc"
        inner = f"w{i - 1}_alloc" if i > 1 else "malloc"
        wrapper_db[name] = {
            "inner_allocator": inner,
            "inner_spec": {"index": 0} if inner == "malloc" else None,
            "size_spec": {"index": 0},
            "chain": [inner],
        }
    resolve_wrappers([entry], wrapper_db, DEFAULT_ALLOCATORS)
    assert entry["size"] == 77
    assert entry["size_expr"] == "const"
    assert (
        entry["unwrapped_via"]
        == "w5_alloc -> w4_alloc -> w3_alloc -> w2_alloc -> w1_alloc -> malloc"
    )


def test_resolve_wrapper_cycle_safe():
    """Cycle: a -> b -> a. Must not loop forever."""
    entry = {
        "function": "caller",
        "function_addr": "00500000",
        "callee": "a_alloc",
        "callee_addr": "00400700",
        "call_seq": 1,
        "size": None,
        "size_expr": "unknown",
        "size_vn": None,
        "unwrapped_via": None,
        "stores": [],
        "returns": {"output_vn": "v0", "passed_to": [], "returned": False},
        "_call_args": [{"const": 10}],
    }
    wrapper_db = {
        "a_alloc": {
            "inner_allocator": "b_alloc",
            "inner_spec": None,
            "size_spec": {"index": 0},
            "chain": ["b_alloc"],
        },
        "b_alloc": {
            "inner_allocator": "a_alloc",
            "inner_spec": None,
            "size_spec": {"index": 0},
            "chain": ["a_alloc"],
        },
    }
    resolve_wrappers([entry], wrapper_db, DEFAULT_ALLOCATORS)
    assert entry["unwrapped_via"] is None
    assert entry["size"] is None
