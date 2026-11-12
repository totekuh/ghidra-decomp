"""Unit tests for the decompilation polish pipeline."""

from __future__ import annotations

from ghidra_decomp.polish import polish
from ghidra_decomp.polish._parser import is_parseable
from ghidra_decomp.polish.bool_simplify import simplify_booleans
from ghidra_decomp.polish.cast_cleanup import remove_redundant_casts
from ghidra_decomp.polish.dead_vars import eliminate_dead_variables
from ghidra_decomp.polish.loop_normalize import normalize_loops
from ghidra_decomp.polish.prelude import (
    GHIDRA_PRELUDE,
    inject_prelude,
    strip_prelude,
)
from ghidra_decomp.polish.struct_fields import synthesize_struct_fields

P = GHIDRA_PRELUDE


# ── Prelude ──────────────────────────────────────────────────────────


def test_inject_then_strip_is_identity():
    code = "int foo(void) { return 0; }\n"
    assert strip_prelude(inject_prelude(code)) == code


def test_injected_prelude_makes_ghidra_types_parseable():
    code = P + "undefined8 FUN_001(undefined4 p) { return p; }\n"
    assert is_parseable(code)


def test_strip_removes_only_prelude_lines():
    extra = "/* user comment */\n"
    code = extra + P + "int f(void) { return 0; }\n"
    stripped = strip_prelude(code)
    assert "user comment" in stripped
    assert "__GHIDRA_PRELUDE" not in stripped


# ── Dead variable elimination ────────────────────────────────────────


def _dv(body: str) -> str:
    code = P + body
    result = eliminate_dead_variables(code)
    return strip_prelude(result)


def test_removes_write_only_local():
    code = """\
uint f(uint p) {
    uint dead;
    uint live;
    dead = p * 3;
    live = p + 1;
    return live;
}
"""
    result = _dv(code)
    assert "dead" not in result
    assert "live" in result


def test_keeps_read_variable():
    code = """\
uint f(uint p) {
    uint x;
    x = p + 1;
    return x;
}
"""
    result = _dv(code)
    assert "x = p + 1" in result
    assert "return x" in result


def test_keeps_volatile_variable():
    code = """\
uint f(uint p) {
    volatile uint v;
    v = p;
    return 0;
}
"""
    result = _dv(code)
    assert "v = p" in result


def test_keeps_address_taken_variable():
    code = """\
uint f(uint p) {
    uint x;
    x = 5;
    other(&x);
    return 0;
}
"""
    result = _dv(code)
    assert "x = 5" in result


def test_dead_var_with_call_preserves_call():
    code = """\
uint f(uint p) {
    uint dead;
    dead = some_func(p);
    return 0;
}
"""
    result = _dv(code)
    assert "dead" not in result
    assert "some_func(p);" in result


def test_removes_multiple_dead_assignments():
    code = """\
uint f(uint p) {
    uint dead;
    dead = p * 1;
    dead = p * 2;
    dead = p * 3;
    return 0;
}
"""
    result = _dv(code)
    assert "dead" not in result


def test_dead_var_with_initializer():
    code = """\
uint f(uint p) {
    uint dead = p * 3;
    return 0;
}
"""
    result = _dv(code)
    assert "dead" not in result


# ── Boolean simplification ───────────────────────────────────────────


def _bs(body: str) -> str:
    code = P + body
    result = simplify_booleans(code)
    return strip_prelude(result)


def test_x_neq_zero_becomes_x():
    code = "uint f(uint x) { if (x != 0) { return 1; } return 0; }\n"
    result = _bs(code)
    assert "if (x)" in result
    assert "!= 0" not in result


def test_x_eq_zero_becomes_not_x():
    code = "uint f(uint x) { if (x == 0) { return 1; } return 0; }\n"
    result = _bs(code)
    assert "if (!x)" in result
    assert "== 0" not in result


def test_zero_neq_x_becomes_x():
    code = "uint f(uint x) { if (0 != x) { return 1; } return 0; }\n"
    result = _bs(code)
    assert "if (x)" in result


def test_double_negation_removed():
    code = "uint f(uint x) { if (!!x) { return 1; } return 0; }\n"
    result = _bs(code)
    assert "if (x)" in result
    assert "!!" not in result


def test_negated_equality_simplified():
    code = "uint f(uint a, uint b) { if (!(a == b)) { return 1; } return 0; }\n"
    result = _bs(code)
    assert "!=" in result
    assert "!(a == b)" not in result


def test_negated_inequality_simplified():
    code = "uint f(uint a, uint b) { if (!(a != b)) { return 1; } return 0; }\n"
    result = _bs(code)
    assert "==" in result
    assert "!(a != b)" not in result


def test_preserves_non_boolean_context():
    code = "uint f(uint x) { uint r = (x != 0); return r; }\n"
    result = _bs(code)
    assert "x != 0" in result


def test_simplifies_while_condition():
    code = "void f(uint x) { while (x != 0) { x = x - 1; } }\n"
    result = _bs(code)
    assert "while (x)" in result


def test_simplifies_for_condition():
    code = "void f(uint x) { for (; x != 0; ) { x = x - 1; } }\n"
    result = _bs(code)
    assert "!= 0" not in result


def test_simplifies_logical_operands():
    code = "uint f(uint a, uint b) { if (a != 0 && b != 0) { return 1; } return 0; }\n"
    result = _bs(code)
    assert "if (a && b)" in result


# ── Redundant cast removal ───────────────────────────────────────────


def _cc(body: str) -> str:
    code = P + body
    result = remove_redundant_casts(code)
    return strip_prelude(result)


def test_removes_same_type_cast():
    code = "uint f(uint x) { return (uint)x; }\n"
    result = _cc(code)
    assert "(uint)" not in result
    assert "return x;" in result


def test_removes_nested_identical_casts():
    code = "int f(uint x) { return (int)(int)x; }\n"
    result = _cc(code)
    assert "(int)(int)" not in result
    assert "return (int)x;" in result


def test_preserves_different_type_cast():
    code = "int f(uint x) { return (int)x; }\n"
    result = _cc(code)
    assert "(int)x" in result


def test_preserves_void_pointer_null():
    code = "void f(void) { int *p = (void *)0; }\n"
    result = _cc(code)
    assert "(void *)0" in result


def test_handles_ghidra_types():
    code = "undefined8 f(undefined8 x) { return (undefined8)x; }\n"
    result = _cc(code)
    assert "(undefined8)" not in result
    assert "return x;" in result


def test_preserves_pointer_cast():
    code = "void f(int *p) { char *q = (char *)p; }\n"
    result = _cc(code)
    assert "(char *)" in result


# ── Full pipeline ────────────────────────────────────────────────────


def test_polish_chains_all_transforms():
    code = """\
uint f(uint p1, uint p2) {
    uint dead;
    uint result;
    dead = p1 * 3;
    result = 0;
    if (p1 != 0) {
        result = (uint)p1;
    }
    return result;
}
"""
    result, flag = polish(code)
    assert flag is True
    assert "dead" not in result
    assert "if (p1)" in result
    assert "(uint)p1" not in result


def test_polish_skip_returns_original():
    code = "uint f(uint x) { if (x != 0) { return 1; } return 0; }\n"
    result, flag = polish(code, skip=True)
    assert flag is False
    assert result == code


def test_polish_returns_false_when_no_changes():
    code = "int f(int x) { return x; }\n"
    result, flag = polish(code)
    assert flag is False
    assert result == code


def test_polish_fallback_on_empty():
    _result, flag = polish("")
    assert flag is False


def test_polish_handles_unparseable_gracefully():
    code = "this is not valid C at all {{{{ ;;;;"
    result, flag = polish(code)
    assert flag is False
    assert result == code


# ── Loop normalization ───────────────────────────────────────────────


def _ln(body: str) -> str:
    code = P + body
    result = normalize_loops(code)
    return strip_prelude(result)


def test_while_to_for_basic():
    code = """\
uint f(uint len) {
    uint i;
    uint sum;
    sum = 0;
    i = 0;
    while (i < len) {
        sum = sum + i;
        i = i + 1;
    }
    return sum;
}
"""
    result = _ln(code)
    assert "for (i = 0; i < len; i = i + 1)" in result
    assert "while" not in result
    assert "sum = sum + i;" in result


def test_while_to_for_preserves_body():
    code = """\
uint f(uint n) {
    uint i;
    uint a;
    uint b;
    i = 0;
    while (i < n) {
        a = i * 2;
        b = a + 1;
        do_stuff(b);
        i = i + 1;
    }
    return 0;
}
"""
    result = _ln(code)
    assert "for (i = 0;" in result
    assert "a = i * 2;" in result
    assert "b = a + 1;" in result
    assert "do_stuff(b);" in result


def test_while_to_for_skips_when_var_modified_in_body():
    code = """\
uint f(uint n) {
    uint i;
    i = 0;
    while (i < n) {
        i = i * 2;
        i = i + 1;
    }
    return i;
}
"""
    result = _ln(code)
    assert "while" in result
    assert "for" not in result


def test_while_to_for_skips_when_no_init():
    code = """\
uint f(uint i, uint n) {
    while (i < n) {
        i = i + 1;
    }
    return i;
}
"""
    result = _ln(code)
    assert "while" in result


def test_while_to_for_skips_when_no_increment():
    code = """\
uint f(uint n) {
    uint i;
    i = 0;
    while (i < n) {
        do_stuff(i);
    }
    return i;
}
"""
    result = _ln(code)
    assert "while" in result


def test_fill_empty_for_init():
    code = """\
uint f(uint n) {
    uint i;
    i = 0;
    for (; i < n; i = i + 1) {
        do_stuff(i);
    }
    return i;
}
"""
    result = _ln(code)
    assert "for (i = 0; i < n;" in result
    lines = [l.strip() for l in result.split("\n")]
    assert "i = 0;" not in lines


def test_fill_empty_for_skips_unrelated_init():
    code = """\
uint f(uint n) {
    uint j;
    j = 99;
    for (; n > 0; n = n - 1) {
        do_stuff(n);
    }
    return j;
}
"""
    result = _ln(code)
    assert "j = 99;" in result
    assert "for (;" in result


def test_while_true_break_to_while():
    code = """\
uint f(uint x) {
    while (1) {
        if (x > 10) break;
        x = x + 1;
    }
    return x;
}
"""
    result = _ln(code)
    assert "while (x <= 10)" in result
    assert "break" not in result
    assert "x = x + 1;" in result


def test_while_true_break_negates_equality():
    code = """\
uint f(uint x, uint y) {
    while (1) {
        if (x == y) break;
        x = x + 1;
    }
    return x;
}
"""
    result = _ln(code)
    assert "while (x != y)" in result
    assert "break" not in result


def test_pipeline_includes_loop_normalize():
    code = """\
uint f(uint len) {
    uint i;
    uint dead;
    uint sum;
    dead = 42;
    sum = 0;
    i = 0;
    while (i < len) {
        if (i != 0) {
            sum = sum + i;
        }
        i = i + 1;
    }
    return sum;
}
"""
    result, flag = polish(code)
    assert flag is True
    assert "dead" not in result
    assert "for (i = 0;" in result
    assert "if (i)" in result


# ── Struct field synthesis ───────────────────────────────────────────


def _sf(body: str) -> str:
    code = P + body
    result = synthesize_struct_fields(code)
    return strip_prelude(result)


def test_struct_field_basic():
    code = """\
u32 f(void *obj) {
    u32 a = *(u32 *)((int)obj + 8);
    u32 b = *(int *)((int)obj + 4);
    u32 c = *(int *)obj;
    return a + b + c;
}
"""
    result = _sf(code)
    assert "_struct_obj" in result
    assert "->field_0x8" in result
    assert "->field_0x4" in result
    assert "->field_0x0" in result


def test_struct_field_preserves_single_access():
    code = """\
u32 f(void *obj) {
    return *(int *)((int)obj + 4);
}
"""
    result = _sf(code)
    assert "_struct_" not in result
    assert "->field_" not in result


def test_struct_field_write():
    code = """\
void f(void *obj) {
    *(int *)((int)obj + 4) = 42;
    *(int *)((int)obj + 8) = 99;
}
"""
    result = _sf(code)
    assert "->field_0x4 = 42" in result
    assert "->field_0x8 = 99" in result


def test_struct_field_skips_non_pattern():
    code = """\
u32 f(int *arr) {
    return arr[2];
}
"""
    result = _sf(code)
    assert "_struct_" not in result


def test_struct_field_multiple_bases():
    code = """\
u32 f(void *a, void *b) {
    u32 x = *(int *)((int)a + 0) + *(int *)((int)a + 4);
    u32 y = *(int *)((int)b + 0) + *(int *)((int)b + 8);
    return x + y;
}
"""
    result = _sf(code)
    assert "_struct_a" in result
    assert "_struct_b" in result
    assert "((_struct_a *)a)->field_0x0" in result
    assert "((_struct_b *)b)->field_0x8" in result


def test_struct_field_hex_offsets():
    code = """\
u32 f(void *obj) {
    u32 a = *(int *)((int)obj + 0x10);
    u32 b = *(int *)((int)obj + 0x1c);
    return a + b;
}
"""
    result = _sf(code)
    assert "->field_0x10" in result
    assert "->field_0x1c" in result


def test_struct_field_typedef_emitted():
    code = """\
u32 f(void *obj) {
    u32 a = *(int *)((int)obj + 4);
    u32 b = *(u32 *)((int)obj + 8);
    return a + b;
}
"""
    result = _sf(code)
    assert "typedef struct {" in result
    assert "int field_0x4;" in result
    assert "u32 field_0x8;" in result
    assert "} _struct_obj;" in result


def test_pipeline_includes_struct_fields():
    code = """\
u32 f(void *obj) {
    u32 dead;
    dead = 42;
    u32 a = *(int *)((int)obj + 4);
    u32 b = *(u32 *)((int)obj + 8);
    if (a != 0) {
        return a + b;
    }
    return 0;
}
"""
    result, flag = polish(code)
    assert flag is True
    assert "dead" not in result
    assert "->field_0x4" in result
    assert "->field_0x8" in result
    assert "if (a)" in result
