"""Unit tests for the decompilation polish pipeline."""

from __future__ import annotations

from ghidra_decomp.polish import polish
from ghidra_decomp.polish._parser import is_parseable
from ghidra_decomp.polish.bool_simplify import simplify_booleans
from ghidra_decomp.polish.cast_cleanup import remove_redundant_casts
from ghidra_decomp.polish.dead_vars import eliminate_dead_variables
from ghidra_decomp.polish.prelude import (
    GHIDRA_PRELUDE,
    inject_prelude,
    strip_prelude,
)

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
