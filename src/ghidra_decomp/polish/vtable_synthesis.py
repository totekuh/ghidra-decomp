"""Synthesize vtable structs for stripped C++ binaries.

Detects double-deref indirect calls through code** casts — the pattern Ghidra
emits for virtual method dispatch — and rewrites them with synthesized vtable
typedefs and arrow notation.
"""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse


def _is_code_ptr_ptr_cast(node) -> bool:
    """Check if node is a cast_expression to `code **`."""
    if node.type != "cast_expression":
        return False
    for child in node.children:
        if child.type == "type_descriptor":
            td_text = node_text(child).strip()
            return td_text == "code **"
    return False


def _extract_vtable_call(call_node) -> tuple[str, int, str] | None:
    """Extract (base_var_text, offset, first_arg_text) from a vtable dispatch call.

    Returns None if the call doesn't match the vtable pattern.
    """
    callee = call_node.child_by_field_name("function")
    args = call_node.child_by_field_name("arguments")
    if callee is None or args is None:
        return None
    if callee.type != "parenthesized_expression":
        return None

    inner = _unwrap_parens(callee)
    if inner is None:
        return None

    # Must be pointer_expression(*) > pointer_expression(*) > cast_expression(code **)
    if inner.type != "pointer_expression":
        return None
    star1 = inner.child(0)
    if star1 is None or node_text(star1) != "*":
        return None
    deref2 = inner.child(1)
    if deref2 is None or deref2.type != "pointer_expression":
        return None
    star2 = deref2.child(0)
    if star2 is None or node_text(star2) != "*":
        return None
    cast = deref2.child(1)
    if cast is None or not _is_code_ptr_ptr_cast(cast):
        return None

    # Inside the cast: either *var (slot 0) or (*var + offset) (slot N)
    cast_operand = _get_cast_operand(cast)
    if cast_operand is None:
        return None

    base_var, offset = _extract_base_and_offset(cast_operand)
    if base_var is None:
        return None

    # First argument should reference the same base object
    first_arg = _get_first_arg(args)
    if first_arg is None:
        return None

    return base_var, offset, first_arg


def _unwrap_parens(node):
    """Unwrap one level of parenthesized_expression."""
    if node.type != "parenthesized_expression":
        return None
    for child in node.named_children:
        return child
    return None


def _get_cast_operand(cast_node):
    """Get the operand of a cast_expression (the thing being cast)."""
    children = cast_node.children
    past_close_paren = False
    for child in children:
        if child.type == ")" and not past_close_paren:
            past_close_paren = True
            continue
        if past_close_paren:
            return child
    return None


def _extract_base_and_offset(node) -> tuple[str | None, int]:
    """Extract base variable and vtable offset from inside the code** cast.

    Handles:
    - *param_1  → (param_1, 0)
    - (*param_1 + 8)  → (param_1, 8)
    - **(undefined8 **)(base + idx*8)  → None (array pattern, too complex)
    """
    # Slot 0: *identifier
    if node.type == "pointer_expression":
        star = node.child(0)
        operand = node.child(1)
        if (
            star is not None
            and node_text(star) == "*"
            and operand is not None
            and operand.type == "identifier"
        ):
            return node_text(operand), 0
        return None, 0

    # Slot N: parenthesized_expression containing binary_expression
    if node.type == "parenthesized_expression":
        inner = _unwrap_parens(node)
        if inner is not None:
            return _extract_from_binary(inner)

    # Direct binary_expression
    if node.type == "binary_expression":
        return _extract_from_binary(node)

    return None, 0


def _extract_from_binary(node) -> tuple[str | None, int]:
    """Extract base var and offset from `*var + OFFSET`."""
    if node.type != "binary_expression":
        return None, 0

    left = node.child_by_field_name("left")
    right = node.child_by_field_name("right")
    if left is None or right is None:
        return None, 0

    op = None
    for child in node.children:
        if child.type == "+":
            op = "+"
            break

    if op != "+":
        return None, 0

    # Left should be *identifier
    if left.type != "pointer_expression":
        return None, 0
    star = left.child(0)
    ident = left.child(1)
    if star is None or node_text(star) != "*" or ident is None:
        return None, 0
    if ident.type != "identifier":
        return None, 0

    # Right should be a number literal
    if right.type != "number_literal":
        return None, 0

    try:
        offset = int(node_text(right), 0)
    except ValueError:
        return None, 0

    return node_text(ident), offset


def _get_first_arg(args_node) -> str | None:
    """Get text of first argument in argument_list."""
    for child in args_node.named_children:
        return node_text(child)
    return None


def _find_call_expressions(node) -> list:
    """Collect all call_expression nodes in AST."""
    results = []
    if node.type == "call_expression":
        results.append(node)
    for child in node.children:
        results.extend(_find_call_expressions(child))
    return results


def synthesize_vtables(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    func_defs = [n for n in root.children if n.type == "function_definition"]
    all_edits: list[tuple[int, int, str]] = []
    all_typedefs: list[str] = []

    for func_def in func_defs:
        calls = _find_call_expressions(func_def)
        vtable_calls: dict[str, list[tuple[int, int, int]]] = {}

        for call in calls:
            extracted = _extract_vtable_call(call)
            if extracted is None:
                continue
            base_var, offset, _first_arg = extracted
            if base_var not in vtable_calls:
                vtable_calls[base_var] = []
            callee = call.child_by_field_name("function")
            vtable_calls[base_var].append((offset, callee.start_byte, callee.end_byte))

        for base_var, entries in vtable_calls.items():
            offsets = sorted({e[0] for e in entries})
            if len(offsets) < 2:
                continue

            safe_name = base_var.replace("*", "").replace(" ", "")
            vtable_name = f"_vtable_{safe_name}"
            obj_name = f"_vobj_{safe_name}"

            fields = "; ".join(f"code *vfunc_0x{off:x}" for off in offsets)
            vtable_td = f"typedef struct {{ {fields}; }} {vtable_name};"
            obj_td = f"typedef struct {{ {vtable_name} *_vtable; }} {obj_name};"
            all_typedefs.append(vtable_td)
            all_typedefs.append(obj_td)

            for offset, start, end in entries:
                if offset not in offsets:
                    continue
                replacement = f"(({obj_name} *){base_var})->_vtable->vfunc_0x{offset:x}"
                all_edits.append((start, end, replacement))

    if not all_edits:
        return c_code

    seen = set()
    unique_edits = []
    for start, end, replacement in all_edits:
        key = (start, end)
        if key not in seen:
            seen.add(key)
            unique_edits.append((start, end, replacement))

    result = apply_edits(c_code, unique_edits)

    unique_tds = list(dict.fromkeys(all_typedefs))
    if unique_tds:
        prefix = "\n".join(unique_tds) + "\n\n"
        result = prefix + result

    return result
