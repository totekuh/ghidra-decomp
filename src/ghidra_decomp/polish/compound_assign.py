"""Simplify x = x op expr into compound assignment x op= expr."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse

_COMPOUND_OPS = frozenset({"+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"})


def _collect_compound_edits(node) -> list[tuple[int, int, str]]:
    edits = []

    for child in node.children:
        edits.extend(_collect_compound_edits(child))

    if node.type != "assignment_expression":
        return edits

    lhs = node.child_by_field_name("left")
    rhs = node.child_by_field_name("right")
    if lhs is None or rhs is None:
        return edits
    if lhs.type != "identifier":
        return edits
    if rhs.type != "binary_expression":
        return edits

    var_name = node_text(lhs)

    rhs_left = rhs.child_by_field_name("left")
    rhs_right = rhs.child_by_field_name("right")
    if rhs_left is None or rhs_right is None:
        return edits
    if rhs_left.type != "identifier" or node_text(rhs_left) != var_name:
        return edits

    op_node = None
    for child in rhs.children:
        if child.type in _COMPOUND_OPS:
            op_node = child
            break
    if op_node is None:
        return edits

    op = node_text(op_node)
    rhs_text = node_text(rhs_right)
    replacement = f"{var_name} {op}= {rhs_text}"
    edits.append((node.start_byte, node.end_byte, replacement))

    return edits


def simplify_compound_assignments(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    edits = _collect_compound_edits(root)
    if not edits:
        return c_code

    seen = set()
    unique = []
    for start, end, replacement in edits:
        key = (start, end)
        if key not in seen:
            seen.add(key)
            unique.append((start, end, replacement))

    return apply_edits(c_code, unique)
