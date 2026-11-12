"""Simplify if (cond) { return 1; } return 0; into return cond;."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse

_ZERO_LITERALS = frozenset(
    {"0", "0U", "0u", "0L", "0l", "0UL", "0ul", "0LL", "0ll", "0ULL", "0ull"}
)

_NEGATE_OP = {"==": "!=", "!=": "==", "<": ">=", ">": "<=", "<=": ">", ">=": "<"}


def _is_zero(node) -> bool:
    if node is None:
        return False
    if node.type == "number_literal":
        return node_text(node) in _ZERO_LITERALS
    if node.type == "parenthesized_expression" and node.named_child_count == 1:
        return _is_zero(node.named_children[0])
    return False


_ONE_LITERALS = frozenset({"1", "1U", "1u", "1L", "1l", "1UL", "1ul"})


def _is_one(node) -> bool:
    if node is None:
        return False
    if node.type == "number_literal":
        return node_text(node) in _ONE_LITERALS
    return False


def _negate_condition(text: str, node) -> str:
    if node.type == "unary_expression":
        op = node.child(0)
        if op is not None and node_text(op) == "!":
            arg = node.child(1)
            if arg is not None:
                return node_text(arg)

    if node.type == "binary_expression":
        for child in node.children:
            if child.type in _NEGATE_OP:
                lhs = node.child_by_field_name("left")
                rhs = node.child_by_field_name("right")
                if lhs is not None and rhs is not None:
                    return f"{node_text(lhs)} {_NEGATE_OP[child.type]} {node_text(rhs)}"

    return f"!({text})"


def _get_return_expr(return_stmt):
    for child in return_stmt.named_children:
        if child.type != "return":
            return child
    return None


def _extract_single_return(consequence):
    if consequence is None:
        return None
    if consequence.type == "return_statement":
        return consequence
    if consequence.type == "compound_statement":
        named = consequence.named_children
        if len(named) == 1 and named[0].type == "return_statement":
            return named[0]
    return None


def _get_indent(node, source: str) -> str:
    line_start = node.start_byte
    while line_start > 0 and source[line_start - 1] in (" ", "\t"):
        line_start -= 1
    return source[line_start : node.start_byte]


def simplify_returns(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node
    edits = []

    func_defs = [n for n in root.children if n.type == "function_definition"]
    for func_def in func_defs:
        body = func_def.child_by_field_name("body")
        if body is None or body.type != "compound_statement":
            continue

        named = body.named_children
        if len(named) < 2:
            continue

        last = named[-1]
        second_last = named[-2]

        if second_last.type != "if_statement" or last.type != "return_statement":
            continue

        alt = second_last.child_by_field_name("alternative")
        if alt is not None:
            continue

        consequence = second_last.child_by_field_name("consequence")
        if_return = _extract_single_return(consequence)
        if if_return is None:
            continue

        if_expr = _get_return_expr(if_return)
        trail_expr = _get_return_expr(last)

        if_zero = _is_zero(if_expr)
        if_one = _is_one(if_expr)
        trail_zero = _is_zero(trail_expr)
        trail_one = _is_one(trail_expr)

        if not ((if_one and trail_zero) or (if_zero and trail_one)):
            continue

        cond_node = second_last.child_by_field_name("condition")
        if cond_node is None:
            continue
        cond_inner = (
            cond_node.named_children[0]
            if cond_node.named_child_count > 0
            else cond_node
        )
        cond_text = node_text(cond_inner)

        indent = _get_indent(second_last, c_code)

        if if_one and trail_zero:
            replacement = f"{indent}return {cond_text};"
        else:
            negated = _negate_condition(cond_text, cond_inner)
            replacement = f"{indent}return {negated};"

        start = second_last.start_byte
        while start > 0 and c_code[start - 1] in (" ", "\t"):
            start -= 1

        end = last.end_byte
        while end < len(c_code) and c_code[end] in (" ", "\t"):
            end += 1
        if end < len(c_code) and c_code[end] == "\n":
            end += 1

        edits.append((start, end, replacement + "\n"))

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
