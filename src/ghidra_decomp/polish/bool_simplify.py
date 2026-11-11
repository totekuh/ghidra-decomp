"""Simplify boolean expressions in condition contexts."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse

_ZERO_LITERALS = frozenset(
    {"0", "0U", "0u", "0L", "0l", "0UL", "0ul", "0LL", "0ll", "0ULL", "0ull"}
)

_OPPOSITE_OP = {"!=": "==", "==": "!="}


def _is_zero(node) -> bool:
    if node.type == "number_literal":
        return node_text(node) in _ZERO_LITERALS
    if node.type == "parenthesized_expression" and node.named_child_count == 1:
        return _is_zero(node.named_children[0])
    return False


def _is_boolean_context(node) -> bool:
    parent = node.parent
    if parent is None:
        return False

    if parent.type == "if_statement":
        cond = parent.child_by_field_name("condition")
        return cond is not None and _contains_node(cond, node)

    if parent.type == "while_statement":
        cond = parent.child_by_field_name("condition")
        return cond is not None and _contains_node(cond, node)

    if parent.type == "for_statement":
        cond = parent.child_by_field_name("condition")
        return cond is not None and _contains_node(cond, node)

    if parent.type == "do_statement":
        cond = parent.child_by_field_name("condition")
        return cond is not None and _contains_node(cond, node)

    if parent.type == "binary_expression":
        for child in parent.children:
            if child.type in ("&&", "||"):
                return True

    if parent.type == "unary_expression":
        op = parent.child(0)
        if op is not None and node_text(op) == "!":
            return True

    if parent.type == "conditional_expression":
        cond = parent.child_by_field_name("condition")
        return cond is not None and _contains_node(cond, node)

    if parent.type == "parenthesized_expression":
        return _is_boolean_context(parent)

    return False


def _contains_node(container, target) -> bool:
    if container.id == target.id:
        return True
    for child in container.children:
        if _contains_node(child, target):
            return True
    return False


def _collect_simplifications(node) -> list[tuple[int, int, str]]:
    edits = []

    for child in node.children:
        edits.extend(_collect_simplifications(child))

    if node.type == "binary_expression" and _is_boolean_context(node):
        children = node.children
        op_node = None
        for c in children:
            if c.type in ("!=", "=="):
                op_node = c
                break
        if op_node is not None:
            op = node_text(op_node)
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                if _is_zero(right):
                    other = node_text(left)
                    if op == "!=":
                        edits.append((node.start_byte, node.end_byte, other))
                    elif op == "==":
                        edits.append((node.start_byte, node.end_byte, f"!{other}"))
                elif _is_zero(left):
                    other = node_text(right)
                    if op == "!=":
                        edits.append((node.start_byte, node.end_byte, other))
                    elif op == "==":
                        edits.append((node.start_byte, node.end_byte, f"!{other}"))

    if node.type == "unary_expression":
        op = node.child(0)
        if op is not None and node_text(op) == "!":
            arg = node.child(1)
            if arg is not None:
                inner = arg
                if (
                    inner.type == "parenthesized_expression"
                    and inner.named_child_count == 1
                ):
                    inner = inner.named_children[0]

                if inner.type == "unary_expression":
                    inner_op = inner.child(0)
                    if inner_op is not None and node_text(inner_op) == "!":
                        inner_arg = inner.child(1)
                        if inner_arg is not None:
                            edits.append(
                                (node.start_byte, node.end_byte, node_text(inner_arg))
                            )

                elif inner.type == "binary_expression":
                    inner_op_node = None
                    for c in inner.children:
                        if c.type in ("!=", "=="):
                            inner_op_node = c
                            break
                    if inner_op_node is not None:
                        inner_op = node_text(inner_op_node)
                        if inner_op in _OPPOSITE_OP:
                            inner_left = inner.child_by_field_name("left")
                            inner_right = inner.child_by_field_name("right")
                            if inner_left is not None and inner_right is not None:
                                new_op = _OPPOSITE_OP[inner_op]
                                replacement = f"({node_text(inner_left)} {new_op} {node_text(inner_right)})"
                                edits.append(
                                    (node.start_byte, node.end_byte, replacement)
                                )

    return edits


def simplify_booleans(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    edits = _collect_simplifications(root)
    if not edits:
        return c_code

    seen_ranges = set()
    unique_edits = []
    for start, end, replacement in edits:
        key = (start, end)
        if key not in seen_ranges:
            seen_ranges.add(key)
            unique_edits.append((start, end, replacement))

    return apply_edits(c_code, unique_edits)
