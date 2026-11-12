"""Flatten nested if statements without else into combined && conditions."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse


def _has_or_operator(node) -> bool:
    if node.type == "binary_expression":
        for child in node.children:
            if child.type == "||":
                return True
    return False


def _collect_conditions_and_body(if_node):
    """Walk nested single-if chains, collecting conditions and the innermost body.

    Returns (conditions_texts, innermost_body_node) or None if pattern doesn't match.
    """
    conditions = []
    current = if_node

    while True:
        if current.child_by_field_name("alternative") is not None:
            if not conditions:
                return None
            break

        cond_node = current.child_by_field_name("condition")
        if cond_node is None:
            break

        cond_inner = (
            cond_node.named_children[0]
            if cond_node.named_child_count > 0
            else cond_node
        )
        cond_text = node_text(cond_inner)

        if _has_or_operator(cond_inner):
            cond_text = f"({cond_text})"

        conditions.append(cond_text)

        consequence = current.child_by_field_name("consequence")
        if consequence is None or consequence.type != "compound_statement":
            break

        named = consequence.named_children
        if len(named) != 1 or named[0].type != "if_statement":
            break

        current = named[0]

    if len(conditions) < 2:
        return None

    innermost_consequence = current.child_by_field_name("consequence")
    if innermost_consequence is None:
        return None

    return conditions, innermost_consequence


def _get_indent(node, source: str) -> str:
    line_start = node.start_byte
    while line_start > 0 and source[line_start - 1] in (" ", "\t"):
        line_start -= 1
    return source[line_start : node.start_byte]


def flatten_nested_ifs(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node
    edits = []

    stack = [root]
    visited = set()
    while stack:
        node = stack.pop()
        if node.type == "if_statement" and node.id not in visited:
            result = _collect_conditions_and_body(node)
            if result is not None:
                conditions, body = result
                indent = _get_indent(node, c_code)
                combined_cond = " && ".join(conditions)
                body_text = node_text(body)
                replacement = f"{indent}if ({combined_cond}) {body_text}"

                start = node.start_byte
                while start > 0 and c_code[start - 1] in (" ", "\t"):
                    start -= 1
                edits.append((start, node.end_byte, replacement))
                visited.add(node.id)
                continue

        stack.extend(node.children)

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
