"""Synthesize ternary expressions from if/else single-assignment patterns."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse


def _has_call_expression(node) -> bool:
    if node.type == "call_expression":
        return True
    for child in node.children:
        if _has_call_expression(child):
            return True
    return False


def _extract_single_assignment(branch):
    """Extract (var_name, rhs_text) from a branch that is a single assignment.

    Branch can be compound_statement with one expression_statement,
    or bare expression_statement.
    """
    if branch is None:
        return None

    actual = branch
    if branch.type == "else_clause":
        inner = branch.named_children
        if len(inner) != 1:
            return None
        actual = inner[0]

    stmt = None
    if actual.type == "compound_statement":
        named = actual.named_children
        if len(named) != 1:
            return None
        stmt = named[0]
    elif actual.type == "expression_statement":
        stmt = actual
    else:
        return None

    if stmt.type != "expression_statement":
        return None

    assign = None
    for child in stmt.children:
        if child.type == "assignment_expression":
            assign = child
            break
    if assign is None:
        return None

    lhs = assign.child_by_field_name("left")
    rhs = assign.child_by_field_name("right")
    if lhs is None or rhs is None:
        return None
    if lhs.type != "identifier":
        return None

    if _has_call_expression(rhs):
        return None

    return node_text(lhs), node_text(rhs)


def _get_indent(node, source: str) -> str:
    line_start = node.start_byte
    while line_start > 0 and source[line_start - 1] in (" ", "\t"):
        line_start -= 1
    return source[line_start : node.start_byte]


def _collect_ternary_edits(root, source: str) -> list[tuple[int, int, str]]:
    edits = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "if_statement":
            consequence = node.child_by_field_name("consequence")
            alternative = node.child_by_field_name("alternative")
            if consequence is not None and alternative is not None:
                then_info = _extract_single_assignment(consequence)
                else_info = _extract_single_assignment(alternative)
                if then_info is not None and else_info is not None:
                    then_var, then_rhs = then_info
                    else_var, else_rhs = else_info
                    if then_var == else_var:
                        cond_node = node.child_by_field_name("condition")
                        if cond_node is not None:
                            cond_inner = (
                                cond_node.named_children[0]
                                if cond_node.named_child_count > 0
                                else cond_node
                            )
                            cond_text = node_text(cond_inner)
                            indent = _get_indent(node, source)
                            replacement = (
                                f"{indent}{then_var} = {cond_text}"
                                f" ? {then_rhs} : {else_rhs};"
                            )
                            start = node.start_byte
                            while start > 0 and source[start - 1] in (" ", "\t"):
                                start -= 1
                            edits.append((start, node.end_byte, replacement))
                            continue
        stack.extend(node.children)
    return edits


def synthesize_ternaries(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    edits = _collect_ternary_edits(root, c_code)
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
