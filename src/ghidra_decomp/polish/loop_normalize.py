"""Normalize while loops into for loops when init/condition/increment pattern is clear."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse

_NEGATE_OP = {"==": "!=", "!=": "==", "<": ">=", ">": "<=", "<=": ">", ">=": "<"}


def _negate_condition(text: str, node) -> str:
    """Negate a condition intelligently, avoiding double negation."""
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


def _is_simple_assignment(node) -> tuple[str, object] | None:
    """If node is `var = expr;`, return (var_name, assignment_expression)."""
    if node.type != "expression_statement":
        return None
    for child in node.children:
        if child.type == "assignment_expression":
            lhs = child.child_by_field_name("left")
            if lhs is not None and lhs.type == "identifier":
                return node_text(lhs), child
    return None


def _mentions_var(node, var_name: str) -> bool:
    if node.type == "identifier" and node_text(node) == var_name:
        return True
    for child in node.children:
        if _mentions_var(child, var_name):
            return True
    return False


def _var_assigned_in_body(body, var_name: str, exclude_last: bool) -> bool:
    """Check if var_name is on the LHS of any assignment in body, optionally excluding last statement."""
    stmts = [c for c in body.named_children if c.type == "expression_statement"]
    check = stmts[:-1] if exclude_last and stmts else stmts
    for stmt in check:
        for child in stmt.children:
            if child.type == "assignment_expression":
                lhs = child.child_by_field_name("left")
                if lhs is not None and node_text(lhs) == var_name:
                    return True
    return False


def _last_expression_statement(body):
    """Return last expression_statement in a compound_statement, or None."""
    for child in reversed(body.named_children):
        if child.type in ("{", "}"):
            continue
        if child.type == "expression_statement":
            return child
        return None
    return None


def _preceding_sibling(node):
    """Get the named sibling immediately before this node in the parent."""
    parent = node.parent
    if parent is None:
        return None
    prev = None
    for child in parent.named_children:
        if child.id == node.id:
            return prev
        prev = child
    return None


def _line_range(node, source: str) -> tuple[int, int]:
    start = node.start_byte
    end = node.end_byte
    while start > 0 and source[start - 1] in (" ", "\t"):
        start -= 1
    while end < len(source) and source[end] in (" ", "\t"):
        end += 1
    if end < len(source) and source[end] == "\n":
        end += 1
    return start, end


def _get_indent(node, source: str) -> str:
    line_start = node.start_byte
    while line_start > 0 and source[line_start - 1] in (" ", "\t"):
        line_start -= 1
    return source[line_start : node.start_byte]


def _body_without_last_stmt(body, last_stmt, source: str) -> str:
    """Return body text with the last statement removed."""
    body_text = node_text(body)
    last_start = last_stmt.start_byte - body.start_byte
    last_end = last_stmt.end_byte - body.start_byte
    while last_end < len(body_text) and body_text[last_end] in (" ", "\t"):
        last_end += 1
    if last_end < len(body_text) and body_text[last_end] == "\n":
        last_end += 1
    while last_start > 0 and body_text[last_start - 1] in (" ", "\t"):
        last_start -= 1
    if last_start > 0 and body_text[last_start - 1] == "\n":
        last_start -= 1
        last_start += 1
    return body_text[:last_start] + body_text[last_end:]


def _while_to_for(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node
    edits = []

    func_defs = [n for n in root.children if n.type == "function_definition"]
    for func_def in func_defs:
        body = func_def.child_by_field_name("body")
        if body is None:
            continue

        for child in body.named_children:
            if child.type != "while_statement":
                continue

            cond_node = child.child_by_field_name("condition")
            loop_body = child.child_by_field_name("body")
            if cond_node is None or loop_body is None:
                continue
            if loop_body.type != "compound_statement":
                continue

            prev = _preceding_sibling(child)
            if prev is None:
                continue
            init_info = _is_simple_assignment(prev)
            if init_info is None:
                continue
            var_name, init_expr = init_info

            if not _mentions_var(cond_node, var_name):
                continue

            last_stmt = _last_expression_statement(loop_body)
            if last_stmt is None:
                continue
            update_info = _is_simple_assignment(last_stmt)
            if update_info is None:
                continue
            update_var, update_expr = update_info
            if update_var != var_name:
                continue

            if _var_assigned_in_body(loop_body, var_name, exclude_last=True):
                continue

            cond_inner = (
                cond_node.named_children[0]
                if cond_node.named_child_count > 0
                else cond_node
            )
            cond_text = node_text(cond_inner)
            init_text = node_text(init_expr)
            update_text = node_text(update_expr)
            new_body = _body_without_last_stmt(loop_body, last_stmt, c_code)

            indent = _get_indent(child, c_code)
            for_stmt = (
                f"{indent}for ({init_text}; {cond_text}; {update_text}) {new_body}"
            )

            init_start, _init_end = _line_range(prev, c_code)
            edits.append((init_start, child.end_byte, for_stmt))

    if not edits:
        return c_code
    return apply_edits(c_code, edits)


def _fill_empty_for_init(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node
    edits = []

    func_defs = [n for n in root.children if n.type == "function_definition"]
    for func_def in func_defs:
        body = func_def.child_by_field_name("body")
        if body is None:
            continue

        for child in body.named_children:
            if child.type != "for_statement":
                continue

            initializer = child.child_by_field_name("initializer")
            if initializer is not None:
                continue

            condition = child.child_by_field_name("condition")
            update = child.child_by_field_name("update")

            prev = _preceding_sibling(child)
            if prev is None:
                continue
            init_info = _is_simple_assignment(prev)
            if init_info is None:
                continue
            var_name, init_expr = init_info

            mentioned = False
            if condition is not None and _mentions_var(condition, var_name):
                mentioned = True
            if update is not None and _mentions_var(update, var_name):
                mentioned = True
            if not mentioned:
                continue

            for_text = node_text(child)
            open_paren = for_text.find("(")
            if open_paren == -1:
                continue
            semi_after_paren = for_text.find(";", open_paren)
            if semi_after_paren == -1:
                continue

            init_text = node_text(init_expr)
            new_for = (
                for_text[: open_paren + 1] + init_text + for_text[semi_after_paren:]
            )

            indent = _get_indent(child, c_code)
            init_start, _init_end = _line_range(prev, c_code)
            edits.append((init_start, child.end_byte, indent + new_for))

    if not edits:
        return c_code
    return apply_edits(c_code, edits)


def _while_true_break(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node
    edits = []

    func_defs = [n for n in root.children if n.type == "function_definition"]
    for func_def in func_defs:
        body = func_def.child_by_field_name("body")
        if body is None:
            continue

        for child in body.named_children:
            if child.type != "while_statement":
                continue

            cond_node = child.child_by_field_name("condition")
            loop_body = child.child_by_field_name("body")
            if cond_node is None or loop_body is None:
                continue
            if loop_body.type != "compound_statement":
                continue

            inner_cond = (
                cond_node.named_children[0]
                if cond_node.named_child_count > 0
                else cond_node
            )
            cond_text = node_text(inner_cond).strip()
            if cond_text not in ("1", "true"):
                continue

            named = loop_body.named_children
            if not named:
                continue
            first_stmt = named[0]
            if first_stmt.type != "if_statement":
                continue

            alt = first_stmt.child_by_field_name("alternative")
            if alt is not None:
                continue

            consequence = first_stmt.child_by_field_name("consequence")
            if consequence is None:
                continue

            is_break = False
            if consequence.type == "break_statement":
                is_break = True
            elif consequence.type == "compound_statement":
                inner_stmts = consequence.named_children
                if len(inner_stmts) == 1 and inner_stmts[0].type == "break_statement":
                    is_break = True
            if not is_break:
                continue

            if_cond = first_stmt.child_by_field_name("condition")
            if if_cond is None:
                continue
            if_cond_inner = (
                if_cond.named_children[0] if if_cond.named_child_count > 0 else if_cond
            )
            break_cond_text = node_text(if_cond_inner)
            negated = _negate_condition(break_cond_text, if_cond_inner)

            remaining_stmts = named[1:]
            indent = _get_indent(child, c_code)

            remaining_text = ""
            for stmt in remaining_stmts:
                stmt_indent = _get_indent(stmt, c_code)
                remaining_text += stmt_indent + node_text(stmt) + "\n"

            new_while = f"{indent}while ({negated}) {{\n{remaining_text}{indent}}}"
            line_start = child.start_byte
            while line_start > 0 and c_code[line_start - 1] in (" ", "\t"):
                line_start -= 1
            edits.append((line_start, child.end_byte, new_while))

    if not edits:
        return c_code
    return apply_edits(c_code, edits)


def normalize_loops(c_code: str) -> str:
    result = _while_to_for(c_code)
    result = _fill_empty_for_init(result)
    result = _while_true_break(result)
    return result
