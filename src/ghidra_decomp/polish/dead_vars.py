"""Remove local variables that are assigned but never read."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse


def _is_volatile(decl_node) -> bool:
    for child in decl_node.children:
        if child.type == "type_qualifier" and node_text(child) == "volatile":
            return True
    return False


def _has_call_expression(node) -> bool:
    if node.type == "call_expression":
        return True
    for child in node.children:
        if _has_call_expression(child):
            return True
    return False


def _collect_identifiers(node, names: set[str]) -> None:
    if node.type == "identifier":
        names.add(node_text(node))
    for child in node.children:
        _collect_identifiers(child, names)


def _is_address_of(node) -> bool:
    parent = node.parent
    if parent is None:
        return False
    if parent.type == "unary_expression":
        op = parent.child(0)
        if op is not None and node_text(op) == "&":
            return True
    return False


def _find_local_declarations(body) -> list[tuple[str, object, int | None]]:
    """Return (var_name, declaration_node, declarator_index) for each local."""
    results = []
    for child in body.children:
        if child.type != "declaration":
            continue
        if _is_volatile(child):
            continue
        declarators = []
        for i, sub in enumerate(child.children):
            if sub.type == "init_declarator":
                decl = sub.child_by_field_name("declarator")
                if decl is not None and decl.type == "identifier":
                    declarators.append((node_text(decl), i))
            elif sub.type == "identifier":
                first = child.children[0] if child.children else None
                if first is not None and first.type in (
                    "primitive_type",
                    "sized_type_specifier",
                    "type_identifier",
                    "type_qualifier",
                    "struct_specifier",
                    "union_specifier",
                    "enum_specifier",
                ):
                    declarators.append((node_text(sub), i))

        for var_name, idx in declarators:
            results.append((var_name, child, idx if len(declarators) > 1 else None))
    return results


def _find_assignments(body, var_name: str) -> list:
    """Find expression_statements where var_name is on the LHS of assignment."""
    results = []
    for child in body.children:
        if child.type != "expression_statement":
            continue
        expr = None
        for sub in child.children:
            if sub.type == "assignment_expression":
                expr = sub
                break
        if expr is None:
            continue
        lhs = expr.child_by_field_name("left")
        if lhs is not None and lhs.type == "identifier" and node_text(lhs) == var_name:
            results.append(child)
    return results


def _is_read(node, var_name: str) -> bool:
    """Check if this identifier occurrence is a read (not just LHS of assignment)."""
    if node_text(node) != var_name:
        return False

    if _is_address_of(node):
        return True

    parent = node.parent
    if parent is None:
        return True

    if parent.type == "assignment_expression":
        lhs = parent.child_by_field_name("left")
        if lhs is not None and lhs.id == node.id:
            return False

    if parent.type == "init_declarator":
        decl = parent.child_by_field_name("declarator")
        if decl is not None and decl.id == node.id:
            return False

    return parent.type != "declaration"


def _count_reads(root, var_name: str) -> int:
    count = 0
    stack = [root]
    while stack:
        n = stack.pop()
        if n.type == "identifier" and _is_read(n, var_name):
            count += 1
        stack.extend(n.children)
    return count


def _line_byte_range(node, source: str) -> tuple[int, int]:
    """Get byte range for the full line(s) containing a statement."""
    start = node.start_byte
    end = node.end_byte
    while start > 0 and source[start - 1] in (" ", "\t"):
        start -= 1
    while end < len(source) and source[end] in (" ", "\t"):
        end += 1
    if end < len(source) and source[end] == "\n":
        end += 1
    return start, end


def eliminate_dead_variables(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    func_defs = [n for n in root.children if n.type == "function_definition"]
    if not func_defs:
        return c_code

    edits = []

    for func_def in func_defs:
        body = func_def.child_by_field_name("body")
        if body is None:
            continue

        locals_ = _find_local_declarations(body)

        for var_name, decl_node, declarator_idx in locals_:
            reads = _count_reads(body, var_name)
            if reads > 0:
                continue

            assignments = _find_assignments(body, var_name)
            for assign_stmt in assignments:
                expr = None
                for sub in assign_stmt.children:
                    if sub.type == "assignment_expression":
                        expr = sub
                        break
                if expr is not None:
                    rhs = expr.child_by_field_name("right")
                    if rhs is not None and _has_call_expression(rhs):
                        rhs_text = node_text(rhs)
                        start, end = _line_byte_range(assign_stmt, c_code)
                        indent = c_code[start : assign_stmt.start_byte]
                        edits.append((start, end, indent + rhs_text + ";\n"))
                    else:
                        start, end = _line_byte_range(assign_stmt, c_code)
                        edits.append((start, end, ""))

            if declarator_idx is None:
                start, end = _line_byte_range(decl_node, c_code)
                edits.append((start, end, ""))

    if not edits:
        return c_code

    return apply_edits(c_code, edits)
