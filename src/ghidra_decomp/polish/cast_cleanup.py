"""Remove redundant casts where cast type matches the operand's declared type."""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse


def _normalize_type(type_str: str) -> str:
    return " ".join(type_str.split())


def _extract_type_from_descriptor(node) -> str | None:
    if node.type == "type_descriptor":
        parts = []
        for child in node.children:
            if child.type in (
                "primitive_type",
                "sized_type_specifier",
                "type_identifier",
                "type_qualifier",
            ):
                parts.append(node_text(child))
        if parts:
            return _normalize_type(" ".join(parts))
    return None


def _build_scope(func_def) -> dict[str, str]:
    """Build variable name -> type string mapping from declarations and parameters."""
    scope: dict[str, str] = {}

    declarator = func_def.child_by_field_name("declarator")
    if declarator is not None:
        params = declarator.child_by_field_name("parameters")
        if params is not None:
            for param in params.children:
                if param.type == "parameter_declaration":
                    type_parts = []
                    name = None
                    for child in param.children:
                        if child.type in (
                            "primitive_type",
                            "sized_type_specifier",
                            "type_identifier",
                            "type_qualifier",
                        ):
                            type_parts.append(node_text(child))
                        elif child.type == "identifier":
                            name = node_text(child)
                        elif child.type == "pointer_declarator":
                            inner = child.child_by_field_name("declarator")
                            if inner is not None and inner.type == "identifier":
                                name = node_text(inner)
                                type_parts.append("*")
                    if name and type_parts:
                        scope[name] = _normalize_type(" ".join(type_parts))

    body = func_def.child_by_field_name("body")
    if body is None:
        return scope

    for child in body.children:
        if child.type != "declaration":
            continue
        type_parts = []
        for sub in child.children:
            if sub.type in (
                "primitive_type",
                "sized_type_specifier",
                "type_identifier",
                "type_qualifier",
            ):
                type_parts.append(node_text(sub))
            elif sub.type == "init_declarator":
                decl = sub.child_by_field_name("declarator")
                if decl is not None and decl.type == "identifier":
                    name = node_text(decl)
                    if type_parts:
                        scope[name] = _normalize_type(" ".join(type_parts))
                elif decl is not None and decl.type == "pointer_declarator":
                    inner = decl.child_by_field_name("declarator")
                    if inner is not None and inner.type == "identifier":
                        name = node_text(inner)
                        scope[name] = _normalize_type(" ".join(type_parts) + " *")
            elif sub.type == "identifier" and type_parts:
                scope[node_text(sub)] = _normalize_type(" ".join(type_parts))

    return scope


def _is_void_ptr_null(cast_node) -> bool:
    type_desc = cast_node.child_by_field_name("type")
    value = cast_node.child_by_field_name("value")
    if type_desc is None or value is None:
        return False
    type_text = _normalize_type(node_text(type_desc))
    if "void" in type_text and "*" in type_text:
        val_text = node_text(value).strip()
        if val_text in ("0", "NULL", "0L", "0UL"):
            return True
    return False


def _collect_cast_edits(node, scope: dict[str, str]) -> list[tuple[int, int, str]]:
    edits = []

    for child in node.children:
        edits.extend(_collect_cast_edits(child, scope))

    if node.type == "cast_expression":
        if _is_void_ptr_null(node):
            return edits

        type_desc = node.child_by_field_name("type")
        value = node.child_by_field_name("value")
        if type_desc is None or value is None:
            return edits

        cast_type = _extract_type_from_descriptor(type_desc)
        if cast_type is None:
            return edits

        if value.type == "cast_expression":
            inner_type_desc = value.child_by_field_name("type")
            if inner_type_desc is not None:
                inner_cast_type = _extract_type_from_descriptor(inner_type_desc)
                if inner_cast_type == cast_type:
                    edits.append((node.start_byte, node.end_byte, node_text(value)))
                    return edits

        if value.type == "identifier":
            var_name = node_text(value)
            var_type = scope.get(var_name)
            if var_type is not None and var_type == cast_type:
                edits.append((node.start_byte, node.end_byte, var_name))
                return edits

        if value.type == "parenthesized_expression" and value.named_child_count == 1:
            inner = value.named_children[0]
            if inner.type == "identifier":
                var_name = node_text(inner)
                var_type = scope.get(var_name)
                if var_type is not None and var_type == cast_type:
                    edits.append((node.start_byte, node.end_byte, var_name))
                    return edits

    return edits


def remove_redundant_casts(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    func_defs = [n for n in root.children if n.type == "function_definition"]
    if not func_defs:
        return c_code

    all_edits = []
    for func_def in func_defs:
        scope = _build_scope(func_def)
        all_edits.extend(_collect_cast_edits(func_def, scope))

    if not all_edits:
        return c_code

    seen = set()
    unique = []
    for start, end, replacement in all_edits:
        key = (start, end)
        if key not in seen:
            seen.add(key)
            unique.append((start, end, replacement))

    return apply_edits(c_code, unique)
