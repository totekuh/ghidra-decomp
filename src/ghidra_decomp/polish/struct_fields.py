"""Synthesize struct field accesses from Ghidra's pointer arithmetic patterns."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from ._parser import apply_edits, node_text, parse


def _is_pointer_type_descriptor(node) -> bool:
    if node is None or node.type != "type_descriptor":
        return False
    for child in node.children:
        if child.type == "abstract_pointer_declarator":
            return True
    return False


def _extract_pointed_type(type_desc) -> str | None:
    """Extract the pointed-to type name from a pointer type_descriptor like 'int *'."""
    parts = []
    for child in type_desc.children:
        if (
            child.type in ("primitive_type", "type_identifier", "sized_type_specifier")
            or child.type == "type_qualifier"
        ):
            parts.append(node_text(child))
    return " ".join(parts) if parts else None


def _parse_number(text: str) -> int | None:
    text = text.strip().rstrip("uUlL")
    try:
        if text.startswith(("0x", "0X")):
            return int(text, 16)
        return int(text)
    except ValueError:
        return None


def _detect_field_access(node) -> tuple[str, int, str, Any] | None:
    """Detect *(type *)((cast)base + offset) or *(type *)base patterns.

    Returns (base_name, offset, field_type, pointer_expression_node) or None.
    """
    if node.type != "pointer_expression":
        return None

    cast = None
    for child in node.children:
        if child.type == "cast_expression":
            cast = child
            break
    if cast is None:
        return None

    type_desc = cast.child_by_field_name("type")
    if not _is_pointer_type_descriptor(type_desc):
        return None

    field_type = _extract_pointed_type(type_desc)
    if field_type is None:
        return None

    value = cast.child_by_field_name("value")
    if value is None:
        return None

    if value.type == "identifier":
        return node_text(value), 0, field_type, node

    if value.type == "parenthesized_expression" and value.named_child_count == 1:
        inner = value.named_children[0]
        if inner.type == "binary_expression":
            op_found = False
            for child in inner.children:
                if child.type == "+":
                    op_found = True
                    break
            if not op_found:
                return None

            left = inner.child_by_field_name("left")
            right = inner.child_by_field_name("right")
            if left is None or right is None:
                return None

            base_name = None
            offset_val = None

            if left.type == "cast_expression":
                inner_val = left.child_by_field_name("value")
                if inner_val is not None and inner_val.type == "identifier":
                    base_name = node_text(inner_val)
            elif left.type == "identifier":
                base_name = node_text(left)

            if right.type == "number_literal":
                offset_val = _parse_number(node_text(right))

            if base_name is not None and offset_val is not None:
                return base_name, offset_val, field_type, node

    return None


def _collect_field_accesses(root) -> dict[str, list[tuple[int, str, Any]]]:
    """Walk tree, collect all field accesses grouped by base variable."""
    accesses: dict[str, list[tuple[int, str, Any]]] = defaultdict(list)

    stack = [root]
    while stack:
        node = stack.pop()
        result = _detect_field_access(node)
        if result is not None:
            base, offset, field_type, ptr_node = result
            accesses[base].append((offset, field_type, ptr_node))
        else:
            stack.extend(node.children)

    return dict(accesses)


def _build_struct_typedef(base_name: str, fields: dict[int, str]) -> str:
    """Generate typedef struct for the inferred layout."""
    sorted_offsets = sorted(fields.keys())
    lines = ["typedef struct {"]
    for offset in sorted_offsets:
        field_type = fields[offset]
        lines.append(f"    {field_type} field_0x{offset:x};")
    lines.append(f"}} _struct_{base_name};")
    return "\n".join(lines) + "\n"


def synthesize_struct_fields(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    func_defs = [n for n in root.children if n.type == "function_definition"]
    if not func_defs:
        return c_code

    all_edits = []
    struct_typedefs = []

    for func_def in func_defs:
        accesses = _collect_field_accesses(func_def)

        for base_name, access_list in accesses.items():
            distinct_offsets = {}
            for offset, field_type, _node in access_list:
                if offset not in distinct_offsets:
                    distinct_offsets[offset] = field_type

            if len(distinct_offsets) < 2:
                continue

            struct_name = f"_struct_{base_name}"
            struct_typedefs.append(_build_struct_typedef(base_name, distinct_offsets))

            for offset, _field_type, ptr_node in access_list:
                replacement = f"(({struct_name} *){base_name})->field_0x{offset:x}"
                all_edits.append((ptr_node.start_byte, ptr_node.end_byte, replacement))

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

    if struct_typedefs:
        typedef_block = "\n".join(struct_typedefs) + "\n"
        first_func = None
        new_tree = parse(result)
        for child in new_tree.root_node.children:
            if child.type == "function_definition":
                first_func = child
                break
        if first_func is not None:
            insert_pos = first_func.start_byte
            result = result[:insert_pos] + typedef_block + result[insert_pos:]

    return result
