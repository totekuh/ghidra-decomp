"""Build a binary-wide struct type catalog from Ghidra's DataTypeManager.

Records every resolved struct/union type that appears in decompiled function
signatures, local variables, or cast operations.  The output is a fact file
that pairs with alloc_map.json to give downstream tools (e.g. binprobe) the
field-level layout needed for struct-field overflow detection.

Must stay importable without Ghidra: every function takes already-live objects
and only calls methods on them, so unit tests can drive it with fakes.
"""

from __future__ import annotations

from typing import Any

STRUCT_MAP_SCHEMA_VERSION = 1


def build_struct_map(
    types_data: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the struct_map from already-extracted types.json data.

    Filters to struct and union kinds, reshapes into the struct_map schema
    keyed by type name.  Uses the types data that _extract_types already
    produced, so no second Ghidra walk is needed.
    """
    structs: dict[str, dict[str, Any]] = {}

    for record in types_data:
        kind = record.get("kind")
        if kind not in ("struct", "union"):
            continue

        name = record.get("name")
        if not name:
            continue

        fields = []
        for field in record.get("fields", []):
            entry: dict[str, Any] = {
                "name": field.get("name", "unknown"),
                "size": field.get("size", 0),
                "type": field.get("type", "undefined"),
            }
            if "offset" in field:
                entry["offset"] = field["offset"]
            fields.append(entry)

        if kind == "struct":
            fields.sort(key=lambda f: f.get("offset", 0))

        structs[name] = {
            "size": record.get("size", 0),
            "kind": kind,
            "fields": fields,
        }

    return {
        "schema_version": STRUCT_MAP_SCHEMA_VERSION,
        "structs": structs,
    }


def filter_referenced_types(
    struct_map: dict[str, Any],
    alloc_entries: list[dict[str, Any]] | None = None,
    function_records: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Narrow struct_map to types actually referenced by decompiled code.

    A type is referenced if:
    - It appears as struct_type on an alloc_map entry
    - It appears as base_type on a store in an alloc_map entry
    - It appears as a parameter or local variable type in function records
    - It appears as a return type in function records
    """
    referenced: set[str] = set()

    for entry in alloc_entries or []:
        st = entry.get("struct_type")
        if st:
            referenced.add(st)
        for store in entry.get("stores", []):
            bt = store.get("base_type")
            if bt:
                referenced.add(bt)

    for record in function_records or []:
        rt = record.get("return_type") or record.get("signature", {}).get("return_type")
        if rt:
            referenced.add(rt)
        for param in record.get("params", []) or record.get("signature", {}).get(
            "parameters", []
        ):
            pt = param.get("type") or param.get("data_type")
            if pt:
                referenced.add(_strip_pointer(pt))
        for local in record.get("signature", {}).get("locals", []):
            lt = local.get("data_type")
            if lt:
                referenced.add(_strip_pointer(lt))

    if not referenced:
        return struct_map

    filtered_structs = {
        name: info
        for name, info in struct_map.get("structs", {}).items()
        if name in referenced
    }

    return {
        "schema_version": struct_map["schema_version"],
        "structs": filtered_structs,
    }


def _strip_pointer(type_name: str) -> str:
    """Strip pointer suffix from a type name."""
    if type_name.endswith(" *"):
        return type_name[:-2]
    if type_name.endswith("*"):
        return type_name[:-1].rstrip()
    return type_name
