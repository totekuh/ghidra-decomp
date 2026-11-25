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


def infer_struct_types(
    filtered_map: dict[str, Any],
    full_map: dict[str, Any],
) -> dict[str, Any]:
    """Match auto-generated structs against named structs by offset patterns.

    When Ghidra decompiles a stripped binary with a GDT, it creates
    auto-generated structs (``_struct_param_1``) with only the field offsets
    it observes.  Named structs from the GDT have full field layouts.  This
    function finds named structs whose field offsets are a superset of the
    auto-generated struct's offsets, and annotates the match.
    """
    all_structs = full_map.get("structs", {})
    filtered_structs = filtered_map.get("structs", {})

    named_index: dict[str, set[int]] = {}
    for name, info in all_structs.items():
        if _is_auto_generated(name):
            continue
        if info.get("kind") != "struct":
            continue
        offsets = {f["offset"] for f in info.get("fields", []) if "offset" in f}
        if offsets:
            named_index[name] = offsets

    result_structs = dict(filtered_structs)

    for name, info in filtered_structs.items():
        if not _is_auto_generated(name):
            continue
        if info.get("kind") != "struct":
            continue

        observed = {f["offset"] for f in info.get("fields", []) if "offset" in f}
        if not observed:
            continue

        candidates = []
        for gdt_name, gdt_offsets in named_index.items():
            if observed <= gdt_offsets:
                candidates.append(gdt_name)

        if not candidates:
            continue

        candidates.sort(key=lambda n: all_structs[n].get("size", 0))
        best = candidates[0]

        entry = dict(info)
        entry["inferred_type"] = best
        entry["inferred_fields"] = all_structs[best]["fields"]
        entry["inferred_size"] = all_structs[best].get("size", 0)
        entry["inference_candidates"] = len(candidates)
        result_structs[name] = entry

    return {
        "schema_version": filtered_map["schema_version"],
        "structs": result_structs,
    }


_AUTO_PREFIXES = ("_struct_", "astruct", "anon_struct_", "unnamed_struct_")


def _is_auto_generated(name: str) -> bool:
    return any(name.startswith(p) for p in _AUTO_PREFIXES)


def _strip_pointer(type_name: str) -> str:
    """Strip pointer suffix from a type name."""
    if type_name.endswith(" *"):
        return type_name[:-2]
    if type_name.endswith("*"):
        return type_name[:-1].rstrip()
    return type_name
