"""Type system extraction from Ghidra's data type manager."""

from __future__ import annotations

from ..constants import TYPE_USAGE_LIMIT


def _category_path(dt) -> str:
    """Report where the type manager filed this type."""
    category = dt.getCategoryPath()
    if category is None:
        return "/"
    return category.getPath()


def _alignment_record(dt, composite) -> dict:
    """Report how the type is aligned."""
    record: dict = {"value": dt.getAlignment(), "type": None, "minimum": None}
    if composite is None:
        return record
    record["type"] = str(composite.getAlignmentType())
    if composite.hasExplicitMinimumAlignment():
        record["minimum"] = composite.getExplicitMinimumAlignment()
    return record


def _packing_record(composite) -> dict | None:
    """Report how a composite's members are packed."""
    if composite is None:
        return None
    record: dict = {"type": str(composite.getPackingType()), "value": None}
    if composite.hasExplicitPackingValue():
        record["value"] = composite.getExplicitPackingValue()
    return record


def _source_archive_record(dt) -> dict | None:
    """Report where the type came from."""
    archive = dt.getSourceArchive()
    if archive is None:
        return None
    return {"name": archive.getName(), "archive_type": str(archive.getArchiveType())}


def _referenced_data_types(declared) -> list[tuple]:
    """Every type a declaration reaches, paired with the declaration itself."""
    from ghidra.program.model.data import Array, Pointer, TypeDef

    if declared is None:
        return []

    via = declared.getName()
    reached: list[tuple] = []
    seen: set[str] = set()
    current = declared
    while current is not None:
        path = current.getPathName()
        if path in seen:
            break
        seen.add(path)
        reached.append((current, via))
        if not isinstance(current, (Pointer, Array, TypeDef)):
            break
        current = current.getDataType()
    return reached


def _type_usage_index(program) -> dict[str, list[dict]]:
    """Map every type to the data and functions that use it."""
    usage: dict[str, list[dict]] = {}

    def record(declared, entry: dict) -> None:
        for dt, via in _referenced_data_types(declared):
            usage.setdefault(dt.getPathName(), []).append({**entry, "via": via})

    for data in program.getListing().getDefinedData(True):
        record(
            data.getDataType(),
            {
                "kind": "data",
                "address": data.getAddress().toString(),
                "name": data.getLabel(),
                "ordinal": None,
            },
        )

    for func in program.getFunctionManager().getFunctions(True):
        entry = {
            "kind": "function_return",
            "address": func.getEntryPoint().toString(),
            "name": func.getName(),
            "ordinal": None,
        }
        record(func.getReturnType(), entry)
        for parameter in func.getParameters():
            record(
                parameter.getDataType(),
                {
                    **entry,
                    "kind": "function_parameter",
                    "ordinal": parameter.getOrdinal(),
                },
            )

    return usage


def _type_usage(entries: list[dict]) -> dict:
    """Bound the recorded user list without hiding how large it really is."""
    ordered = sorted(
        entries,
        key=lambda entry: (
            entry["kind"],
            entry["address"],
            -1 if entry["ordinal"] is None else entry["ordinal"],
            entry["via"] or "",
        ),
    )
    return {
        "usage_count": len(ordered),
        "usage_truncated": len(ordered) > TYPE_USAGE_LIMIT,
        "used_by": ordered[:TYPE_USAGE_LIMIT],
    }


def _extract_types(program) -> list[dict]:
    """Extract all recovered types (structs, enums, typedefs, unions, function pointers)."""
    dtm = program.getDataTypeManager()

    from ghidra.program.model.data import (
        BuiltInDataType,
        Composite,
        Enum,
        FunctionDefinition,
        Structure,
        TypeDef,
        Union,
    )

    usage = _type_usage_index(program)
    result = []

    for dt in dtm.getAllDataTypes():
        if isinstance(dt, BuiltInDataType):
            continue

        if isinstance(dt, Structure):
            specific = {
                "kind": "struct",
                "size": dt.getLength(),
                "fields": [
                    {
                        "name": comp.getFieldName() or f"field_0x{comp.getOffset():x}",
                        "type": comp.getDataType().getName(),
                        "offset": comp.getOffset(),
                        "size": comp.getLength(),
                    }
                    for comp in dt.getComponents()
                ],
            }

        elif isinstance(dt, Union):
            specific = {
                "kind": "union",
                "size": dt.getLength(),
                "fields": [
                    {
                        "name": comp.getFieldName() or f"field_{comp.getOrdinal()}",
                        "type": comp.getDataType().getName(),
                        "size": comp.getLength(),
                    }
                    for comp in dt.getComponents()
                ],
            }

        elif isinstance(dt, Enum):
            specific = {
                "kind": "enum",
                "size": dt.getLength(),
                "members": {name: dt.getValue(name) for name in dt.getNames()},
            }

        elif isinstance(dt, TypeDef):
            base = dt.getBaseDataType()
            specific = {
                "kind": "typedef",
                "base_type": base.getName() if base else "unknown",
            }

        elif isinstance(dt, FunctionDefinition):
            ret = dt.getReturnType()
            specific = {
                "kind": "function_pointer",
                "return_type": ret.getName() if ret else "void",
                "params": [
                    {"type": arg.getDataType().getName(), "name": arg.getName()}
                    for arg in dt.getArguments()
                ],
            }

        else:
            continue

        path = dt.getPathName()
        composite = dt if isinstance(dt, Composite) else None
        result.append(
            {
                **specific,
                "name": dt.getName(),
                "path": path,
                "category_path": _category_path(dt),
                "alignment": _alignment_record(dt, composite),
                "packing": _packing_record(composite),
                "source_archive": _source_archive_record(dt),
                **_type_usage(usage.get(path, [])),
            }
        )

    result.sort(key=lambda record: record["path"])
    return result
