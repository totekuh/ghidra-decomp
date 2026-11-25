"""Unit tests for struct_map builder and struct_type extraction on alloc_map."""

from __future__ import annotations

from types import SimpleNamespace

from test_pcode import (
    FakeHighVariable,
    FakeOp,
    FakeVarnode,
    const,
    fake_func,
    fake_high_function,
    fake_program,
)

from ghidra_decomp.alloc_map import (
    DEFAULT_ALLOCATORS,
    build_alloc_entries,
)
from ghidra_decomp.pcode import VarnodeNamer
from ghidra_decomp.struct_map import (
    STRUCT_MAP_SCHEMA_VERSION,
    build_struct_map,
    filter_referenced_types,
)

# ── helpers ──────────────────────────────────────────────────────────────


def _callee_addr(name="malloc", addr="00406230"):
    vn = FakeVarnode(int(addr, 16), size=4, space="ram", addr=addr)
    return vn


def _program_with_function(name, addr):
    func_obj = SimpleNamespace(getName=lambda: name)
    return fake_program(functions={addr: func_obj})


def _fake_high_typed(type_name):
    """Create a FakeHighVariable whose getDataType().getName() returns type_name."""
    dt = SimpleNamespace(getName=lambda: type_name)
    return FakeHighVariable("tmp", dt, None, has_symbol=False)


def _namer_for(ops):
    namer = VarnodeNamer()
    for op in ops:
        out = op.getOutput()
        if out is not None and not out.isConstant():
            namer.id_for(out)
        for inp in op.getInputs():
            if inp is not None and not inp.isConstant():
                namer.id_for(inp)
    return namer


# ── kmem_cache_alloc_trace size at arg 2 ────────────────────────────────


def test_kmem_cache_alloc_trace_size_at_arg2():
    """kmem_cache_alloc_trace(cache, flags, size) resolves size from arg 2."""
    target = _callee_addr("kmem_cache_alloc_trace", "00406700")
    cache_vn = FakeVarnode(0x100, space="register")
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, cache_vn, const(0xCC0), const(0x2000)])

    hf = fake_high_function([call])
    func = fake_func(name="mwifiex_init")
    program = fake_program(
        functions={
            "00406700": SimpleNamespace(getName=lambda: "kmem_cache_alloc_trace"),
        }
    )
    namer = _namer_for([call])

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    e = entries[0]
    assert e["callee"] == "kmem_cache_alloc_trace"
    assert e["size"] == 0x2000
    assert e["size_expr"] == "const"


def test_kmem_cache_alloc_trace_in_catalogue():
    assert "kmem_cache_alloc_trace" in DEFAULT_ALLOCATORS
    assert DEFAULT_ALLOCATORS["kmem_cache_alloc_trace"] == {"index": 2}


# ── struct_type extraction on alloc_map entries ─────────────────────────


def test_struct_type_from_typed_output():
    """When alloc output has a pointer-to-struct type, struct_type is extracted."""
    high = _fake_high_typed("mwifiex_private *")
    target = _callee_addr("kmalloc", "00406300")
    output = FakeVarnode(0x200, high=high)
    call = FakeOp("CALL", output, [target, const(8192), const(0xCC0)])

    hf = fake_high_function([call])
    func = fake_func(name="init_priv")
    program = fake_program(
        functions={"00406300": SimpleNamespace(getName=lambda: "kmalloc")}
    )
    namer = _namer_for([call])

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["struct_type"] == "mwifiex_private"


def test_struct_type_none_when_untyped():
    """When alloc output has no high variable, struct_type is None."""
    target = _callee_addr()
    output = FakeVarnode(0x200)
    call = FakeOp("CALL", output, [target, const(64)])

    hf = fake_high_function([call])
    func = fake_func(name="test")
    program = _program_with_function("malloc", "00406230")
    namer = _namer_for([call])

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["struct_type"] is None


def test_struct_type_strips_star_no_space():
    """Type name 'hci_dev*' (no space before star) still works."""
    high = _fake_high_typed("hci_dev*")
    target = _callee_addr("kzalloc", "00406300")
    output = FakeVarnode(0x200, high=high)
    call = FakeOp("CALL", output, [target, const(4096), const(0xCC0)])

    hf = fake_high_function([call])
    func = fake_func(name="hci_init")
    program = fake_program(
        functions={"00406300": SimpleNamespace(getName=lambda: "kzalloc")}
    )
    namer = _namer_for([call])

    entries = build_alloc_entries(hf, func, program, namer, DEFAULT_ALLOCATORS, [call])
    assert len(entries) == 1
    assert entries[0]["struct_type"] == "hci_dev"


# ── struct_map builder ──────────────────────────────────────────────────


SAMPLE_TYPES = [
    {
        "kind": "struct",
        "name": "mwifiex_private",
        "size": 8192,
        "fields": [
            {"offset": 0, "name": "adapter", "size": 8, "type": "mwifiex_adapter *"},
            {
                "offset": 498,
                "name": "wmm_ie",
                "size": 50,
                "type": "IEEEtypes_WmmParameter_t",
            },
            {"offset": 548, "name": "wmm_enabled", "size": 1, "type": "uint8_t"},
        ],
        "path": "/mwifiex_private",
        "category_path": "/",
        "alignment": {},
        "packing": {},
        "source_archive": {},
    },
    {
        "kind": "union",
        "name": "net_data",
        "size": 8,
        "fields": [
            {"name": "raw", "size": 8, "type": "uint8_t[8]"},
            {"name": "value", "size": 8, "type": "uint64_t"},
        ],
        "path": "/net_data",
        "category_path": "/",
        "alignment": {},
        "packing": {},
        "source_archive": {},
    },
    {
        "kind": "enum",
        "name": "wifi_state",
        "size": 4,
        "members": {"OFF": 0, "ON": 1},
        "path": "/wifi_state",
        "category_path": "/",
        "alignment": {},
        "packing": {},
        "source_archive": {},
    },
    {
        "kind": "typedef",
        "name": "u32",
        "base_type": "unsigned int",
        "path": "/u32",
        "category_path": "/",
        "alignment": {},
        "packing": {},
        "source_archive": {},
    },
]


def test_build_struct_map_filters_to_struct_union():
    result = build_struct_map(SAMPLE_TYPES)
    assert result["schema_version"] == STRUCT_MAP_SCHEMA_VERSION
    assert "mwifiex_private" in result["structs"]
    assert "net_data" in result["structs"]
    assert "wifi_state" not in result["structs"]
    assert "u32" not in result["structs"]


def test_build_struct_map_struct_fields_sorted():
    result = build_struct_map(SAMPLE_TYPES)
    s = result["structs"]["mwifiex_private"]
    assert s["size"] == 8192
    assert s["kind"] == "struct"
    offsets = [f["offset"] for f in s["fields"]]
    assert offsets == sorted(offsets)


def test_build_struct_map_union_has_kind():
    result = build_struct_map(SAMPLE_TYPES)
    u = result["structs"]["net_data"]
    assert u["kind"] == "union"
    assert u["size"] == 8
    assert len(u["fields"]) == 2


def test_build_struct_map_empty():
    result = build_struct_map([])
    assert result["schema_version"] == STRUCT_MAP_SCHEMA_VERSION
    assert result["structs"] == {}


# ── filter_referenced_types ─────────────────────────────────────────────


def test_filter_keeps_referenced_from_alloc():
    raw = build_struct_map(SAMPLE_TYPES)
    alloc_entries = [{"struct_type": "mwifiex_private", "stores": []}]
    filtered = filter_referenced_types(raw, alloc_entries=alloc_entries)
    assert "mwifiex_private" in filtered["structs"]
    assert "net_data" not in filtered["structs"]


def test_filter_keeps_referenced_from_store_base_type():
    raw = build_struct_map(SAMPLE_TYPES)
    alloc_entries = [
        {
            "struct_type": None,
            "stores": [{"base_type": "net_data", "kind": "field"}],
        }
    ]
    filtered = filter_referenced_types(raw, alloc_entries=alloc_entries)
    assert "net_data" in filtered["structs"]


def test_filter_keeps_referenced_from_function_params():
    raw = build_struct_map(SAMPLE_TYPES)
    function_records = [
        {
            "signature": {
                "return_type": "void",
                "parameters": [
                    {"data_type": "mwifiex_private *", "name": "priv"},
                ],
                "locals": [],
            },
            "params": [{"type": "mwifiex_private *", "name": "priv"}],
        }
    ]
    filtered = filter_referenced_types(raw, function_records=function_records)
    assert "mwifiex_private" in filtered["structs"]


def test_filter_returns_all_when_no_references():
    raw = build_struct_map(SAMPLE_TYPES)
    filtered = filter_referenced_types(raw)
    assert filtered["structs"] == raw["structs"]
