"""Unit tests for the high-pcode serializer, driven entirely with fakes.

The serializer only calls methods on the objects passed to it, so these fakes
reproduce the slice of the Ghidra API it touches — no embedded Ghidra needed.
"""

from __future__ import annotations

from types import SimpleNamespace

from ghidra_decomp.pcode import serialize_high_function

SCHEMA = 8


class FakeStorage:
    """Variable storage; a real class so ``str(storage)`` reaches a ``__str__``."""

    def __init__(self, kind="register", register="a0", offset=None):
        self.kind = kind
        self.register = register
        self.offset = offset

    def isUnassignedStorage(self):
        return self.kind == "unassigned"

    def isStackStorage(self):
        return self.kind == "stack"

    def isRegisterStorage(self):
        return self.kind == "register"

    def isMemoryStorage(self):
        return self.kind == "memory"

    def getStackOffset(self):
        return self.offset

    def getRegister(self):
        return SimpleNamespace(getName=lambda: self.register)

    def __str__(self):
        return f"{self.register or 'Stack'}:4"


class FakeDataType:
    def __init__(self, name, *, display_name=None, elem_size=None, count=None):
        self._name = name
        self._display_name = display_name or name
        self._elem_size = elem_size
        self._count = count

    def getName(self):
        return self._name

    def getDisplayName(self):
        return self._display_name

    # Present only for array types; absence is how the serializer tells them apart.
    def getNumElements(self):
        return self._count

    def getElementLength(self):
        return self._elem_size


class FakeHighVariable:
    """A recovered variable. Storage hangs off its symbol, as in real Ghidra.

    ``symbol=None`` models an unnamed temporary, whose storage must fall back to
    the varnode's raw register.
    """

    def __init__(self, name, data_type, storage, *, has_symbol=True):
        self._name = name
        self._data_type = data_type
        self._storage = storage
        self._has_symbol = has_symbol

    def getName(self):
        return self._name

    def getDataType(self):
        return self._data_type

    def getSymbol(self):
        if not self._has_symbol:
            return None
        return SimpleNamespace(
            getName=lambda: self._name,
            getStorage=lambda: self._storage,
        )


class FakeVarnode:
    def __init__(
        self, offset, size=4, space="register", const=False, high=None, addr=None
    ):
        self._offset = offset
        self._size = size
        self._space = space
        self._const = const
        self._high = high
        self._addr = addr if addr is not None else f"{space}:{offset:x}"
        self._def = None  # wired after the defining op exists

    def isConstant(self):
        return self._const

    def getOffset(self):
        return self._offset

    def getSize(self):
        return self._size

    def getAddress(self):
        space_obj = SimpleNamespace(getName=lambda: self._space)
        return SimpleNamespace(
            getAddressSpace=lambda: space_obj,
            toString=lambda: self._addr,
        )

    def getDef(self):
        return self._def

    def getHigh(self):
        return self._high


def const(value, size=4):
    return FakeVarnode(value, size=size, space="const", const=True)


class FakeOp:
    _clock = 0

    def __init__(self, mnemonic, output, inputs, addr="00087600"):
        self._mnemonic = mnemonic
        self._output = output
        self._inputs = list(inputs)
        self._addr = addr
        FakeOp._clock += 1
        self._time = FakeOp._clock
        if output is not None and not output.isConstant():
            output._def = self

    def getMnemonic(self):
        return self._mnemonic

    def getOutput(self):
        return self._output

    def getInputs(self):
        return list(self._inputs)

    def getSeqnum(self):
        return SimpleNamespace(
            getTime=lambda: self._time,
            getTarget=lambda: SimpleNamespace(toString=lambda: self._addr),
        )


class FakeBlock:
    def __init__(self, index, ops, start, stop):
        self._index = index
        self._ops = ops
        self._start = start
        self._stop = stop
        self._out: list[FakeBlock] = []
        self._in: list[FakeBlock] = []

    def getIndex(self):
        return self._index

    def getStart(self):
        return SimpleNamespace(toString=lambda: self._start)

    def getStop(self):
        return SimpleNamespace(toString=lambda: self._stop)

    def getIterator(self):
        return list(self._ops)

    def getOutSize(self):
        return len(self._out)

    def getOut(self, i):
        return self._out[i]

    def getInSize(self):
        return len(self._in)

    def getIn(self, i):
        return self._in[i]


def fake_high_function(ops, blocks=None, symbols=None):
    return SimpleNamespace(
        getPcodeOps=lambda: list(ops),
        getBasicBlocks=lambda: list(blocks or []),
        getLocalSymbolMap=lambda: SimpleNamespace(
            getSymbols=lambda: list(symbols or [])
        ),
    )


class FakeParameter:
    def __init__(self, name, data_type, ordinal=0):
        self._name = name
        self._data_type = data_type
        self._ordinal = ordinal

    def getName(self):
        return self._name

    def getDataType(self):
        return self._data_type

    def getOrdinal(self):
        return self._ordinal


def fake_func(
    name="RTMPDeFragmentDataFrame",
    entry="00087514",
    parameters=None,
    signature_source="Analysis",
):
    body = SimpleNamespace(
        getAddressRanges=lambda _ordered: [
            SimpleNamespace(
                getMinAddress=lambda: SimpleNamespace(toString=lambda: entry),
                getMaxAddress=lambda: SimpleNamespace(toString=lambda: "000878ff"),
            )
        ]
    )
    params = list(parameters or [])
    return SimpleNamespace(
        getName=lambda: name,
        getEntryPoint=lambda: SimpleNamespace(toString=lambda: entry),
        getBody=lambda: body,
        getParameters=lambda: list(params),
        getSignatureSource=lambda: signature_source,
    )


def fake_program(
    functions=None, memory=None, arch="MIPS:LE:32:default", registers=None
):
    functions = functions or {}
    registers = registers or {}

    def get_register(varnode):
        name = registers.get(id(varnode))
        return SimpleNamespace(getName=lambda: name) if name is not None else None

    return SimpleNamespace(
        getLanguageID=lambda: SimpleNamespace(toString=lambda: arch),
        getFunctionManager=lambda: SimpleNamespace(
            getFunctionAt=lambda addr: functions.get(addr.toString()),
            getFunctionContaining=lambda addr: functions.get(addr.toString()),
        ),
        getMemory=lambda: memory,
        getRegister=get_register,
    )


# --------------------------------------------------------------------------- #


def test_none_high_function_serializes_to_none():
    assert (
        serialize_high_function(
            None, fake_func(), fake_program(), schema_version=SCHEMA
        )
        is None
    )


def test_envelope_carries_identity_and_arch():
    op = FakeOp("COPY", FakeVarnode(0x200), [FakeVarnode(0x100)])
    payload = serialize_high_function(
        fake_high_function([op]), fake_func(), fake_program(), schema_version=SCHEMA
    )

    assert payload["schema_version"] == SCHEMA
    assert payload["function"] == "RTMPDeFragmentDataFrame"
    assert payload["entry"] == "00087514"
    assert payload["arch"] == "MIPS:LE:32:default"
    assert payload["body_ranges"] == [{"start": "00087514", "end": "000878ff"}]
    assert {"ops", "varnodes", "blocks", "calls", "locals", "rodata"} <= set(payload)


def test_def_use_resolves_through_a_shared_varnode_id():
    # INT_ADD defines a value; STORE consumes it. The same varnode object must
    # serialize to the same id in both places, or def-use is lost.
    length = FakeVarnode(0x300)
    add = FakeOp("INT_ADD", length, [FakeVarnode(0x100), const(2048)])
    store = FakeOp("STORE", None, [FakeVarnode(0x400, space="unique"), length])

    payload = serialize_high_function(
        fake_high_function([add, store]),
        fake_func(),
        fake_program(),
        schema_version=SCHEMA,
    )

    add_out = payload["ops"][0]["output"]["vn"]
    store_len = payload["ops"][1]["inputs"][1]["vn"]
    assert add_out == store_len


def test_constants_are_inlined_not_given_ids():
    add = FakeOp(
        "INT_ADD", FakeVarnode(0x300), [FakeVarnode(0x100), const(2048, size=4)]
    )
    payload = serialize_high_function(
        fake_high_function([add]), fake_func(), fake_program(), schema_version=SCHEMA
    )

    inputs = payload["ops"][0]["inputs"]
    assert inputs[1] == {"const": 2048, "size": 4}
    assert "vn" not in inputs[1]


def test_signed_opcode_is_preserved_verbatim():
    # Signedness lives in the opcode, never the varnode; INT_SLESS must survive.
    guard = FakeOp(
        "INT_SLESS", FakeVarnode(0x500, size=1), [FakeVarnode(0x100), const(0x92A)]
    )
    payload = serialize_high_function(
        fake_high_function([guard]), fake_func(), fake_program(), schema_version=SCHEMA
    )

    assert payload["ops"][0]["op"] == "INT_SLESS"
    assert payload["ops"][0]["inputs"][1] == {"const": 0x92A, "size": 4}


def test_varnode_map_resolves_highvariable_with_array_extent():
    buf_type = FakeDataType("uchar[64]", elem_size=1, count=64)
    high = FakeHighVariable("buf", buf_type, FakeStorage("stack", None, -72))
    varnode = FakeVarnode(0x100, size=4, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])

    payload = serialize_high_function(
        fake_high_function([op]), fake_func(), fake_program(), schema_version=SCHEMA
    )

    entries = {entry["highvar"]: entry for entry in payload["varnodes"]}
    assert "buf" in entries
    assert entries["buf"]["type"] == "uchar[64]"
    assert entries["buf"]["storage"]["kind"] == "stack"
    assert entries["buf"]["storage"]["stack_offset"] == -72
    assert entries["buf"]["array"] == {"elem_size": 1, "count": 64}


def test_varnode_type_includes_pointer_marker():
    ptr_type = FakeDataType("my_struct", display_name="my_struct *")
    high = FakeHighVariable("ptr", ptr_type, FakeStorage("register", "RDI"))
    varnode = FakeVarnode(0x100, size=8, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])

    payload = serialize_high_function(
        fake_high_function([op]), fake_func(), fake_program(), schema_version=SCHEMA
    )

    entries = {entry["highvar"]: entry for entry in payload["varnodes"]}
    assert "ptr" in entries
    assert entries["ptr"]["type"] == "my_struct *"


def test_unnamed_temporary_storage_falls_back_to_its_register():
    high = FakeHighVariable("UNNAMED", FakeDataType("uint"), None, has_symbol=False)
    varnode = FakeVarnode(0x100, size=4, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])
    program = fake_program(registers={id(varnode): "a2"})

    payload = serialize_high_function(
        fake_high_function([op]), fake_func(), program, schema_version=SCHEMA
    )

    entry = next(e for e in payload["varnodes"] if e["type"] == "uint")
    assert entry["storage"]["kind"] == "register"
    assert entry["storage"]["register"] == "a2"


def test_calls_resolve_callee_and_positional_args():
    target = FakeVarnode(0x128104, space="ram", addr="00128104")
    dst = FakeVarnode(0x300)
    src = FakeVarnode(0x400)
    call = FakeOp("CALL", None, [target, dst, src, const(0x40)])
    program = fake_program(
        functions={"00128104": SimpleNamespace(getName=lambda: "memmove")}
    )

    payload = serialize_high_function(
        fake_high_function([call]), fake_func(), program, schema_version=SCHEMA
    )

    assert len(payload["calls"]) == 1
    entry = payload["calls"][0]
    assert entry["op"] == "CALL"
    assert entry["callee"] == "memmove"
    assert entry["callee_addr"] == "00128104"
    # input[0] is the target; the args are input[1:], in order.
    assert len(entry["args"]) == 3
    assert entry["args"][2] == {"const": 0x40, "size": 4}


def test_callind_has_null_callee():
    call = FakeOp(
        "CALLIND", None, [FakeVarnode(0x100, space="register"), FakeVarnode(0x300)]
    )
    payload = serialize_high_function(
        fake_high_function([call]), fake_func(), fake_program(), schema_version=SCHEMA
    )

    entry = payload["calls"][0]
    assert entry["op"] == "CALLIND"
    assert entry["callee"] is None
    assert entry["callee_addr"] is None
    assert len(entry["args"]) == 1


def test_blocks_expose_cfg_and_detect_back_edges():
    op0 = FakeOp(
        "INT_ADD", FakeVarnode(0x300), [FakeVarnode(0x100), const(1)], addr="0001"
    )
    op1 = FakeOp(
        "CBRANCH",
        None,
        [FakeVarnode(0x9, space="ram"), FakeVarnode(0x300)],
        addr="0002",
    )
    header = FakeBlock(0, [op0], "0001", "0001")
    body = FakeBlock(1, [op1], "0002", "0002")
    # A loop: header -> body -> header. The edge body->header is the back-edge.
    header._out = [body]
    body._out = [header]
    body._in = [header]
    header._in = [body]

    payload = serialize_high_function(
        fake_high_function([op0, op1], blocks=[header, body]),
        fake_func(),
        fake_program(),
        schema_version=SCHEMA,
    )

    blocks = {entry["block"]: entry for entry in payload["blocks"]}
    assert blocks[0]["succ"] == [1]
    assert blocks[1]["succ"] == [0]
    assert blocks[0]["ops"] == [0]
    assert blocks[1]["ops"] == [1]
    # The back-edge targets the header, which is therefore a loop header.
    assert blocks[1]["back_edges"] == [[1, 0]]
    assert blocks[0]["loop_header"] is True
    assert blocks[1]["loop_header"] is False


def test_stack_locals_report_array_capacity():
    buf_type = FakeDataType("uchar[64]", elem_size=1, count=64)
    symbol = SimpleNamespace(
        getName=lambda: "buf",
        getDataType=lambda: buf_type,
        getSize=lambda: 64,
        getStorage=lambda: FakeStorage("stack", None, -72),
    )
    scalar = SimpleNamespace(
        getName=lambda: "i",
        getDataType=lambda: FakeDataType("int"),
        getSize=lambda: 4,
        getStorage=lambda: FakeStorage("register", "a0"),
    )

    payload = serialize_high_function(
        fake_high_function([], symbols=[symbol, scalar]),
        fake_func(),
        fake_program(),
        schema_version=SCHEMA,
    )

    # Only stack-resident locals are capacity facts; the register scalar is dropped.
    assert [entry["name"] for entry in payload["locals"]] == ["buf"]
    buf = payload["locals"][0]
    assert buf["size"] == 64
    assert buf["array"] == {"elem_size": 1, "count": 64}
    assert buf["storage"]["stack_offset"] == -72


class FakeMemory:
    def __init__(self, values, writable, big_endian=False):
        self._values = values  # addr string -> (int value, size)
        self._writable = writable
        self._big_endian = big_endian

    def getBlock(self, addr):
        name = addr.toString()
        if name not in self._values:
            return None
        return SimpleNamespace(isWrite=lambda: self._writable)

    def getBytes(self, addr, buf):
        value, _size = self._values[addr.toString()]
        raw = value.to_bytes(len(buf), "big" if self._big_endian else "little")
        buf[:] = raw

    def isBigEndian(self):
        return self._big_endian


def test_rodata_resolves_readonly_reads():
    operand = FakeVarnode(0x120000, size=4, space="ram", addr="00120000")
    load = FakeOp(
        "LOAD",
        FakeVarnode(0x300),
        [FakeVarnode(0x9, space="const", const=True), operand],
    )
    memory = FakeMemory({"00120000": (0x92A, 4)}, writable=False)
    payload = serialize_high_function(
        fake_high_function([load]),
        fake_func(),
        fake_program(memory=memory),
        schema_version=SCHEMA,
    )

    assert payload["rodata"] == [{"addr": "00120000", "size": 4, "value": 0x92A}]


def test_rodata_skips_writable_globals():
    operand = FakeVarnode(0x130000, size=4, space="ram", addr="00130000")
    load = FakeOp(
        "LOAD",
        FakeVarnode(0x300),
        [FakeVarnode(0x9, space="const", const=True), operand],
    )
    memory = FakeMemory({"00130000": (0x10, 4)}, writable=True)
    payload = serialize_high_function(
        fake_high_function([load]),
        fake_func(),
        fake_program(memory=memory),
        schema_version=SCHEMA,
    )

    assert payload["rodata"] == []


def test_dwarf_param_type_overrides_generic_uchar_pointer():
    high = FakeHighVariable(
        "buffer", FakeDataType("uchar", display_name="uchar * *"), FakeStorage()
    )
    varnode = FakeVarnode(0x100, size=8, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])

    struct_type = FakeDataType(
        "mwifiex_ie_types_vendor_param_set",
        display_name="mwifiex_ie_types_vendor_param_set * *",
    )
    func = fake_func(
        parameters=[FakeParameter("buffer", struct_type, ordinal=1)],
        signature_source="Imported",
    )

    payload = serialize_high_function(
        fake_high_function([op]), func, fake_program(), schema_version=SCHEMA
    )

    entries = {e["highvar"]: e for e in payload["varnodes"]}
    assert entries["buffer"]["type"] == "mwifiex_ie_types_vendor_param_set * *"


def test_dwarf_param_type_keeps_specific_high_variable_type():
    high = FakeHighVariable(
        "priv",
        FakeDataType("mwifiex_private", display_name="mwifiex_private *"),
        FakeStorage(),
    )
    varnode = FakeVarnode(0x100, size=8, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])

    declared = FakeDataType("mwifiex_private", display_name="mwifiex_private *")
    func = fake_func(
        parameters=[FakeParameter("priv", declared, ordinal=0)],
        signature_source="Imported",
    )

    payload = serialize_high_function(
        fake_high_function([op]), func, fake_program(), schema_version=SCHEMA
    )

    entries = {e["highvar"]: e for e in payload["varnodes"]}
    assert entries["priv"]["type"] == "mwifiex_private *"


def test_dwarf_param_type_no_override_when_high_type_is_not_generic():
    high = FakeHighVariable(
        "ctx",
        FakeDataType("some_ctx", display_name="some_ctx *"),
        FakeStorage(),
    )
    varnode = FakeVarnode(0x100, size=8, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])

    declared = FakeDataType("other_ctx", display_name="other_ctx *")
    func = fake_func(
        parameters=[FakeParameter("ctx", declared, ordinal=0)],
        signature_source="Imported",
    )

    payload = serialize_high_function(
        fake_high_function([op]), func, fake_program(), schema_version=SCHEMA
    )

    entries = {e["highvar"]: e for e in payload["varnodes"]}
    assert entries["ctx"]["type"] == "some_ctx *"


def test_dwarf_param_type_works_without_parameters():
    high = FakeHighVariable(
        "buf", FakeDataType("uchar", display_name="uchar *"), FakeStorage()
    )
    varnode = FakeVarnode(0x100, size=8, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])

    payload = serialize_high_function(
        fake_high_function([op]), fake_func(), fake_program(), schema_version=SCHEMA
    )

    entries = {e["highvar"]: e for e in payload["varnodes"]}
    assert entries["buf"]["type"] == "uchar *"


def test_dwarf_param_type_ignores_analysis_sourced_params():
    high = FakeHighVariable(
        "buffer", FakeDataType("uchar", display_name="uchar * *"), FakeStorage()
    )
    varnode = FakeVarnode(0x100, size=8, high=high)
    op = FakeOp("COPY", FakeVarnode(0x200), [varnode])

    struct_type = FakeDataType(
        "mwifiex_ie_types_vendor_param_set",
        display_name="mwifiex_ie_types_vendor_param_set * *",
    )
    func = fake_func(
        parameters=[FakeParameter("buffer", struct_type, ordinal=1)],
        signature_source="Analysis",
    )

    payload = serialize_high_function(
        fake_high_function([op]), func, fake_program(), schema_version=SCHEMA
    )

    entries = {e["highvar"]: e for e in payload["varnodes"]}
    assert entries["buffer"]["type"] == "uchar * *"
