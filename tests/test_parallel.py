"""Unit tests for bounded parallel decompilation."""

import sys
import threading
from types import ModuleType, SimpleNamespace

import pytest

from ghidra_decomp.decompiler import (
    STATUS_FAILED,
    STATUS_FALLBACK,
    STATUS_SUCCESS,
    _decompile_functions,
    _decompile_one,
    default_workers,
)


class FakeAddress:
    def __init__(self, value):
        self.value = value

    def toString(self):
        return self.value


def _function(address, name="func"):
    return SimpleNamespace(
        getEntryPoint=lambda: FakeAddress(address), getName=lambda: name
    )


def _high_symbol(name, is_parameter=False):
    return SimpleNamespace(
        getName=lambda: name,
        getDataType=lambda: SimpleNamespace(getName=lambda: "u32"),
        getSize=lambda: 4,
        getStorage=lambda: None,
        isParameter=lambda: is_parameter,
    )


def _result(
    *, completed=True, c_code="int f(void) { }", error=None, symbols=(), high=True
):
    high_function = None
    if high:
        high_function = SimpleNamespace(
            getLocalSymbolMap=lambda: SimpleNamespace(getSymbols=lambda: list(symbols))
        )
    return SimpleNamespace(
        decompileCompleted=lambda: completed,
        getDecompiledFunction=lambda: (
            SimpleNamespace(getC=lambda: c_code) if c_code is not None else None
        ),
        getErrorMessage=lambda: error,
        getHighFunction=lambda: high_function,
    )


def test_a_decompiled_function_reports_success_and_its_c():
    decomp = SimpleNamespace(decompileFunction=lambda func, timeout, monitor: _result())

    assert _decompile_one(decomp, None, _function("1000"), 30) == (
        STATUS_SUCCESS,
        None,
        "int f(void) { }",
        [],
    )


def test_an_empty_result_is_a_fallback_not_a_failure():
    decomp = SimpleNamespace(
        decompileFunction=lambda func, timeout, monitor: _result(c_code="")
    )

    status, error, c_code, _ = _decompile_one(decomp, None, _function("1000"), 30)

    assert status == STATUS_FALLBACK
    assert error == "decompiler returned no C output"
    assert c_code == ""


def test_a_declined_function_is_a_fallback():
    decomp = SimpleNamespace(
        decompileFunction=lambda func, timeout, monitor: _result(
            completed=False, error="Low-level Error: unsupported"
        )
    )

    status, error, *_ = _decompile_one(decomp, None, _function("1000"), 30)

    assert status == STATUS_FALLBACK
    assert "unsupported" in error


@pytest.mark.parametrize(
    "message",
    ["Decompilation timeout", "process timed out after 30 seconds"],
)
def test_a_timeout_is_recorded_as_failed_and_stays_retryable(message):
    decomp = SimpleNamespace(
        decompileFunction=lambda func, timeout, monitor: _result(
            completed=False, error=message
        )
    )

    status, error, *_ = _decompile_one(decomp, None, _function("1000"), 30)

    assert status == STATUS_FAILED
    assert error == message


def test_an_exception_is_recorded_as_failed():
    def raiser(func, timeout, monitor):
        raise RuntimeError("JVM exploded")

    decomp = SimpleNamespace(decompileFunction=raiser)

    status, error, *_ = _decompile_one(decomp, None, _function("1000"), 30)

    assert status == STATUS_FAILED
    assert "JVM exploded" in error


@pytest.fixture
def fake_ghidra(monkeypatch):
    """Install a fake DecompInterface that records how it is used."""
    created = []

    class FakeDecompInterface:
        def __init__(self):
            self.threads = set()
            self.timeouts = []
            self.disposed = False
            self.opened = None
            created.append(self)

        def openProgram(self, program):
            self.opened = program

        def decompileFunction(self, func, timeout, monitor):
            self.threads.add(threading.get_ident())
            self.timeouts.append(timeout)
            return _result(c_code=f"/* {func.getEntryPoint().toString()} */")

        def dispose(self):
            self.disposed = True

    decompiler_module = ModuleType("ghidra.app.decompiler")
    decompiler_module.DecompInterface = FakeDecompInterface
    task_module = ModuleType("ghidra.util.task")
    task_module.ConsoleTaskMonitor = lambda: object()
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", decompiler_module)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", task_module)
    return created


def test_a_serial_run_uses_one_interface_and_disposes_it(fake_ghidra):
    functions = [_function(f"{index:04x}") for index in range(5)]

    results = _decompile_functions(object(), functions, timeout=30, workers=1)

    assert len(fake_ghidra) == 1
    assert fake_ghidra[0].disposed is True
    assert set(results) == {func.getEntryPoint().toString() for func in functions}


def test_an_interface_is_never_shared_between_threads(fake_ghidra):
    functions = [_function(f"{index:04x}") for index in range(40)]

    _decompile_functions(object(), functions, timeout=30, workers=4)

    assert 1 <= len(fake_ghidra) <= 4
    for interface in fake_ghidra:
        assert len(interface.threads) == 1, "one interface served two threads"
    assert all(interface.disposed for interface in fake_ghidra)
    # Two interfaces must never be the same object handed out twice.
    assert len({id(interface) for interface in fake_ghidra}) == len(fake_ghidra)


def test_every_function_is_decompiled_exactly_once(fake_ghidra):
    functions = [_function(f"{index:04x}") for index in range(40)]

    results = _decompile_functions(object(), functions, timeout=30, workers=4)

    assert set(results) == {func.getEntryPoint().toString() for func in functions}
    assert sum(len(interface.timeouts) for interface in fake_ghidra) == len(functions)
    for address, (status, _, c_code, _locals) in results.items():
        assert status == STATUS_SUCCESS
        assert c_code == f"/* {address} */"


@pytest.mark.parametrize("workers", [1, 2, 4, 8])
def test_the_per_function_timeout_is_never_multiplied(fake_ghidra, workers):
    functions = [_function(f"{index:04x}") for index in range(8)]

    _decompile_functions(object(), functions, timeout=30, workers=workers)

    observed = [timeout for interface in fake_ghidra for timeout in interface.timeouts]
    assert observed == [30] * len(functions)


@pytest.mark.parametrize("workers", [1, 4])
def test_results_do_not_depend_on_worker_count(fake_ghidra, workers):
    functions = [_function(f"{index:04x}") for index in range(16)]

    results = _decompile_functions(object(), functions, timeout=30, workers=workers)

    assert results == {
        func.getEntryPoint().toString(): (
            STATUS_SUCCESS,
            None,
            f"/* {func.getEntryPoint().toString()} */",
            [],
        )
        for func in functions
    }


def test_one_failing_function_does_not_affect_the_others(monkeypatch):
    created = []

    class FailingInterface:
        def __init__(self):
            self.disposed = False
            created.append(self)

        def openProgram(self, program):
            pass

        def decompileFunction(self, func, timeout, monitor):
            if func.getEntryPoint().toString() == "0002":
                raise RuntimeError("decompiler crashed")
            return _result()

        def dispose(self):
            self.disposed = True

    decompiler_module = ModuleType("ghidra.app.decompiler")
    decompiler_module.DecompInterface = FailingInterface
    task_module = ModuleType("ghidra.util.task")
    task_module.ConsoleTaskMonitor = lambda: object()
    monkeypatch.setitem(sys.modules, "ghidra.app.decompiler", decompiler_module)
    monkeypatch.setitem(sys.modules, "ghidra.util.task", task_module)

    functions = [_function(f"{index:04x}") for index in range(4)]
    results = _decompile_functions(object(), functions, timeout=30, workers=2)

    assert results["0002"][0] == STATUS_FAILED
    assert "decompiler crashed" in results["0002"][1]
    assert [results[address][0] for address in ("0000", "0001", "0003")] == [
        STATUS_SUCCESS
    ] * 3
    assert all(interface.disposed for interface in created)


def test_default_worker_count_is_bounded():
    workers = default_workers()

    assert 1 <= workers <= 4


def test_decompiled_locals_are_returned_from_the_worker():
    symbols = [_high_symbol("uVar1"), _high_symbol("param_1", is_parameter=True)]
    decomp = SimpleNamespace(
        decompileFunction=lambda func, timeout, monitor: _result(symbols=symbols)
    )

    status, _, _, locals_ = _decompile_one(decomp, None, _function("1000"), 30)

    assert status == STATUS_SUCCESS
    # Locals must be plain data: the decompilation result belongs to the worker
    # that produced it and must not outlive the call.
    assert locals_ == [
        {
            "name": "uVar1",
            "data_type": "u32",
            "size": 4,
            "storage": {
                "kind": "unassigned",
                "register": None,
                "stack_offset": None,
                "description": None,
            },
            "source": None,
        }
    ]


def test_locals_are_empty_when_no_high_function_is_available():
    decomp = SimpleNamespace(
        decompileFunction=lambda func, timeout, monitor: _result(high=False)
    )

    status, _, _, locals_ = _decompile_one(decomp, None, _function("1000"), 30)

    assert status == STATUS_SUCCESS
    assert locals_ == []


def test_a_failed_function_returns_no_locals():
    def raiser(func, timeout, monitor):
        raise RuntimeError("boom")

    _, _, _, locals_ = _decompile_one(
        SimpleNamespace(decompileFunction=raiser), None, _function("1000"), 30
    )

    assert locals_ == []


def test_a_declined_function_still_reports_the_locals_it_produced():
    # The decompiler can model variables and still decline to emit C; that
    # information is worth keeping.
    decomp = SimpleNamespace(
        decompileFunction=lambda func, timeout, monitor: _result(
            completed=False, error="Low-level Error", symbols=[_high_symbol("uVar1")]
        )
    )

    status, _, _, locals_ = _decompile_one(decomp, None, _function("1000"), 30)

    assert status == STATUS_FALLBACK
    assert [item["name"] for item in locals_] == ["uVar1"]
