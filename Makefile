PIPX_VENV := $(HOME)/.local/share/pipx/venvs/ghidra-decomp
VENV_PY := $(PIPX_VENV)/bin/python
GHIDRA_INSTALL_DIR ?= /usr/share/ghidra

.PHONY: install uninstall test lint help e2e

install:
	pipx uninstall ghidra-decomp || echo "Not installed, skipping uninstall"
	pipx install --force .
	pipx inject ghidra-decomp pytest

uninstall:
	pipx uninstall ghidra-decomp

test:
	pipx run ruff check src/ tests/
	pipx run ruff format --check src/ tests/
	pipx run --spec mypy mypy src/ghidra_decomp/ --ignore-missing-imports
	$(VENV_PY) -m pytest tests/test_artifacts.py tests/test_decompiler_helpers.py \
		tests/test_filters.py tests/test_parallel.py tests/test_callgraph_rendering.py \
		tests/test_alloc_map.py tests/test_pcode.py tests/test_struct_map.py \
		tests/test_kernel_gdt.py tests/test_json_output.py \
		--cov=ghidra_decomp --cov-report=term-missing --cov-fail-under=80

lint:
	pipx run ruff check src/ tests/
	pipx run ruff format --check src/ tests/

e2e:
	GHIDRA_INSTALL_DIR=$(GHIDRA_INSTALL_DIR) $(VENV_PY) -m pytest tests/ -v --ignore=tests/test_polish.py

help:
	@echo "make install    pipx install --force . (+ pytest in venv)"
	@echo "make uninstall  pipx uninstall"
	@echo "make test       ruff + mypy + unit tests (no Ghidra)"
	@echo "make lint       ruff check + format check"
	@echo "make e2e        full suite including e2e (needs Ghidra, some need Docker)"
	@echo ""
	@echo "Override Ghidra path: make e2e GHIDRA_INSTALL_DIR=/path/to/ghidra"
