.PHONY: install uninstall test lint

install:
	pipx install --force .

uninstall:
	pipx uninstall ghidra-decomp

test:
	pipx run ruff check src/ tests/
	pipx run ruff format --check src/ tests/
	pipx run --spec mypy mypy src/ghidra_decomp/ --ignore-missing-imports
	PYTHONPATH=src python -m pytest tests/test_artifacts.py tests/test_decompiler_helpers.py \
		tests/test_filters.py tests/test_parallel.py

lint:
	pipx run ruff check src/ tests/
	pipx run ruff format --check src/ tests/
