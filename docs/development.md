# Development

## Makefile

```bash
make install    # pipx install --force .
make uninstall  # pipx uninstall ghidra-decomp
make test       # lint + typecheck + unit tests
make lint       # ruff check + format check only
```

## Fast checks

```bash
ruff check src/ tests/
ruff format --check src/ tests/
mypy src/ghidra_decomp/ --ignore-missing-imports
pytest tests/test_artifacts.py tests/test_decompiler_helpers.py \
       tests/test_filters.py tests/test_parallel.py
pytest tests/test_multiarch_e2e.py::test_checked_in_fixture_hashes_and_provenance
```

CI installs the project and pytest before running these fast unit/CLI tests and the
checked-in fixture checksum/provenance validation. It does not start embedded Ghidra.

## Full end-to-end suite

The complete suite starts embedded Ghidra and decompiles the original repository
fixture, the host's `true` executable, and six stored ELF fixtures covering x86-32,
ARMv7, AArch64, MIPS32LE, PowerPC32BE, and RISC-V64:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra pytest tests/
```

The system-binary integration test verifies manifest and artifact hashes, sidecars,
addressed assembly bytes, call-site-aware xrefs, storage metadata, stack frames, and
combined output. It skips when the host does not provide `true` or a Ghidra install.

See `tests/fixtures/README.md` for the pinned LLVM 21 regeneration and reproducibility
procedure for the multi-architecture binaries.
