# Contributing

## Prerequisites

- Python 3.10+
- [Ghidra](https://ghidra-sre.org/) 11.0+ (tested with 12.0.3)
- Set the `GHIDRA_INSTALL_DIR` environment variable to your Ghidra installation

## Dev setup

```bash
git clone https://github.com/totekuh/ghidra-decomp.git
cd ghidra-decomp
pip install -e .
```

## Running tests

```bash
pytest tests/
```

Tests run the full decompilation pipeline against a test binary, so they require Ghidra and take ~60s due to JVM startup.

## Code style

We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

We also use [mypy](https://mypy-lang.org/) for type checking:

```bash
mypy src/ghidra_decomp/ --ignore-missing-imports
```

## Submitting changes

1. Fork the repo
2. Create a feature branch (`git checkout -b my-feature`)
3. Make your changes
4. Run tests and linting
5. Open a PR against `main`
