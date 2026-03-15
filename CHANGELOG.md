# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [0.1.0] - 2026-03-15

### Added

- One `.c` file per function with metadata header comments (name, address, size, calling convention, params)
- Combined `all_functions.c` for full-text search
- JSON indexes: types, functions, callgraph, strings, imports, exports, symbols, sections, metadata
- `--base-addr` option to rebase the binary before export
- `--timeout` option for per-function decompilation timeout (default 60s)
- Automatic retry with escalated timeout for failed functions
- Assembly listing fallback for permanently failed functions
- Ghidra project cache cleanup after each run for atomic, reproducible results
