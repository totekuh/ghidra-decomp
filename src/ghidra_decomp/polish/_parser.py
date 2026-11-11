"""Shared tree-sitter parsing utilities for the polish pipeline."""

from __future__ import annotations

import tree_sitter as ts
import tree_sitter_c as tsc

_language: ts.Language | None = None
_parser: ts.Parser | None = None


def _get_language() -> ts.Language:
    global _language
    if _language is None:
        _language = ts.Language(tsc.language())
    return _language


def get_parser() -> ts.Parser:
    global _parser
    if _parser is None:
        _parser = ts.Parser(_get_language())
    return _parser


def parse(source: str) -> ts.Tree:
    return get_parser().parse(source.encode())


def query(pattern: str) -> ts.Query:
    return ts.Query(_get_language(), pattern)


def run_query(
    pattern: str, node: ts.Node
) -> list[tuple[int, dict[str, list[ts.Node]]]]:
    q = query(pattern)
    cursor = ts.QueryCursor(q)
    return list(cursor.matches(node))


def has_error(node: ts.Node) -> bool:
    return node.has_error


def is_parseable(source: str) -> bool:
    tree = parse(source)
    return not tree.root_node.has_error


def apply_edits(source: str, edits: list[tuple[int, int, str]]) -> str:
    sorted_edits = sorted(edits, key=lambda e: e[0], reverse=True)
    for start, end, replacement in sorted_edits:
        source = source[:start] + replacement + source[end:]
    return source


def node_text(node: ts.Node) -> str:
    return node.text.decode() if node.text else ""
