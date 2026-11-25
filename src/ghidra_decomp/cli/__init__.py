"""CLI entry points for ghidra-decomp."""

from .main_cmd import main
from .query_cmd import query

__all__ = ["main", "query"]
