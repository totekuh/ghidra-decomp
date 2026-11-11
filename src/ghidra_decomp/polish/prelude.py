"""Typedef prelude that makes Ghidra's nonstandard types parseable by tree-sitter."""

from __future__ import annotations

_SENTINEL_BEGIN = "/* __GHIDRA_PRELUDE_BEGIN__ */"
_SENTINEL_END = "/* __GHIDRA_PRELUDE_END__ */"

_TYPEDEFS = """\
typedef unsigned char byte;
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined3;
typedef unsigned int undefined4;
typedef unsigned long undefined5;
typedef unsigned long undefined6;
typedef unsigned long long undefined7;
typedef unsigned long long undefined8;
typedef unsigned int uint;
typedef unsigned short ushort;
typedef unsigned long ulong;
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef int bool;
typedef int BOOL;
typedef void code;
typedef unsigned char uchar;
typedef unsigned int dword;
typedef unsigned short word;
typedef unsigned long long qword;
"""

GHIDRA_PRELUDE = f"{_SENTINEL_BEGIN}\n{_TYPEDEFS}{_SENTINEL_END}\n"


def inject_prelude(c_code: str) -> str:
    return GHIDRA_PRELUDE + c_code


def strip_prelude(c_code: str) -> str:
    begin = c_code.find(_SENTINEL_BEGIN)
    if begin == -1:
        return c_code
    end = c_code.find(_SENTINEL_END)
    if end == -1:
        return c_code
    end += len(_SENTINEL_END)
    if end < len(c_code) and c_code[end] == "\n":
        end += 1
    return c_code[:begin] + c_code[end:]
