"""Reduce structured gotos by inverting same-block forward if-goto patterns.

Handles only the provably safe case where an `if (cond) goto L;` and its target
label `L:` are siblings in the same block, the goto is the sole consequence with
no else, and the label appears later in that block. The statements between them
are the code the goto skips, so the pattern is equivalent to guarding those
statements with the negated condition:

    if (cond) goto L;
    <S>
    L:
    <tail>

becomes

    if (!cond) {
      <S>
    }
    L:
    <tail>

The label is kept (other gotos may target it; it is now reached by fallthrough).
C labels are function-scoped, so moving statements into the new block never
changes label visibility. Nothing is duplicated and no condition is mangled.
"""

from __future__ import annotations

from ._parser import apply_edits, node_text, parse
from .loop_normalize import _negate_condition


def _goto_target(goto_node) -> str | None:
    for child in goto_node.children:
        if child.type == "statement_identifier":
            return node_text(child)
    return None


def _sole_goto_consequence(if_node):
    """Return the goto_statement if the if's consequence is exactly one goto."""
    if if_node.child_by_field_name("alternative") is not None:
        return None
    cons = if_node.child_by_field_name("consequence")
    if cons is None:
        return None
    if cons.type == "goto_statement":
        return cons
    if cons.type == "compound_statement":
        inner = [c for c in cons.named_children if c.type != "comment"]
        if len(inner) == 1 and inner[0].type == "goto_statement":
            return inner[0]
    return None


def _line_start(source: str, byte: int) -> int:
    start = byte
    while start > 0 and source[start - 1] in (" ", "\t"):
        start -= 1
    return start


def _indent(source: str, byte: int) -> str:
    return source[_line_start(source, byte) : byte]


def _reindent(text: str, pad: str = "  ") -> str:
    lines = text.split("\n")
    return "\n".join(pad + ln if ln.strip() else ln for ln in lines)


def _collect_block_edits(block, source: str, edits: list) -> None:
    kids = [c for c in block.named_children if c.type != "comment"]

    label_index: dict[str, int] = {}
    for i, c in enumerate(kids):
        if c.type == "labeled_statement":
            lbl = c.child(0)
            if lbl is not None:
                label_index[node_text(lbl)] = i

    for i, node in enumerate(kids):
        if node.type != "if_statement":
            continue
        goto_node = _sole_goto_consequence(node)
        if goto_node is None:
            continue
        target = _goto_target(goto_node)
        if target is None or target not in label_index:
            continue
        j = label_index[target]
        if j <= i:
            continue  # backward or self; only forward handled

        label_node = kids[j]

        cond_node = node.child_by_field_name("condition")
        if cond_node is None:
            continue
        inner = (
            cond_node.named_children[0]
            if cond_node.named_child_count > 0
            else cond_node
        )
        negated = _negate_condition(node_text(inner), inner)

        if_line_start = _line_start(source, node.start_byte)
        label_line_start = _line_start(source, label_node.start_byte)
        indent = source[if_line_start : node.start_byte]

        intervening = source[node.end_byte : label_line_start]

        if not intervening.strip():
            # Goto jumps straight to the next statement: a no-op. Drop it.
            replacement = ""
        else:
            body = _reindent(intervening)
            replacement = f"{indent}if ({negated}) {{{body}{indent}}}\n"

        edits.append((if_line_start, label_line_start, replacement))


def _drop_overlaps(edits: list) -> list:
    """Keep only non-overlapping edits (greedy, outermost-first by position)."""
    edits = sorted(edits, key=lambda e: e[0])
    kept = []
    last_end = -1
    for start, end, repl in edits:
        if start < last_end:
            continue
        kept.append((start, end, repl))
        last_end = end
    return kept


def reduce_gotos(c_code: str) -> str:
    tree = parse(c_code)
    root = tree.root_node

    edits: list = []

    def walk(node):
        if node.type == "compound_statement":
            _collect_block_edits(node, c_code, edits)
        for child in node.children:
            walk(child)

    walk(root)

    if not edits:
        return c_code

    edits = _drop_overlaps(edits)
    if not edits:
        return c_code

    return apply_edits(c_code, edits)
