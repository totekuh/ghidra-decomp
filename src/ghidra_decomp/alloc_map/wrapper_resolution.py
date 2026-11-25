"""Pure-dict wrapper resolution and detection (no live Ghidra objects)."""

from __future__ import annotations

from typing import Any


def resolve_wrappers(
    entries: list[dict[str, Any]],
    wrapper_db: dict[str, dict[str, Any]],
    allocators: dict[str, dict[str, Any] | None],
) -> list[dict[str, Any]]:
    """Post-pass: resolve heuristic-matched entries through detected wrappers.

    Modifies entries in place and returns them.  Strips transient ``_call_args``.
    """
    for entry in entries:
        call_args = entry.pop("_call_args", None)
        if entry.get("unwrapped_via") is not None:
            continue
        if entry["callee"] is None:
            continue
        if entry["callee"] in allocators:
            continue
        if call_args is None:
            continue

        chain: list[str] = []
        current_callee = entry["callee"]
        current_args = call_args
        resolved = False

        seen_callees: set[str] = set()
        while current_callee not in seen_callees:
            seen_callees.add(current_callee)
            info = wrapper_db.get(current_callee)
            if info is None:
                break
            chain.append(current_callee)
            wrapper_spec = info["size_spec"]
            inner_chain = info["chain"]

            size_info = _resolve_call_args(current_args, wrapper_spec)
            if size_info is not None and inner_chain:
                final_allocator = inner_chain[-1]
                if final_allocator in allocators:
                    entry["size"] = size_info["size"]
                    entry["size_expr"] = size_info["size_expr"]
                    entry["size_vn"] = size_info["size_vn"]
                    entry["unwrapped_via"] = " -> ".join(chain + inner_chain)
                    resolved = True
                    break
                next_callee = inner_chain[0]
                if next_callee in wrapper_db:
                    next_args = _build_forwarded_args(current_args, wrapper_spec)
                    if next_args is None:
                        break
                    current_callee = next_callee
                    current_args = next_args
                    continue
            break

        if not resolved:
            entry.setdefault("unwrapped_via", None)

    return entries


def _resolve_call_args(
    args: list[dict[str, Any]], spec: dict[str, Any]
) -> dict[str, Any] | None:
    """Resolve size from serialized call arguments and a size spec."""
    if "index" in spec:
        idx = spec["index"]
        if idx >= len(args):
            return None
        arg = args[idx]
        if "const" in arg:
            return {"size": arg["const"], "size_expr": "const", "size_vn": None}
        return {"size": None, "size_expr": "variable", "size_vn": arg.get("vn")}

    if "product" in spec:
        idx_a, idx_b = spec["product"]
        if idx_a >= len(args) or idx_b >= len(args):
            return None
        arg_a, arg_b = args[idx_a], args[idx_b]
        if "const" in arg_a and "const" in arg_b:
            return {
                "size": arg_a["const"] * arg_b["const"],
                "size_expr": "product",
                "size_vn": None,
            }
        return {"size": None, "size_expr": "variable", "size_vn": None}

    return None


def _build_forwarded_args(
    caller_args: list[dict[str, Any]], wrapper_spec: dict[str, Any]
) -> list[dict[str, Any]] | None:
    """Build the argument list for the next level of wrapper chain."""
    if "index" in wrapper_spec:
        idx = wrapper_spec["index"]
        if idx >= len(caller_args):
            return None
        return [caller_args[idx]]
    if "product" in wrapper_spec:
        idx_a, idx_b = wrapper_spec["product"]
        if idx_a >= len(caller_args) or idx_b >= len(caller_args):
            return None
        return [caller_args[idx_a], caller_args[idx_b]]
    return None


def detect_wrappers_from_candidates(
    candidates: dict[str, dict[str, Any]],
    allocators: dict[str, dict[str, Any] | None],
) -> dict[str, dict[str, Any]]:
    """Iteratively detect wrappers from candidate data until no new wrappers found.

    Returns wrapper_db mapping function name to wrapper info.
    """
    wrapper_db: dict[str, dict[str, Any]] = {}

    changed = True
    while changed:
        changed = False
        for func_name, cand in candidates.items():
            if func_name in wrapper_db:
                continue
            # A candidate may carry several allocator call sites (a
            # multi-path wrapper); every site must derive the same size
            # spec or the function is not treated as a wrapper.
            call_records = cand.get("calls") or [cand]

            wrapper_spec: dict[str, Any] | None = None
            first_spec: dict[str, Any] | None = None
            chain_prefix: list[str] = []

            for record in call_records:
                callee = record["callee"]
                spec: dict[str, Any] | None = None
                if callee in allocators:
                    spec = allocators[callee]
                    record_chain = [callee]
                elif callee in wrapper_db:
                    w = wrapper_db[callee]
                    spec = w["size_spec"]
                    record_chain = [callee] + w["chain"]
                else:
                    wrapper_spec = None
                    break

                if spec is None:
                    wrapper_spec = None
                    break

                record_spec = _derive_wrapper_spec(record, spec)
                if record_spec is None:
                    wrapper_spec = None
                    break
                if wrapper_spec is None:
                    wrapper_spec = record_spec
                    first_spec = spec
                    chain_prefix = record_chain
                elif not _specs_equivalent(wrapper_spec, record_spec):
                    wrapper_spec = None
                    break

            if wrapper_spec is None or first_spec is None:
                continue

            wrapper_db[func_name] = {
                "inner_allocator": cand["callee"],
                "inner_spec": first_spec,
                "size_spec": wrapper_spec,
                "chain": chain_prefix,
            }
            changed = True

    return wrapper_db


def _derive_wrapper_spec(
    cand: dict[str, Any], inner_spec: dict[str, Any]
) -> dict[str, Any] | None:
    """Derive the wrapper's size spec from its candidate data and inner spec."""
    param_mapping = cand["param_mapping"]
    const_args = cand["const_args"]

    if "index" in inner_spec:
        idx = inner_spec["index"]
        if idx in param_mapping:
            return {"index": param_mapping[idx]}
        if idx in const_args:
            return inner_spec
        return None

    if "product" in inner_spec:
        idx_a, idx_b = inner_spec["product"]
        a_param = param_mapping.get(idx_a)
        b_param = param_mapping.get(idx_b)
        a_const = const_args.get(idx_a)
        b_const = const_args.get(idx_b)

        if a_const == 1 and b_param is not None:
            return {"index": b_param}
        if b_const == 1 and a_param is not None:
            return {"index": a_param}
        if a_param is not None and b_param is not None:
            return {"product": [a_param, b_param]}
        if a_const is not None and b_const is not None:
            return inner_spec
        return None

    return None


def _specs_equivalent(a: dict[str, Any], b: dict[str, Any]) -> bool:
    """Whether two derived size specs describe the same sizing.

    Product specs compare order-insensitively: ``product(0, 1)`` and
    ``product(1, 0)`` both mean "the product of both params".
    """
    if a == b:
        return True
    if "product" in a and "product" in b:
        return sorted(a["product"]) == sorted(b["product"])
    return False
