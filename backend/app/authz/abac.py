"""
ABAC — attribute-based access control with a small JSON policy language.

A policy `condition` is a rule tree evaluated against a context:
    {"subject": {...}, "resource": {...}, "action": "read", "env": {...}}

Leaf rule:  {"op": "eq", "attr": "resource.classification", "value": "public"}
Value may reference the context: {"ref": "subject.user_id"}.
Composite:  {"op": "and"|"or", "rules": [...]}, {"op": "not", "rule": {...}}

Ops: eq, ne, lt, lte, gt, gte, in, contains.
"""
from typing import Any


def _resolve_path(ctx: dict, path: str) -> Any:
    cur: Any = ctx
    for part in path.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            return None
    return cur


def _resolve_value(ctx: dict, value: Any) -> Any:
    if isinstance(value, dict) and "ref" in value:
        return _resolve_path(ctx, value["ref"])
    return value


def evaluate(condition: dict, ctx: dict) -> bool:
    if not condition:
        return True  # empty condition = always matches

    op = condition.get("op")

    if op == "and":
        return all(evaluate(r, ctx) for r in condition.get("rules", []))
    if op == "or":
        return any(evaluate(r, ctx) for r in condition.get("rules", []))
    if op == "not":
        return not evaluate(condition.get("rule", {}), ctx)

    left = _resolve_path(ctx, condition.get("attr", ""))
    right = _resolve_value(ctx, condition.get("value"))

    try:
        if op == "eq":
            return left == right
        if op == "ne":
            return left != right
        if op == "lt":
            return left < right
        if op == "lte":
            return left <= right
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "in":
            return left in right
        if op == "contains":
            return right in (left or [])
    except TypeError:
        return False
    return False
