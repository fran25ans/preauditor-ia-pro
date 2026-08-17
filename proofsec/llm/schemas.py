"""Small strict validators for ProofSec LLM JSON outputs."""

from __future__ import annotations


ALLOWED_ACTIONS = {"read", "create", "update", "delete", "unknown"}


def validate_invariant_suggestions(data: dict, allowed_resources: set[str], allowed_actions: set[str]) -> list[dict]:
    raw_items = data.get("invariants")
    if not isinstance(raw_items, list):
        raise ValueError("LLM response must contain an invariants list.")

    validated: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for raw in raw_items[:10]:
        if not isinstance(raw, dict):
            continue
        item = {
            "name": clean_string(raw.get("name")),
            "description": clean_string(raw.get("description")),
            "resource": clean_string(raw.get("resource")),
            "action": clean_string(raw.get("action")),
            "expected_behavior": clean_string(raw.get("expected_behavior")),
            "evidence": clean_string(raw.get("evidence")),
            "confidence": clean_confidence(raw.get("confidence")),
        }
        if not all(item[key] for key in ("name", "description", "resource", "action", "expected_behavior", "evidence")):
            continue
        if item["resource"] not in allowed_resources:
            continue
        if item["action"] not in allowed_actions or item["action"] not in ALLOWED_ACTIONS:
            continue
        key = (item["name"], item["resource"], item["action"])
        if key in seen:
            continue
        seen.add(key)
        validated.append(item)
    return validated


def clean_string(value: object, limit: int = 500) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().split())[:limit]


def clean_confidence(value: object) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(number, 1.0))
