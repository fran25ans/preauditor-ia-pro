"""Infer response collection shape and resource id fields from safe GET responses."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


COMMON_COLLECTION_KEYS = ("content", "data", "results", "items")
ID_FIELD_NAMES = ("id", "uuid")
NON_RESOURCE_COLLECTION_KEYS = ("links", "_links")


@dataclass(frozen=True)
class IdFieldCandidate:
    field: str
    confidence: float
    reason: str
    present_ratio: float
    unique_ratio: float

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ResponseShapeSuggestion:
    items_path: str
    id_field: str | None
    confidence: float
    reason: str
    id_candidates: tuple[IdFieldCandidate, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "items_path": self.items_path,
            "id_field": self.id_field,
            "confidence": self.confidence,
            "reason": self.reason,
            "id_candidates": [candidate.to_dict() for candidate in self.id_candidates],
        }


def normalize(value: object) -> str:
    return str(value).strip().strip('"').strip("'")


def singular(resource: str) -> str:
    lowered = resource.lower().strip()
    if lowered.endswith("ies"):
        return lowered[:-3] + "y"
    if lowered.endswith("s"):
        return lowered[:-1]
    return lowered


def scalar_fields(item: Any) -> dict[str, str]:
    if not isinstance(item, dict):
        return {}
    fields: dict[str, str] = {}
    for key, value in item.items():
        if isinstance(value, (dict, list)) or value is None:
            continue
        fields[str(key)] = normalize(value)
    return fields


def collection_candidates(value: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, list[Any]]]:
    if depth > 3:
        return []
    if isinstance(value, list):
        return [(prefix, value)]
    if not isinstance(value, dict):
        return []
    candidates: list[tuple[str, list[Any]]] = []
    for key, item in value.items():
        path = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(item, list):
            candidates.append((path, item))
        elif isinstance(item, dict):
            candidates.extend(collection_candidates(item, path, depth + 1))
    return candidates


def score_collection(path: str, items: list[Any]) -> float:
    if path.lower().rsplit(".", 1)[-1] in NON_RESOURCE_COLLECTION_KEYS:
        return 0.12
    dict_count = sum(1 for item in items if isinstance(item, dict))
    dict_ratio = dict_count / max(len(items), 1)
    key_bonus = 0.24 if path in COMMON_COLLECTION_KEYS else 0.0
    size_bonus = min(0.18, len(items) * 0.03)
    root_bonus = 0.1 if path == "" else 0.0
    return min(0.98, 0.45 + (0.28 * dict_ratio) + key_bonus + size_bonus + root_bonus)


def infer_items_collection(parsed: Any) -> tuple[str, list[Any], float, str]:
    candidates = collection_candidates(parsed)
    if not candidates:
        return "", [], 0.0, "No list-like collection was found in the response."
    ranked = sorted(candidates, key=lambda item: (-score_collection(item[0], item[1]), item[0]))
    path, items = ranked[0]
    confidence = round(score_collection(path, items), 2)
    label = "root array" if path == "" else path
    return path, items, confidence, f"Detected {label} as the most likely collection with {len(items)} item(s)."


def score_id_field(
    field: str,
    values: list[str],
    total_items: int,
    resource: str,
    has_detail_endpoint: bool,
) -> IdFieldCandidate:
    lowered = field.lower()
    resource_singular = singular(resource)
    present_ratio = len(values) / max(total_items, 1)
    unique_ratio = len(set(values)) / max(len(values), 1)
    score = 0.14
    reasons: list[str] = []
    if lowered in ID_FIELD_NAMES:
        score += 0.32
        reasons.append("field name is a canonical id")
    if lowered == f"{resource_singular}id" or lowered == f"{resource_singular}_id":
        score += 0.36
        reasons.append("field name matches the resource id")
    elif lowered == f"{resource_singular}ref" or lowered == f"{resource_singular}key" or lowered == f"{resource_singular}code":
        score += 0.34
        reasons.append("field name matches the resource reference")
    elif lowered.endswith("id") or lowered.endswith("_id"):
        score += 0.18
        reasons.append("field name ends with id")
    elif lowered.endswith("ref") or lowered.endswith("key") or lowered.endswith("code"):
        score += 0.2
        reasons.append("field name looks like a stable resource reference")
    if "owner" in lowered or "advisor" in lowered or "manager" in lowered or "assigned" in lowered or "createdby" in lowered:
        score -= 0.18
        reasons.append("field looks more like ownership than resource identity")
    if present_ratio >= 0.95:
        score += 0.16
        reasons.append("field is present in every sampled item")
    else:
        score += 0.08 * present_ratio
        reasons.append(f"field presence ratio is {present_ratio:.2f}")
    if unique_ratio >= 0.95:
        score += 0.16
        reasons.append("field is unique across sampled items")
    else:
        score += 0.08 * unique_ratio
        reasons.append(f"field uniqueness ratio is {unique_ratio:.2f}")
    if has_detail_endpoint:
        score += 0.08
        reasons.append("resource has a detail endpoint with a path parameter")
    score = round(max(0.0, min(0.99, score)), 2)
    return IdFieldCandidate(
        field=field,
        confidence=score,
        reason="; ".join(reasons) or "scalar field observed in collection items",
        present_ratio=round(present_ratio, 2),
        unique_ratio=round(unique_ratio, 2),
    )


def infer_id_field(
    resource: str,
    items: list[Any],
    has_detail_endpoint: bool = False,
) -> tuple[str | None, tuple[IdFieldCandidate, ...]]:
    values_by_field: dict[str, list[str]] = {}
    dict_items = [item for item in items if isinstance(item, dict)]
    for item in dict_items:
        for field, value in scalar_fields(item).items():
            values_by_field.setdefault(field, []).append(value)
    candidates = tuple(
        sorted(
            (
                score_id_field(field, values, len(dict_items), resource, has_detail_endpoint)
                for field, values in values_by_field.items()
            ),
            key=lambda item: (-item.confidence, item.field),
        )
    )
    if not candidates:
        return None, ()
    if candidates[0].confidence < 0.65:
        return None, candidates
    return candidates[0].field, candidates


def infer_response_shape(resource: str, parsed: Any, has_detail_endpoint: bool = False) -> ResponseShapeSuggestion:
    items_path, items, collection_confidence, collection_reason = infer_items_collection(parsed)
    id_field, candidates = infer_id_field(resource, items, has_detail_endpoint)
    id_confidence = candidates[0].confidence if candidates else 0.35
    if id_field is None:
        id_confidence = 0.0
    elif candidates and id_field != candidates[0].field:
        id_confidence = 0.35
    confidence = round(min(0.98, (collection_confidence * 0.45) + (id_confidence * 0.55)), 2)
    return ResponseShapeSuggestion(
        items_path=items_path,
        id_field=id_field,
        confidence=confidence,
        reason=f"{collection_reason} ID field candidate: {id_field or 'UNKNOWN'}.",
        id_candidates=candidates[:5],
    )
