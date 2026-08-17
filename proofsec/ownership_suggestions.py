"""Suggest ownership fields by correlating API responses with identity attributes."""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from proofsec.models import ProofSecIdentity


@dataclass(frozen=True)
class OwnershipFieldSuggestion:
    resource: str
    field: str
    identity_attribute: str
    matched_identity: str
    confidence: float
    reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def normalize(value: object) -> str:
    return str(value).strip().strip('"').strip("'")


def scalar_paths(value: Any, prefix: str = "") -> list[tuple[str, str]]:
    if isinstance(value, dict):
        paths: list[tuple[str, str]] = []
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            paths.extend(scalar_paths(item, path))
        return paths
    if isinstance(value, list):
        return []
    if value is None:
        return []
    return [(prefix, normalize(value))]


OWNERSHIP_FIELD_TOKENS = (
    "owner",
    "advisor",
    "user",
    "account",
    "customer",
    "manager",
    "assigned",
    "assignee",
    "responsible",
    "agent",
    "createdby",
    "created_by",
)


def field_has_ownership_semantics(field: str) -> bool:
    lowered = field.lower()
    return any(token in lowered for token in OWNERSHIP_FIELD_TOKENS)


def matching_identity_attributes(
    value: str,
    identities: dict[str, ProofSecIdentity],
) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for identity in identities.values():
        for attribute_name, attribute_value in identity.attributes.items():
            if attribute_name in {"role"}:
                continue
            if value == normalize(attribute_value):
                matches.append((identity.name, attribute_name))
    return matches


def suggest_owner_fields_for_item(
    resource_name: str,
    item: Any,
    observed_identity: ProofSecIdentity,
    identities: dict[str, ProofSecIdentity],
) -> list[OwnershipFieldSuggestion]:
    if not isinstance(item, dict):
        return []
    suggestions: list[OwnershipFieldSuggestion] = []
    for field, value in scalar_paths(item):
        if not field or not value:
            continue
        if not field_has_ownership_semantics(field):
            continue
        for identity_name, attribute_name in matching_identity_attributes(value, identities):
            confidence = 0.94 if identity_name == observed_identity.name else 0.82
            suggestions.append(
                OwnershipFieldSuggestion(
                    resource=resource_name,
                    field=field,
                    identity_attribute=attribute_name,
                    matched_identity=identity_name,
                    confidence=confidence,
                    reason=(
                        f"Response field {field} matched identity "
                        f"{identity_name}.{attribute_name} during discovery."
                    ),
                )
            )
    deduped: dict[tuple[str, str, str, str], OwnershipFieldSuggestion] = {}
    for suggestion in suggestions:
        key = (
            suggestion.resource,
            suggestion.field,
            suggestion.identity_attribute,
            suggestion.matched_identity,
        )
        existing = deduped.get(key)
        if existing is None or suggestion.confidence > existing.confidence:
            deduped[key] = suggestion
    return sorted(deduped.values(), key=lambda item: (-item.confidence, item.field, item.matched_identity))


def suggest_owner_fields_from_observations(
    resource_name: str,
    observations: list[tuple[Any, ProofSecIdentity]],
    identities: dict[str, ProofSecIdentity],
) -> list[OwnershipFieldSuggestion]:
    field_stats: dict[tuple[str, str], dict[str, object]] = {}
    for item, observed_identity in observations:
        if not isinstance(item, dict):
            continue
        seen_fields: set[tuple[str, str]] = set()
        for field, value in scalar_paths(item):
            if not field or not value:
                continue
            matches = matching_identity_attributes(value, identities)
            for matched_identity, attribute_name in matches:
                key = (field, attribute_name)
                stats = field_stats.setdefault(
                    key,
                    {
                        "observations": 0,
                        "owner_matches": 0,
                        "ambiguous_matches": 0,
                        "matched_identities": set(),
                    },
                )
                if key not in seen_fields:
                    stats["observations"] = int(stats["observations"]) + 1
                    seen_fields.add(key)
                matched_identities = stats["matched_identities"]
                if isinstance(matched_identities, set):
                    matched_identities.add(matched_identity)
                if matched_identity == observed_identity.name:
                    stats["owner_matches"] = int(stats["owner_matches"]) + 1
                else:
                    stats["ambiguous_matches"] = int(stats["ambiguous_matches"]) + 1
    suggestions: list[OwnershipFieldSuggestion] = []
    for (field, attribute_name), stats in field_stats.items():
        observations = int(stats["observations"])
        owner_matches = int(stats["owner_matches"])
        ambiguous_matches = int(stats["ambiguous_matches"])
        if observations == 0 or owner_matches == 0:
            continue
        matched_identities = stats["matched_identities"]
        distinct_matches = len(matched_identities) if isinstance(matched_identities, set) else 0
        ratio = owner_matches / observations
        semantic_boost = 0.08 if field_has_ownership_semantics(field) else 0.0
        multi_identity_boost = 0.08 if distinct_matches >= 2 else 0.0
        ambiguity_penalty = min(0.25, ambiguous_matches * 0.08)
        confidence = max(0.0, min(0.98, 0.48 + (0.34 * ratio) + semantic_boost + multi_identity_boost - ambiguity_penalty))
        if confidence < 0.75:
            continue
        matched_label = ",".join(sorted(matched_identities)) if isinstance(matched_identities, set) else "unknown"
        suggestions.append(
            OwnershipFieldSuggestion(
                resource=resource_name,
                field=field,
                identity_attribute=attribute_name,
                matched_identity=matched_label,
                confidence=round(confidence, 2),
                reason=(
                    f"Field {field} matched {owner_matches}/{observations} observed identity "
                    f"attribute values for {attribute_name}; ambiguous matches: {ambiguous_matches}."
                ),
            )
        )
    return sorted(suggestions, key=lambda item: (-item.confidence, item.field, item.identity_attribute))
