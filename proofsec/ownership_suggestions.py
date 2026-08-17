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
        lowered_field = field.lower()
        if not any(token in lowered_field for token in ("owner", "advisor", "user", "account", "customer")):
            continue
        for identity in identities.values():
            for attribute_name, attribute_value in identity.attributes.items():
                if value == normalize(attribute_value):
                    confidence = 0.94 if identity.name == observed_identity.name else 0.82
                    suggestions.append(
                        OwnershipFieldSuggestion(
                            resource=resource_name,
                            field=field,
                            identity_attribute=attribute_name,
                            matched_identity=identity.name,
                            confidence=confidence,
                            reason=(
                                f"Response field {field} matched identity "
                                f"{identity.name}.{attribute_name} during discovery."
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

