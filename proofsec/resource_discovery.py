"""Configured resource discovery for ProofSec dynamic authorization tests."""

from __future__ import annotations

import json
from typing import Any

from proofsec.http.client import run_http_request
from proofsec.models import ProofSecIdentity, ProofSecResourceExample, ProofSecTarget
from proofsec.ownership_suggestions import (
    OwnershipFieldSuggestion,
    suggest_owner_fields_for_item,
    suggest_owner_fields_from_observations,
)
from proofsec.response_shape import infer_response_shape
from proofsec.runtime_config import auth_headers


def normalize(value: object) -> str:
    return str(value).strip().strip('"').strip("'")


def value_at_path(value: Any, dotted_path: str) -> Any:
    current = value
    for part in dotted_path.split("."):
        if part == "":
            continue
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def collection_from_response(parsed: Any, items_path: str) -> list[Any]:
    if items_path:
        parsed = value_at_path(parsed, items_path)
    if isinstance(parsed, list):
        return parsed
    if isinstance(parsed, dict):
        for key in ("items", "data", "results", "content"):
            value = parsed.get(key)
            if isinstance(value, list):
                return value
    return []


def marker_from_item(item: Any, marker_fields: tuple[str, ...], owner_identity: str) -> tuple[str, ...]:
    markers = [owner_identity]
    if isinstance(item, dict):
        for field in marker_fields:
            value = value_at_path(item, field)
            if value is not None:
                markers.append(normalize(value))
    return tuple(dict.fromkeys(marker for marker in markers if marker))


def owner_from_item(item: Any, owner_fields: tuple[str, ...], identities: dict[str, ProofSecIdentity]) -> tuple[str, str, float]:
    if not isinstance(item, dict):
        return "UNKNOWN", "not_resolved", 0.0
    identity_names = set(identities)
    for field in owner_fields:
        value = value_at_path(item, field)
        if value is None:
            continue
        value_text = normalize(value)
        if value_text in identity_names:
            return value_text, f"response_field:{field}", 1.0
        for identity in identities.values():
            for attribute_name, attribute_value in identity.attributes.items():
                if value_text and value_text == normalize(attribute_value):
                    return identity.name, f"response_field:{field}->identity_attribute:{attribute_name}", 1.0
    return "UNKNOWN", "not_resolved", 0.0


def discover_resources_with_suggestions(
    config: dict,
    target: ProofSecTarget,
    identities: dict[str, ProofSecIdentity],
) -> tuple[list[ProofSecResourceExample], list[OwnershipFieldSuggestion]]:
    discovered: list[ProofSecResourceExample] = []
    suggestions: list[OwnershipFieldSuggestion] = []
    for resource_name, raw in (config.get("discovery") or {}).items():
        list_endpoint = str(raw.get("list_endpoint") or "").strip()
        configured_id_field = str(raw.get("id_field") or "auto")
        configured_items_path = str(raw.get("items_path") or "")
        marker_fields = tuple(str(item) for item in raw.get("owner_marker_fields", ["owner", "owner.id", "advisor", "advisor.id", "advisorId"]))
        configured_owner_fields = tuple(str(item) for item in raw.get("owner_fields", []))
        if not list_endpoint.startswith("/"):
            continue
        observations: list[tuple[dict[str, Any], ProofSecIdentity]] = []
        for identity in identities.values():
            url = target.base_url.rstrip("/") + list_endpoint
            evidence = run_http_request(target, "GET", url, auth_headers(identity))
            if evidence.status is None or evidence.status < 200 or evidence.status >= 300:
                continue
            try:
                parsed = json.loads(evidence.response_body or evidence.response_body_preview)
            except json.JSONDecodeError:
                continue
            shape = infer_response_shape(resource_name, parsed, has_detail_endpoint=True)
            items_path = configured_items_path or shape.items_path
            id_field = configured_id_field if configured_id_field != "auto" else shape.id_field
            for item in collection_from_response(parsed, items_path):
                if not isinstance(item, dict):
                    continue
                resource_id = value_at_path(item, id_field)
                if resource_id is None:
                    continue
                item_suggestions = suggest_owner_fields_for_item(resource_name, item, identity, identities)
                suggestions.extend(item_suggestions)
                observations.append((item, identity))
        aggregate_suggestions = suggest_owner_fields_from_observations(resource_name, observations, identities)
        suggestions.extend(aggregate_suggestions)
        aggregate_fields = tuple(suggestion.field for suggestion in aggregate_suggestions if suggestion.confidence >= 0.85)
        for item, identity in observations:
            resource_id = value_at_path(item, id_field)
            if resource_id is None:
                continue
            resource_id_text = normalize(resource_id)
            owner_fields = configured_owner_fields or tuple(dict.fromkeys([*aggregate_fields, *marker_fields]))
            owner_identity, ownership_source, ownership_confidence = owner_from_item(item, owner_fields, identities)
            discovered.append(
                ProofSecResourceExample(
                    name=f"{resource_name.rstrip('s')}_{resource_id_text}",
                    resource=resource_name,
                    resource_id=resource_id_text,
                    owner_identity=owner_identity,
                    observed_by=(identity.name,),
                    ownership_source=ownership_source,
                    ownership_confidence=ownership_confidence,
                    sensitive_markers=marker_from_item(item, marker_fields, identity.name),
                )
            )
    merged: dict[tuple[str, str, str], ProofSecResourceExample] = {}
    for item in discovered:
        key = (item.resource, item.resource_id, item.owner_identity)
        existing = merged.get(key)
        if existing:
            observed = tuple(sorted(set(existing.observed_by) | set(item.observed_by)))
            markers = tuple(sorted(set(existing.sensitive_markers) | set(item.sensitive_markers)))
            merged[key] = ProofSecResourceExample(
                name=item.name,
                resource=item.resource,
                resource_id=item.resource_id,
                owner_identity=item.owner_identity,
                observed_by=observed,
                ownership_source=item.ownership_source,
                ownership_confidence=item.ownership_confidence,
                sensitive_markers=markers,
            )
        else:
            merged[key] = item
    deduped_suggestions: dict[tuple[str, str, str, str], OwnershipFieldSuggestion] = {}
    for suggestion in suggestions:
        key = (
            suggestion.resource,
            suggestion.field,
            suggestion.identity_attribute,
            suggestion.matched_identity,
        )
        existing = deduped_suggestions.get(key)
        if existing is None or suggestion.confidence > existing.confidence:
            deduped_suggestions[key] = suggestion
    return (
        sorted(merged.values(), key=lambda item: (item.resource, item.resource_id, item.owner_identity)),
        sorted(deduped_suggestions.values(), key=lambda item: (item.resource, -item.confidence, item.field)),
    )


def discover_resources(
    config: dict,
    target: ProofSecTarget,
    identities: dict[str, ProofSecIdentity],
) -> list[ProofSecResourceExample]:
    resources, _ = discover_resources_with_suggestions(config, target, identities)
    return resources
