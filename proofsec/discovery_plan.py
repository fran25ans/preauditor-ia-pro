"""Suggest runtime discovery configuration from a ProofSec security model."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from proofsec.contract import load_security_model
from proofsec.models import EndpointNode, ProjectSecurityModel


@dataclass(frozen=True)
class DiscoveryConfigSuggestion:
    resource: str
    list_endpoint: str
    items_path: str
    id_field: str
    owner_fields: tuple[str, ...]
    owner_marker_fields: tuple[str, ...]
    confidence: float
    reason: str
    related_detail_endpoints: tuple[str, ...] = ()

    def to_runtime_entry(self) -> dict[str, object]:
        return {
            "list_endpoint": self.list_endpoint,
            "items_path": self.items_path,
            "id_field": self.id_field,
            "owner_fields": list(self.owner_fields),
            "owner_marker_fields": list(self.owner_marker_fields),
        }

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["owner_fields"] = list(self.owner_fields)
        payload["owner_marker_fields"] = list(self.owner_marker_fields)
        payload["related_detail_endpoints"] = list(self.related_detail_endpoints)
        return payload


def normalized_collection_path(path: str) -> str:
    return "/" + path.strip("/").rstrip("/")


def is_collection_get(endpoint: EndpointNode) -> bool:
    if endpoint.method != "GET" or endpoint.parameters:
        return False
    if endpoint.resource in {"", "unknown"}:
        return False
    tail = endpoint.path.rstrip("/").rsplit("/", 1)[-1]
    return "{" not in endpoint.path and tail.lower() == endpoint.resource.lower()


def detail_endpoints_for(model: ProjectSecurityModel, resource: str) -> tuple[str, ...]:
    endpoints = [
        f"{endpoint.method} {endpoint.path}"
        for endpoint in model.endpoints
        if endpoint.resource == resource and endpoint.method == "GET" and endpoint.parameters
    ]
    return tuple(sorted(endpoints))


def suggest_discovery_config(model: ProjectSecurityModel) -> dict[str, object]:
    suggestions: dict[str, DiscoveryConfigSuggestion] = {}
    for endpoint in model.endpoints:
        if not is_collection_get(endpoint):
            continue
        detail_endpoints = detail_endpoints_for(model, endpoint.resource)
        confidence = 0.82 + (0.08 if detail_endpoints else 0.0)
        if endpoint.roles:
            confidence += 0.04
        suggestions[endpoint.resource] = DiscoveryConfigSuggestion(
            resource=endpoint.resource,
            list_endpoint=normalized_collection_path(endpoint.path),
            items_path="data",
            id_field="id",
            owner_fields=(),
            owner_marker_fields=("owner", "owner.id", "advisor.id", "advisorId", "managerId", "assignedTo", "createdBy"),
            confidence=round(min(confidence, 0.96), 2),
            reason=(
                f"{endpoint.method} {endpoint.path} looks like a collection endpoint for {endpoint.resource}; "
                "confirm response shape and ownership fields before dynamic testing."
            ),
            related_detail_endpoints=detail_endpoints,
        )
    return {
        "schema_version": "1.0",
        "project_path": model.project_path,
        "discovery": {resource: item.to_runtime_entry() for resource, item in sorted(suggestions.items())},
        "suggestions": [item.to_dict() for _, item in sorted(suggestions.items())],
        "notes": [
            "Generated from the static security model. A human should confirm list_endpoint, items_path, id_field and ownership fields before using it against a real target.",
            "If owner_fields is empty, ProofSec can still propose fields dynamically by correlating responses with identity.attributes.",
        ],
    }


def write_discovery_config_suggestions(model_path: Path, output: Path) -> dict[str, object]:
    payload = suggest_discovery_config(load_security_model(model_path))
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload

