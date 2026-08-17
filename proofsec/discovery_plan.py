"""Suggest runtime discovery configuration from a ProofSec security model."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from proofsec.contract import load_security_model
from proofsec.discovery.openapi import model_from_openapi
from proofsec.http.client import run_http_request
from proofsec.models import EndpointNode, ProjectSecurityModel
from proofsec.ownership_suggestions import suggest_owner_fields_from_observations
from proofsec.response_shape import infer_response_shape
from proofsec.resource_discovery import endpoint_for_identity
from proofsec.runtime_config import assert_target_authorized, auth_headers, load_identities, load_runtime_config, load_target


@dataclass(frozen=True)
class DiscoveryConfigSuggestion:
    resource: str
    list_endpoint: str
    items_path: str
    id_field: str | None
    owner_fields: tuple[str, ...]
    owner_marker_fields: tuple[str, ...]
    confidence: float
    reason: str
    related_detail_endpoints: tuple[str, ...] = ()
    shape_reason: str = ""
    id_candidates: tuple[dict[str, object], ...] = ()
    owner_field_suggestions: tuple[dict[str, object], ...] = ()
    detail_endpoint: str = ""

    def to_runtime_entry(self) -> dict[str, object]:
        return {
            "list_endpoint": self.list_endpoint,
            "detail_endpoint": self.detail_endpoint,
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
        payload["id_candidates"] = list(self.id_candidates)
        payload["owner_field_suggestions"] = list(self.owner_field_suggestions)
        return payload


def normalized_collection_path(path: str) -> str:
    return "/" + path.strip("/").rstrip("/")


def is_collection_get(endpoint: EndpointNode) -> bool:
    if endpoint.method != "GET":
        return False
    if endpoint.resource in {"", "unknown"}:
        return False
    tail = endpoint.path.rstrip("/").rsplit("/", 1)[-1]
    if tail.startswith("{"):
        return False
    return tail.lower() == endpoint.resource.lower() or tail.lower() in {
        "assigned",
        "mine",
        "search",
        "filter",
        "filtrar",
        "listar",
        "obtener",
    }


def detail_endpoints_for(model: ProjectSecurityModel, resource: str) -> tuple[str, ...]:
    endpoints = [
        f"{endpoint.method} {endpoint.path}"
        for endpoint in model.endpoints
        if endpoint.resource == resource and endpoint.method == "GET" and endpoint.parameters and not is_collection_get(endpoint)
    ]
    return tuple(sorted(endpoints))


def detail_path_for(model: ProjectSecurityModel, resource: str, collection_path: str = "") -> str:
    endpoints = [
        endpoint.path
        for endpoint in model.endpoints
        if endpoint.resource == resource and endpoint.method == "GET" and endpoint.parameters and not is_collection_get(endpoint)
    ]
    if not endpoints:
        return ""
    if collection_path:
        prefix = normalized_collection_path(collection_path).rstrip("/") + "/{"
        prefixed = [path for path in endpoints if normalized_collection_path(path).startswith(prefix)]
        if prefixed:
            return sorted(prefixed, key=lambda item: (item.count("{"), item))[0]
    return sorted(endpoints, key=lambda item: (item.count("{"), item))[0]


def detail_parameters_for(model: ProjectSecurityModel, resource: str, collection_path: str = "") -> tuple[str, ...]:
    detail_path = detail_path_for(model, resource, collection_path)
    for endpoint in model.endpoints:
        if endpoint.path == detail_path and endpoint.resource == resource:
            return endpoint.parameters
    return ()


def path_parameters(path: str) -> tuple[str, ...]:
    import re

    return tuple(sorted(re.findall(r"\{([^}]+)\}", path)))


def suggest_discovery_config(model: ProjectSecurityModel) -> dict[str, object]:
    suggestions: dict[str, DiscoveryConfigSuggestion] = {}
    for endpoint in model.endpoints:
        if not is_collection_get(endpoint):
            continue
        detail_endpoints = detail_endpoints_for(model, endpoint.resource)
        if not detail_endpoints:
            continue
        confidence = 0.82 + (0.08 if detail_endpoints else 0.0)
        if endpoint.roles:
            confidence += 0.04
        suggestions[endpoint.resource] = DiscoveryConfigSuggestion(
            resource=endpoint.resource,
            list_endpoint=normalized_collection_path(endpoint.path),
            detail_endpoint=detail_path_for(model, endpoint.resource, endpoint.path),
            items_path="data",
            id_field="auto",
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


def enhance_discovery_with_response_shapes(payload: dict[str, object], runtime_config: dict) -> dict[str, object]:
    target = load_target(runtime_config)
    assert_target_authorized(target)
    identities = load_identities(runtime_config)
    discovery = payload.get("discovery")
    if isinstance(discovery, dict) and not discovery:
        openapi_evidence = run_http_request(target, "GET", target.base_url.rstrip("/") + "/openapi.json", {})
        if openapi_evidence.status and 200 <= openapi_evidence.status < 300:
            try:
                spec = json.loads(openapi_evidence.response_body or openapi_evidence.response_body_preview)
            except json.JSONDecodeError:
                spec = None
            if isinstance(spec, dict):
                runtime_model = model_from_openapi(spec, project_path=str(payload.get("project_path") or "runtime-openapi"))
                payload = suggest_discovery_config(runtime_model)
                discovery = payload.get("discovery")
    if not isinstance(discovery, dict):
        return payload
    suggestions_by_resource = {
        str(item.get("resource")): item
        for item in payload.get("suggestions", [])
        if isinstance(item, dict) and item.get("resource")
    }
    for resource, entry in discovery.items():
        if not isinstance(entry, dict):
            continue
        list_endpoint = str(entry.get("list_endpoint") or "")
        if not list_endpoint.startswith("/"):
            continue
        observations = []
        parsed_samples = []
        for identity in identities.values():
            resolved_endpoint = endpoint_for_identity(list_endpoint, identity)
            if not resolved_endpoint:
                continue
            evidence = run_http_request(target, "GET", target.base_url.rstrip("/") + resolved_endpoint, auth_headers(identity))
            if evidence.status is None or evidence.status < 200 or evidence.status >= 300:
                continue
            try:
                parsed = json.loads(evidence.response_body or evidence.response_body_preview)
            except json.JSONDecodeError:
                continue
            shape = infer_response_shape(
                str(resource),
                parsed,
                has_detail_endpoint=True,
                detail_parameters=path_parameters(str(entry.get("detail_endpoint") or "")),
            )
            parsed_samples.append(shape)
            from proofsec.resource_discovery import collection_from_response

            for item in collection_from_response(parsed, shape.items_path):
                if isinstance(item, dict):
                    observations.append((item, identity))
        if not parsed_samples:
            continue
        shape = sorted(parsed_samples, key=lambda item: -item.confidence)[0]
        owner_suggestions = suggest_owner_fields_from_observations(str(resource), observations, identities)
        owner_fields = tuple(item.field for item in owner_suggestions if item.confidence >= 0.85)
        marker_fields = tuple(dict.fromkeys([*owner_fields, *entry.get("owner_marker_fields", [])]))
        entry["items_path"] = shape.items_path
        entry["id_field"] = shape.id_field
        entry["owner_fields"] = list(owner_fields)
        entry["owner_marker_fields"] = list(marker_fields)
        suggestion = suggestions_by_resource.get(str(resource))
        if suggestion is not None:
            suggestion["items_path"] = shape.items_path
            suggestion["id_field"] = shape.id_field
            suggestion["owner_fields"] = list(owner_fields)
            suggestion["owner_marker_fields"] = list(marker_fields)
            suggestion["shape_reason"] = shape.reason
            suggestion["id_candidates"] = [candidate.to_dict() for candidate in shape.id_candidates]
            suggestion["owner_field_suggestions"] = [item.to_dict() for item in owner_suggestions]
            suggestion["confidence"] = round(min(0.98, max(float(suggestion.get("confidence", 0.0)), shape.confidence)), 2)
    notes = payload.setdefault("notes", [])
    if isinstance(notes, list):
        notes.append("Runtime config was used for safe GET response shape discovery against the authorized target.")
    return payload


def write_discovery_config_suggestions(model_path: Path, output: Path) -> dict[str, object]:
    payload = suggest_discovery_config(load_security_model(model_path))
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload


def write_discovery_config_suggestions_with_runtime(model_path: Path, runtime_config_path: Path, output: Path) -> dict[str, object]:
    payload = suggest_discovery_config(load_security_model(model_path))
    payload = enhance_discovery_with_response_shapes(payload, load_runtime_config(runtime_config_path))
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return payload
