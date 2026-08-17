"""Evidence quality validation for ProofSec dynamic proofs."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any

from proofsec.models import HttpExchangeEvidence, ProofSecResourceExample


SUCCESS_STATUSES = set(range(200, 300))
FORBIDDEN_STATUSES = {401, 403, 404}


@dataclass(frozen=True)
class BolaValidation:
    state: str
    exploitability: str
    confidence: float
    reason: str
    resource_returned: bool
    resource_id_confirmed: bool
    owner_confirmed: bool


@dataclass(frozen=True)
class AuthorizationValidation:
    state: str
    exploitability: str
    confidence: float
    reason: str


def normalize(value: object) -> str:
    return str(value).strip().strip('"').strip("'")


def walk_json_values(value: Any) -> list[Any]:
    if isinstance(value, dict):
        values: list[Any] = []
        for item in value.values():
            values.extend(walk_json_values(item))
        return values
    if isinstance(value, list):
        values = []
        for item in value:
            values.extend(walk_json_values(item))
        return values
    return [value]


def contains_error_semantics(value: Any) -> bool:
    if isinstance(value, dict):
        error_keys = {"error", "errors", "message", "detail", "reason"}
        if any(str(key).lower() in error_keys for key in value):
            return True
        return any(contains_error_semantics(item) for item in value.values())
    if isinstance(value, list):
        return any(contains_error_semantics(item) for item in value)
    if isinstance(value, str):
        lowered = value.lower()
        return any(token in lowered for token in ("cannot be accessed", "forbidden", "denied", "not allowed", "unauthorized"))
    return False


def contains_functional_marker(value: Any, marker: str) -> bool:
    marker_text = normalize(marker).lower()
    if not marker_text:
        return False
    if isinstance(value, dict):
        for key, item in value.items():
            if marker_text == normalize(key).lower():
                return True
            if contains_functional_marker(item, marker):
                return True
        return False
    if isinstance(value, list):
        return any(contains_functional_marker(item, marker) for item in value)
    return marker_text in normalize(value).lower()


def body_contains_functional_evidence(body: str, functional_markers: tuple[str, ...]) -> bool:
    if not body or not functional_markers:
        return False
    parsed = parse_json_body(body)
    if parsed is not None:
        return any(contains_functional_marker(parsed, marker) for marker in functional_markers)
    lowered = body.lower()
    return any(normalize(marker).lower() in lowered for marker in functional_markers if normalize(marker))


def parse_json_body(body: str) -> Any | None:
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def iter_json_objects(value: Any) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    if isinstance(value, dict):
        objects.append(value)
        for item in value.values():
            objects.extend(iter_json_objects(item))
    elif isinstance(value, list):
        for item in value:
            objects.extend(iter_json_objects(item))
    return objects


def object_contains_resource_id(value: dict[str, Any], resource_id: str) -> bool:
    candidate_keys = {"id", "customer_id", "customerId", "resource_id", "resourceId", "account_id", "accountId", "document_id", "documentId"}
    for key, item in value.items():
        if str(key) in candidate_keys and normalize(item) == normalize(resource_id):
            return True
    return False


def object_contains_owner_marker(value: dict[str, Any], resource: ProofSecResourceExample) -> bool:
    markers = {normalize(marker) for marker in (resource.owner_identity, *resource.sensitive_markers) if marker}
    if not markers:
        return False
    owner_keys = {
        "owner",
        "owner_id",
        "ownerId",
        "advisor",
        "advisor_id",
        "advisorId",
        "user",
        "user_id",
        "userId",
        "customer_owner",
        "customerOwner",
    }
    for key, item in value.items():
        if str(key) in owner_keys:
            if isinstance(item, dict):
                if any(normalize(nested) in markers for nested in walk_json_values(item)):
                    return True
            elif normalize(item) in markers:
                return True
    return False


def find_resource_object(parsed: Any, resource: ProofSecResourceExample) -> dict[str, Any] | None:
    if contains_error_semantics(parsed):
        return None
    for item in iter_json_objects(parsed):
        if object_contains_resource_id(item, resource.resource_id):
            return item
    return None


def response_contains_resource_id_structurally(body: str, resource_id: str) -> bool:
    if not resource_id:
        return False
    parsed = parse_json_body(body)
    if parsed is not None:
        if contains_error_semantics(parsed):
            return False
        return any(object_contains_resource_id(item, resource_id) for item in iter_json_objects(parsed))
    return f'"{resource_id}"' in body or f":{resource_id}" in body or f": {resource_id}" in body


def response_contains_owner_marker_structurally(body: str, resource: ProofSecResourceExample) -> bool:
    parsed = parse_json_body(body)
    if parsed is None:
        return False
    resource_object = find_resource_object(parsed, resource)
    return bool(resource_object and object_contains_owner_marker(resource_object, resource))


def validate_bola_response(evidence: HttpExchangeEvidence, resource: ProofSecResourceExample) -> BolaValidation:
    if evidence.status in FORBIDDEN_STATUSES:
        return BolaValidation(
            state="FIXED",
            exploitability="FIXED",
            confidence=0.95,
            reason="Cross-owner request was rejected with an authorization-style status.",
            resource_returned=False,
            resource_id_confirmed=False,
            owner_confirmed=False,
        )
    if evidence.status not in SUCCESS_STATUSES:
        return BolaValidation(
            state="INCONCLUSIVE",
            exploitability="UNKNOWN",
            confidence=0.35,
            reason="The dynamic request did not return a success status or an authorization denial.",
            resource_returned=False,
            resource_id_confirmed=False,
            owner_confirmed=False,
        )
    body = (evidence.response_body or evidence.response_body_preview).strip()
    if not body:
        return BolaValidation(
            state="INCONCLUSIVE",
            exploitability="UNKNOWN",
            confidence=0.4,
            reason="The response was successful but did not contain a body to validate.",
            resource_returned=False,
            resource_id_confirmed=False,
            owner_confirmed=False,
        )
    parsed = parse_json_body(body)
    if parsed is not None:
        resource_object = find_resource_object(parsed, resource)
        resource_id_confirmed = resource_object is not None
        owner_confirmed = bool(resource_object and object_contains_owner_marker(resource_object, resource))
    else:
        resource_id_confirmed = response_contains_resource_id_structurally(body, resource.resource_id)
        owner_confirmed = False
    if resource_id_confirmed and owner_confirmed:
        return BolaValidation(
            state="PROVEN",
            exploitability="PROVEN",
            confidence=1.0,
            reason="Response confirms the requested resource id and an ownership marker for the other identity.",
            resource_returned=True,
            resource_id_confirmed=True,
            owner_confirmed=True,
        )
    if resource_id_confirmed:
        return BolaValidation(
            state="VALIDATED",
            exploitability="VALIDATED",
            confidence=0.82,
            reason="Response confirms the requested resource id, but ownership was not independently confirmed.",
            resource_returned=True,
            resource_id_confirmed=True,
            owner_confirmed=False,
        )
    return BolaValidation(
        state="INCONCLUSIVE",
        exploitability="UNKNOWN",
        confidence=0.45,
        reason="The response was successful, but the requested resource id was not confirmed in the response.",
        resource_returned=bool(body),
        resource_id_confirmed=False,
        owner_confirmed=owner_confirmed,
    )


def validate_authorization_response(
    evidence: HttpExchangeEvidence,
    functional_markers: tuple[str, ...] = (),
) -> AuthorizationValidation:
    if evidence.status in FORBIDDEN_STATUSES:
        return AuthorizationValidation(
            state="FIXED",
            exploitability="FIXED",
            confidence=0.95,
            reason="Restricted function was rejected with an authorization-style status.",
        )
    if evidence.status not in SUCCESS_STATUSES:
        return AuthorizationValidation(
            state="INCONCLUSIVE",
            exploitability="UNKNOWN",
            confidence=0.35,
            reason="The request did not return a success status or an authorization denial.",
        )
    body = (evidence.response_body or evidence.response_body_preview).strip()
    parsed = parse_json_body(body)
    if parsed is not None and contains_error_semantics(parsed):
        return AuthorizationValidation(
            state="INCONCLUSIVE",
            exploitability="UNKNOWN",
            confidence=0.45,
            reason="The endpoint returned 2xx, but the response body has authorization-error semantics.",
        )
    if contains_error_semantics(body):
        return AuthorizationValidation(
            state="INCONCLUSIVE",
            exploitability="UNKNOWN",
            confidence=0.45,
            reason="The endpoint returned 2xx, but the response text has authorization-error semantics.",
        )
    if body_contains_functional_evidence(body, functional_markers):
        return AuthorizationValidation(
            state="PROVEN",
            exploitability="PROVEN",
            confidence=1.0,
            reason="Lower-privileged identity received a successful response with configured functional evidence.",
        )
    if functional_markers:
        return AuthorizationValidation(
            state="VALIDATED",
            exploitability="VALIDATED",
            confidence=0.72,
            reason="The endpoint returned 2xx without authorization-error semantics, but configured functional evidence was not found.",
        )
    return AuthorizationValidation(
        state="VALIDATED",
        exploitability="VALIDATED",
        confidence=0.68,
        reason="The endpoint returned 2xx without authorization-error semantics, but no functional evidence marker is configured.",
    )
