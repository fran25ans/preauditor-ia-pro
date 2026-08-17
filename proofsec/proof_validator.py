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


def parse_json_body(body: str) -> Any | None:
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def response_contains_resource_id(body: str, resource_id: str) -> bool:
    if not resource_id:
        return False
    parsed = parse_json_body(body)
    if parsed is not None:
        return any(normalize(value) == normalize(resource_id) for value in walk_json_values(parsed))
    return f'"{resource_id}"' in body or f":{resource_id}" in body or f": {resource_id}" in body


def response_contains_owner_marker(body: str, resource: ProofSecResourceExample) -> bool:
    markers = [resource.owner_identity, *resource.sensitive_markers]
    return any(marker and marker in body for marker in markers)


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
    body = evidence.response_body_preview.strip()
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
    resource_id_confirmed = response_contains_resource_id(body, resource.resource_id)
    owner_confirmed = response_contains_owner_marker(body, resource)
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
