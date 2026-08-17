"""Invariant state management and static readiness evaluation."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path

from proofsec.contract import load_security_model
from proofsec.models import ContractInvariant, ContractPermission, ContractRole, InvariantEvaluation, ProjectSecurityModel, SecurityContract


ALLOWED_INVARIANT_STATUSES = {"proposed", "confirmed", "rejected", "testing", "respected", "violated", "unknown"}
HUMAN_REVIEW_STATUSES = {"confirmed", "rejected"}
DYNAMIC_ONLY_STATUSES = {"testing", "respected", "violated"}


def load_security_contract(path: Path) -> SecurityContract:
    path = path.expanduser().resolve()
    if path.suffix.lower() in {".yml", ".yaml"}:
        raise ValueError("YAML contracts are currently human-readable output only. Use JSON for invariant state updates.")
    data = json.loads(path.read_text(encoding="utf-8"))
    roles = [
        ContractRole(
            name=role["name"],
            permissions=tuple(
                ContractPermission(
                    permission=permission["permission"],
                    source=permission.get("source", "detected"),
                    confidence=float(permission.get("confidence", 0.0)),
                    evidence=permission.get("evidence", ""),
                    status=permission.get("status", "proposed"),
                )
                for permission in role.get("permissions", [])
            ),
            source=role.get("source", "detected"),
            confidence=float(role.get("confidence", 1.0)),
            status=role.get("status", "proposed"),
        )
        for role in data.get("roles", [])
    ]
    invariants = [
        ContractInvariant(
            invariant_id=item["invariant_id"],
            name=item["name"],
            description=item["description"],
            resource=item["resource"],
            action=item["action"],
            expected_behavior=item["expected_behavior"],
            source=item.get("source", "inferred"),
            confidence=float(item.get("confidence", 0.0)),
            status=normalize_status(item.get("status", "proposed")),
            evidence=item.get("evidence", ""),
        )
        for item in data.get("invariants", [])
    ]
    return SecurityContract(
        project_path=data.get("project_path", ""),
        generated_at=data.get("generated_at", ""),
        source_model_generated_at=data.get("source_model_generated_at", ""),
        roles=roles,
        resources=list(data.get("resources", [])),
        invariants=invariants,
        notes=list(data.get("notes", [])),
    )


def normalize_status(status: object) -> str:
    value = str(status)
    return value if value in ALLOWED_INVARIANT_STATUSES else "unknown"


def update_invariant_status(contract: SecurityContract, invariant_id: str, status: str) -> SecurityContract:
    status = normalize_status(status)
    if status in DYNAMIC_ONLY_STATUSES:
        raise ValueError(f"Status {status} requires dynamic proof or retest evidence.")
    updated = False
    invariants: list[ContractInvariant] = []
    for invariant in contract.invariants:
        if invariant.invariant_id == invariant_id:
            invariants.append(
                replace(
                    invariant,
                    status=status,
                    source="user-confirmed" if status in HUMAN_REVIEW_STATUSES else invariant.source,
                )
            )
            updated = True
        else:
            invariants.append(invariant)
    if not updated:
        raise ValueError(f"Invariant not found: {invariant_id}")
    contract.invariants = invariants
    return contract


def confirm_all_proposed(contract: SecurityContract) -> SecurityContract:
    contract.invariants = [
        replace(invariant, status="confirmed", source="user-confirmed")
        if invariant.status == "proposed"
        else invariant
        for invariant in contract.invariants
    ]
    return contract


def evaluate_invariants(contract: SecurityContract, model: ProjectSecurityModel | None = None) -> list[InvariantEvaluation]:
    evaluations: list[InvariantEvaluation] = []
    for invariant in contract.invariants:
        matching = tuple(
            f"{endpoint.method} {endpoint.path}"
            for endpoint in (model.endpoints if model else [])
            if endpoint.resource == invariant.resource and endpoint.action == invariant.action
        )
        if invariant.status == "rejected":
            readiness = "not_testable"
            reason = "Invariant was rejected by a reviewer."
            requires_dynamic = False
        elif invariant.status == "proposed":
            readiness = "needs_confirmation"
            reason = "Invariant must be confirmed by a human reviewer before dynamic tests are generated."
            requires_dynamic = True
        elif model and not matching:
            readiness = "unknown"
            reason = "No matching endpoint was found in the current security model."
            requires_dynamic = True
        else:
            readiness = "ready_for_testing"
            reason = "Invariant is confirmed and can be used by a later attack engine."
            requires_dynamic = True
        evaluations.append(
            InvariantEvaluation(
                invariant_id=invariant.invariant_id,
                name=invariant.name,
                status=invariant.status,
                readiness=readiness,
                reason=reason,
                matching_endpoints=matching,
                requires_dynamic_test=requires_dynamic,
            )
        )
    return evaluations


def invariant_state_payload(contract: SecurityContract, evaluations: list[InvariantEvaluation]) -> dict:
    counts = {status: 0 for status in sorted(ALLOWED_INVARIANT_STATUSES)}
    for invariant in contract.invariants:
        counts[invariant.status] += 1
    readiness_counts: dict[str, int] = {}
    for evaluation in evaluations:
        readiness_counts[evaluation.readiness] = readiness_counts.get(evaluation.readiness, 0) + 1
    return {
        "schema_version": "1.0",
        "project_path": contract.project_path,
        "source_contract_generated_at": contract.generated_at,
        "status_counts": counts,
        "readiness_counts": readiness_counts,
        "invariants": [
            {
                "invariant_id": evaluation.invariant_id,
                "name": evaluation.name,
                "status": evaluation.status,
                "readiness": evaluation.readiness,
                "reason": evaluation.reason,
                "matching_endpoints": list(evaluation.matching_endpoints),
                "requires_dynamic_test": evaluation.requires_dynamic_test,
            }
            for evaluation in evaluations
        ],
    }


def write_invariant_state(payload: dict, output: Path) -> None:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_model_if_present(path_value: str | None) -> ProjectSecurityModel | None:
    return load_security_model(Path(path_value)) if path_value else None
