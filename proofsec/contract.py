"""Security Contract generation for ProofSec."""

from __future__ import annotations

import json
from pathlib import Path

from proofsec.models import (
    ContractInvariant,
    ContractPermission,
    ContractRole,
    EndpointNode,
    ProjectSecurityModel,
    SecurityContract,
    stable_hash,
)


def permission_for(endpoint: EndpointNode) -> str:
    scope = "assigned" if endpoint.parameters and endpoint.action == "read" else "any"
    return f"{endpoint.resource}.{endpoint.action}:{scope}"


def invariant_for(endpoint: EndpointNode) -> ContractInvariant | None:
    if endpoint.action != "read" or not endpoint.parameters or not endpoint.roles or endpoint.resource == "unknown":
        return None
    primary_role = endpoint.roles[0].lower()
    resource = endpoint.resource.rstrip("s")
    invariant_id = f"inv_{stable_hash([primary_role, endpoint.resource, endpoint.action, endpoint.path])}"
    name = f"{primary_role}_can_only_access_assigned_{endpoint.resource}"
    return ContractInvariant(
        invariant_id=invariant_id,
        name=name,
        description=f"{endpoint.roles[0]} users should only read {endpoint.resource} records assigned to them.",
        resource=endpoint.resource,
        action=endpoint.action,
        expected_behavior="Cross-owner access should be rejected with 403 Forbidden or equivalent.",
        source="inferred",
        confidence=0.72,
        status="proposed",
        evidence=f"{endpoint.method} {endpoint.path} in {endpoint.file}:{endpoint.line} uses path parameter(s) {', '.join(endpoint.parameters)}.",
    )


def propose_security_contract(model: ProjectSecurityModel) -> SecurityContract:
    permissions_by_role: dict[str, dict[str, ContractPermission]] = {}
    invariants: dict[str, ContractInvariant] = {}
    notes: list[str] = []

    for endpoint in model.endpoints:
        if not endpoint.roles:
            notes.append(f"No role detected for {endpoint.method} {endpoint.path}; user confirmation is required.")
            continue
        permission = permission_for(endpoint)
        for role_name in endpoint.roles:
            role_permissions = permissions_by_role.setdefault(role_name, {})
            role_permissions.setdefault(
                permission,
                ContractPermission(
                    permission=permission,
                    source="detected",
                    confidence=0.9,
                    evidence=f"{endpoint.method} {endpoint.path} requires {role_name} in {endpoint.file}:{endpoint.line}.",
                ),
            )
        invariant = invariant_for(endpoint)
        if invariant:
            invariants[invariant.invariant_id] = invariant

    roles = [
        ContractRole(name=role_name, permissions=tuple(sorted(permissions.values(), key=lambda item: item.permission)))
        for role_name, permissions in sorted(permissions_by_role.items())
    ]
    resources = sorted({resource.name for resource in model.resources})
    return SecurityContract(
        project_path=model.project_path,
        source_model_generated_at=model.generated_at,
        roles=roles,
        resources=resources,
        invariants=sorted(invariants.values(), key=lambda item: item.name),
        notes=notes,
    )


def merge_invariants(contract: SecurityContract, extra_invariants: list[ContractInvariant]) -> SecurityContract:
    merged = {(invariant.name, invariant.resource, invariant.action): invariant for invariant in contract.invariants}
    for invariant in extra_invariants:
        key = (invariant.name, invariant.resource, invariant.action)
        if key not in merged:
            merged[key] = invariant
    contract.invariants = sorted(merged.values(), key=lambda item: item.name)
    return contract


def load_security_model(path: Path) -> ProjectSecurityModel:
    data = json.loads(path.expanduser().resolve().read_text(encoding="utf-8"))
    endpoints = [
        EndpointNode(
            method=item["method"],
            path=item["path"],
            controller=item["controller"],
            handler=item["handler"],
            file=item["file"],
            line=int(item["line"]),
            authorization=item.get("authorization", "unknown"),
            roles=tuple(item.get("roles", [])),
            resource=item.get("resource", ""),
            action=item.get("action", "unknown"),
            parameters=tuple(item.get("parameters", [])),
        )
        for item in data.get("endpoints", [])
    ]
    from proofsec.models import ResourceNode, RoleNode, SecurityEdge

    return ProjectSecurityModel(
        project_path=data.get("project_path", ""),
        generated_at=data.get("generated_at", ""),
        framework=data.get("framework", "unknown"),
        languages=tuple(data.get("languages", [])),
        endpoints=endpoints,
        roles=[RoleNode(item["name"], item.get("source", "detected"), item.get("evidence", "")) for item in data.get("roles", [])],
        resources=[ResourceNode(item["name"], item.get("source", "detected"), item.get("evidence", "")) for item in data.get("resources", [])],
        edges=[
            SecurityEdge(item["source"], item["target"], item["type"], item.get("evidence", ""))
            for item in data.get("edges", [])
        ],
        notes=list(data.get("notes", [])),
    )


def contract_to_yaml(contract: SecurityContract) -> str:
    lines = [
        "schema_version: '1.0'",
        f"project_path: {json.dumps(contract.project_path)}",
        f"generated_at: {json.dumps(contract.generated_at)}",
        f"source_model_generated_at: {json.dumps(contract.source_model_generated_at)}",
        "roles:",
    ]
    for role in contract.roles:
        lines.extend(
            [
                f"  {role.name}:",
                f"    source: {role.source}",
                f"    confidence: {role.confidence}",
                f"    status: {role.status}",
                "    permissions:",
            ]
        )
        for permission in role.permissions:
            lines.extend(
                [
                    f"      - permission: {permission.permission}",
                    f"        source: {permission.source}",
                    f"        confidence: {permission.confidence}",
                    f"        status: {permission.status}",
                    f"        evidence: {json.dumps(permission.evidence)}",
                ]
            )
    lines.append("resources:")
    for resource in contract.resources:
        lines.append(f"  - {resource}")
    lines.append("invariants:")
    for invariant in contract.invariants:
        lines.extend(
            [
                f"  - id: {invariant.invariant_id}",
                f"    name: {invariant.name}",
                f"    description: {json.dumps(invariant.description)}",
                f"    resource: {invariant.resource}",
                f"    action: {invariant.action}",
                f"    expected_behavior: {json.dumps(invariant.expected_behavior)}",
                f"    source: {invariant.source}",
                f"    confidence: {invariant.confidence}",
                f"    status: {invariant.status}",
                f"    evidence: {json.dumps(invariant.evidence)}",
            ]
        )
    if contract.notes:
        lines.append("notes:")
        for note in contract.notes:
            lines.append(f"  - {json.dumps(note)}")
    return "\n".join(lines) + "\n"


def write_contract(contract: SecurityContract, output: Path) -> None:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.suffix.lower() in {".yaml", ".yml"}:
        output.write_text(contract_to_yaml(contract), encoding="utf-8")
    else:
        contract.write_json(output)
