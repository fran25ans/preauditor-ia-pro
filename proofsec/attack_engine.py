"""Safe dynamic attack tests for authorized ProofSec targets."""

from __future__ import annotations

import json
from pathlib import Path
import time

from proofsec.contract import load_security_model
from proofsec.http.client import run_http_request
from proofsec.invariants import load_security_contract
from proofsec.models import (
    ContractInvariant,
    EndpointNode,
    HttpExchangeEvidence,
    ProofSecIdentity,
    ProofSecResourceExample,
    ProofSecTarget,
    SecurityProof,
    stable_hash,
)
from proofsec.proof_validator import validate_authorization_response, validate_bola_response
from proofsec.resource_discovery import identity_attribute
from proofsec.regression import generate_spring_mockmvc_test
from proofsec.remediation import suggest_fix_for_bola
from proofsec.runtime_config import (
    assert_target_authorized,
    auth_headers,
    load_identities,
    load_resource_examples,
    load_runtime_config,
    load_target,
)


READ_METHODS = {"GET", "HEAD"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def endpoint_url(target: ProofSecTarget, endpoint: EndpointNode, resource_id: str, identity: ProofSecIdentity | None = None) -> str:
    path = endpoint.path
    for parameter in endpoint.parameters:
        value = identity_attribute(identity, parameter) if identity else None
        path = path.replace("{" + parameter + "}", value or resource_id)
    return target.base_url.rstrip("/") + "/" + path.lstrip("/")


def matching_confirmed_bola_invariants(contract_path: Path) -> list[ContractInvariant]:
    contract = load_security_contract(contract_path)
    return [
        invariant
        for invariant in contract.invariants
        if invariant.status == "confirmed" and invariant.action == "read"
    ]


def matching_read_endpoints(model_path: Path, invariant: ContractInvariant) -> list[EndpointNode]:
    model = load_security_model(model_path)
    return [
        endpoint
        for endpoint in model.endpoints
        if endpoint.resource == invariant.resource
        and endpoint.action == invariant.action
        and endpoint.method in READ_METHODS
        and endpoint.parameters
        and endpoint.path.rstrip("/").rsplit("/", 1)[-1].startswith("{")
    ]


def dynamic_read_endpoints_from_discovery(config: dict, invariant: ContractInvariant) -> list[EndpointNode]:
    import re

    raw = (config.get("discovery") or {}).get(invariant.resource)
    if not isinstance(raw, dict):
        return []
    detail_endpoint = str(raw.get("detail_endpoint") or "").strip()
    if not detail_endpoint.startswith("/"):
        return []
    parameters = tuple(sorted(re.findall(r"\{([^}]+)\}", detail_endpoint)))
    return [
        EndpointNode(
            method="GET",
            path=detail_endpoint,
            controller="RuntimeDiscovery",
            handler=f"get_{invariant.resource}",
            file="runtime-discovery",
            line=1,
            authorization="unknown",
            roles=(),
            resource=invariant.resource,
            action="read",
            parameters=parameters,
        )
    ]


def dynamic_bola_invariants_from_resources(
    model_path: Path,
    resources: list[ProofSecResourceExample],
    config: dict | None = None,
) -> list[ContractInvariant]:
    """Build test hypotheses from high-confidence dynamic ownership discovery."""
    model = load_security_model(model_path)
    resources_with_detail_endpoints = {
        endpoint.resource
        for endpoint in model.endpoints
        if endpoint.action == "read" and endpoint.method in READ_METHODS and endpoint.parameters
    }
    if config:
        resources_with_detail_endpoints.update(
            str(resource)
            for resource, raw in (config.get("discovery") or {}).items()
            if isinstance(raw, dict) and str(raw.get("detail_endpoint") or "").startswith("/")
        )
    candidates: dict[str, ContractInvariant] = {}
    for resource in resources:
        if resource.resource not in resources_with_detail_endpoints:
            continue
        if resource.owner_identity == "UNKNOWN" or resource.ownership_confidence < 0.85:
            continue
        invariant_id = "dyn_inv_" + stable_hash(["bola", resource.resource, resource.ownership_source])
        candidates.setdefault(
            resource.resource,
            ContractInvariant(
                invariant_id=invariant_id,
                name=f"dynamic_{resource.resource}_owner_access_only",
                description=(
                    f"{resource.resource} records discovered with high-confidence ownership should only be readable "
                    "by their owning identity."
                ),
                resource=resource.resource,
                action="read",
                expected_behavior="Cross-owner access should be rejected with 403 Forbidden or equivalent.",
                source="inferred",
                confidence=0.86,
                status="confirmed",
                evidence=(
                    "Dynamic resource discovery inferred ownership from "
                    f"{resource.ownership_source}; this is a test hypothesis, not a human-confirmed contract rule."
                ),
            ),
        )
    return sorted(candidates.values(), key=lambda item: item.name)


def build_bola_proof(
    invariant: ContractInvariant,
    endpoint: EndpointNode,
    identity: ProofSecIdentity,
    resource: ProofSecResourceExample,
    evidence: HttpExchangeEvidence,
) -> SecurityProof:
    validation = validate_bola_response(evidence, resource)
    state = validation.state
    exploitability = validation.exploitability
    severity = "HIGH"
    confidence = validation.confidence
    if state == "PROVEN":
        conclusion = "SECURITY INVARIANT VIOLATED. Cross-owner resource id and ownership marker were confirmed."
    elif state == "VALIDATED":
        conclusion = "Cross-owner access returned the requested resource id, but ownership evidence is incomplete."
    elif state == "FIXED":
        conclusion = "Invariant respected during this run. Cross-owner access was rejected."
    else:
        conclusion = "Dynamic BOLA test was inconclusive and needs stronger evidence."
    if invariant.invariant_id.startswith("dyn_inv_"):
        conclusion += " The invariant was generated as a dynamic test hypothesis from resource discovery, not as a human-confirmed contract rule."
    proof_id = "proof_" + stable_hash(
        [invariant.invariant_id, endpoint.method, endpoint.path, identity.name, resource.name, str(evidence.status)]
    )
    actual = "network-error" if evidence.status is None else f"{evidence.status}"
    affected_code = f"{endpoint.file}:{endpoint.line}"
    return SecurityProof(
        proof_id=proof_id,
        finding_state=state,
        invariant_id=invariant.invariant_id,
        invariant_name=invariant.name,
        vulnerability="Broken Object Level Authorization",
        severity=severity,
        confidence=confidence,
        exploitability=exploitability,
        expected="403 Forbidden or equivalent denial",
        actual=actual,
        identity=identity.name,
        resource=resource.name,
        resource_owner=resource.owner_identity,
        endpoint=f"{endpoint.method} {endpoint.path}",
        classification="BOLA",
        conclusion=f"{conclusion} Evidence quality: {validation.reason}",
        evidence=evidence,
        affected_code=affected_code,
        suggested_fix=suggest_fix_for_bola(endpoint, invariant),
        regression_test=generate_spring_mockmvc_test(endpoint, invariant, identity, resource),
    )


def build_authorization_proof(
    endpoint: EndpointNode,
    identity: ProofSecIdentity,
    evidence: HttpExchangeEvidence,
    classification: str,
    functional_markers: tuple[str, ...] = (),
) -> SecurityProof:
    validation = validate_authorization_response(evidence, functional_markers)
    state = validation.state
    exploitability = validation.exploitability
    confidence = validation.confidence
    if state == "PROVEN":
        conclusion = "SECURITY INVARIANT VIOLATED. Lower-privileged identity accessed a restricted function."
    elif state == "VALIDATED":
        conclusion = "Lower-privileged identity received a successful response, but functional execution evidence is incomplete."
    elif state == "FIXED":
        conclusion = "Authorization check respected during this run. Restricted function was denied."
    else:
        conclusion = "Dynamic authorization test was inconclusive and needs manual review."
    vulnerability = (
        "Broken Function Level Authorization"
        if classification == "BFLA"
        else "Privilege Escalation / Broken Authorization"
    )
    invariant_id = "dynamic_" + stable_hash([classification, endpoint.method, endpoint.path, ",".join(endpoint.roles)])
    proof_id = "proof_" + stable_hash(
        [invariant_id, endpoint.method, endpoint.path, identity.name, str(evidence.status)]
    )
    actual = "network-error" if evidence.status is None else f"{evidence.status}"
    return SecurityProof(
        proof_id=proof_id,
        finding_state=state,
        invariant_id=invariant_id,
        invariant_name=f"{identity.role.lower()}_must_not_access_{endpoint.resource}_{endpoint.action}",
        vulnerability=vulnerability,
        severity="HIGH" if classification == "BFLA" else "CRITICAL",
        confidence=confidence,
        exploitability=exploitability,
        expected="401/403/404 authorization denial",
        actual=actual,
        identity=identity.name,
        resource=endpoint.resource,
        resource_owner="restricted_role:" + ",".join(endpoint.roles),
        endpoint=f"{endpoint.method} {endpoint.path}",
        classification=classification,
        conclusion=f"{conclusion} Evidence quality: {validation.reason}",
        evidence=evidence,
        affected_code=f"{endpoint.file}:{endpoint.line}",
        suggested_fix=suggest_fix_for_authorization(endpoint, identity, classification),
        regression_test=generate_authorization_regression_test(endpoint, identity, classification),
    )

def run_bola_tests(model_path: Path, contract_path: Path, config_path: Path) -> dict:
    config = load_runtime_config(config_path)
    target = load_target(config)
    assert_target_authorized(target)
    identities = load_identities(config)
    resources = load_resource_examples(config, require=False)
    discovery_suggestions: list[dict[str, object]] = []
    if config.get("discovery"):
        from proofsec.resource_discovery import discover_resources_with_suggestions

        discovered_resources, suggestions = discover_resources_with_suggestions(config, target, identities)
        discovery_suggestions = [suggestion.to_dict() for suggestion in suggestions]
        resources = sorted(
            {(
                resource.resource,
                resource.resource_id,
                resource.owner_identity,
            ): resource for resource in [*resources, *discovered_resources]}.values(),
            key=lambda item: (item.resource, item.resource_id, item.owner_identity),
        )
    if not resources:
        raise ValueError("At least one resource example is required, either in resources or via discovery.")
    proofs: list[SecurityProof] = []
    requests_executed = 0
    invariants = matching_confirmed_bola_invariants(contract_path)
    if not invariants:
        invariants = dynamic_bola_invariants_from_resources(model_path, resources, config)
    for invariant in invariants:
        endpoints = matching_read_endpoints(model_path, invariant) or dynamic_read_endpoints_from_discovery(config, invariant)
        for endpoint in endpoints:
            for identity in identities.values():
                for resource in resources:
                    if resource.resource != invariant.resource or resource.owner_identity == identity.name:
                        continue
                    if resource.owner_identity == "UNKNOWN" or resource.ownership_confidence <= 0:
                        continue
                    if identity.name in resource.observed_by:
                        continue
                    if endpoint.roles and identity.role not in endpoint.roles:
                        continue
                    if requests_executed >= target.max_requests:
                        return proof_payload(proofs, target, limited=True, resource_discovery_suggestions=discovery_suggestions)
                    url = endpoint_url(target, endpoint, resource.resource_id, identity)
                    evidence = run_http_request(target, endpoint.method, url, auth_headers(identity))
                    requests_executed += 1
                    proofs.append(build_bola_proof(invariant, endpoint, identity, resource, evidence))
                    if target.rate_limit_seconds:
                        time.sleep(target.rate_limit_seconds)
    return proof_payload(proofs, target, resource_discovery_suggestions=discovery_suggestions)


def run_authorization_tests(model_path: Path, config_path: Path, test_type: str) -> dict:
    config = load_runtime_config(config_path)
    target = load_target(config)
    assert_target_authorized(target)
    identities = load_identities(config)
    model = load_security_model(model_path)
    proofs: list[SecurityProof] = []
    requests_executed = 0
    for endpoint in model.endpoints:
        if not endpoint.roles:
            continue
        is_mutating = endpoint.method in MUTATING_METHODS
        if test_type == "bfla" and is_mutating:
            continue
        if test_type == "privilege" and not is_mutating:
            continue
        if is_mutating and not target.allow_mutating:
            continue
        if endpoint.method not in READ_METHODS and not target.allow_mutating:
            continue
        for identity in identities.values():
            if identity.role in endpoint.roles:
                continue
            if requests_executed >= target.max_requests:
                return proof_payload(proofs, target, limited=True)
            url = endpoint_url(target, endpoint, "1", identity)
            evidence = run_http_request(target, endpoint.method, url, auth_headers(identity))
            requests_executed += 1
            classification = "BFLA" if test_type == "bfla" else "PRIVILEGE_ESCALATION"
            markers = authorization_functional_markers(config, endpoint, classification)
            proofs.append(build_authorization_proof(endpoint, identity, evidence, classification, markers))
            if target.rate_limit_seconds:
                time.sleep(target.rate_limit_seconds)
    return proof_payload(proofs, target)


def authorization_functional_markers(config: dict, endpoint: EndpointNode, classification: str) -> tuple[str, ...]:
    validation = config.get("authorization_validation") or {}
    marker_map = validation.get("functional_markers") or {}
    if not isinstance(marker_map, dict):
        return ()
    keys = (
        f"{endpoint.method} {endpoint.path}",
        endpoint.path,
        endpoint.resource,
        classification,
        classification.lower(),
    )
    markers: list[str] = []
    for key in keys:
        raw = marker_map.get(key)
        if isinstance(raw, str):
            markers.append(raw)
        elif isinstance(raw, list):
            markers.extend(str(item) for item in raw)
    return tuple(dict.fromkeys(marker for marker in markers if marker))


def run_dynamic_tests(model_path: Path, contract_path: Path, config_path: Path, test_type: str) -> dict:
    if test_type == "bola":
        return run_bola_tests(model_path, contract_path, config_path)
    if test_type in {"bfla", "privilege"}:
        return run_authorization_tests(model_path, config_path, test_type)
    if test_type == "all":
        bola = run_bola_tests(model_path, contract_path, config_path)
        bfla = run_authorization_tests(model_path, config_path, "bfla")
        privilege = run_authorization_tests(model_path, config_path, "privilege")
        config = load_runtime_config(config_path)
        target = load_target(config)
        proofs = bola["proofs"] + bfla["proofs"] + privilege["proofs"]
        return proof_payload_dicts(proofs, target, bola["limited_by_request_budget"] or bfla["limited_by_request_budget"] or privilege["limited_by_request_budget"])
    raise ValueError(f"Unsupported dynamic test type: {test_type}")


def proof_payload(
    proofs: list[SecurityProof],
    target: ProofSecTarget,
    limited: bool = False,
    resource_discovery_suggestions: list[dict[str, object]] | None = None,
) -> dict:
    return proof_payload_dicts([proof.to_dict() for proof in proofs], target, limited, resource_discovery_suggestions)


def proof_payload_dicts(
    proofs: list[dict],
    target: ProofSecTarget,
    limited: bool = False,
    resource_discovery_suggestions: list[dict[str, object]] | None = None,
) -> dict:
    payload = {
        "schema_version": "1.0",
        "target": {
            "base_url": target.base_url,
            "authorized": target.authorized,
            "dry_run": target.dry_run,
            "allow_mutating": target.allow_mutating,
        },
        "limited_by_request_budget": limited,
        "kpis": {
            "tests_executed": len(proofs),
            "proven_vulnerabilities": sum(1 for proof in proofs if proof["exploitability"] == "PROVEN"),
            "validated_findings": sum(1 for proof in proofs if proof["exploitability"] == "VALIDATED"),
            "fixed_vulnerabilities": sum(1 for proof in proofs if proof["exploitability"] == "FIXED"),
            "inconclusive": sum(1 for proof in proofs if proof["exploitability"] == "UNKNOWN"),
            "bola": sum(1 for proof in proofs if proof["classification"] == "BOLA"),
            "bfla": sum(1 for proof in proofs if proof["classification"] == "BFLA"),
            "privilege_escalation": sum(1 for proof in proofs if proof["classification"] == "PRIVILEGE_ESCALATION"),
        },
        "proofs": proofs,
    }
    if resource_discovery_suggestions:
        payload["resource_discovery"] = {
            "suggested_owner_fields": resource_discovery_suggestions,
        }
    return payload


def write_proofs(payload: dict, output: Path) -> None:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def retest_proof(model_path: Path, contract_path: Path, config_path: Path, proof_path: Path) -> dict:
    previous = json.loads(proof_path.expanduser().resolve().read_text(encoding="utf-8"))
    result = run_dynamic_tests(model_path, contract_path, config_path, "all")
    previous_ids = {proof.get("invariant_id") for proof in previous.get("proofs", [])}
    for proof in result["proofs"]:
        if proof["invariant_id"] in previous_ids and proof["exploitability"] == "FIXED":
            proof["finding_state"] = "FIXED"
            proof["conclusion"] = "FIX VERIFIED. The original dynamic test now returns an authorization denial."
    result["previous_proof_file"] = str(proof_path.expanduser().resolve())
    return result


def suggest_fix_for_authorization(endpoint: EndpointNode, identity: ProofSecIdentity, classification: str) -> str:
    roles = ", ".join(endpoint.roles) or "the required role"
    spring_roles = "','".join(endpoint.roles) if endpoint.roles else "ADMIN"
    return (
        f"Enforce server-side authorization for {endpoint.method} {endpoint.path} before executing business logic.\n\n"
        "Conceptual Spring Boot patch:\n"
        "```diff\n"
        f"+ @PreAuthorize(\"hasAnyRole('{spring_roles}')\")\n"
        f"  public ... {endpoint.handler}(...) {{\n"
        "+     // keep resource ownership checks inside the service/repository layer when object ids are involved\n"
        "  }\n"
        "```\n\n"
        f"The test used identity {identity.name} with role {identity.role}; this role must not be able to invoke the endpoint."
    )


def generate_authorization_regression_test(
    endpoint: EndpointNode,
    identity: ProofSecIdentity,
    classification: str,
) -> str:
    method = endpoint.method.lower()
    path = endpoint.path
    for parameter in endpoint.parameters:
        path = path.replace("{" + parameter + "}", "1")
    test_name = f"{identity.name}_cannot_invoke_{endpoint.handler}"
    return f"""@Test
void {test_name}() throws Exception {{
    mockMvc.perform({method}(\"{path}\")
            .header(\"Authorization\", \"Bearer \" + tokenFor(\"{identity.name}\")))
        .andExpect(status().isForbidden());
}}

// Linked ProofSec dynamic check: {classification}
// Expected behaviour: lower-privileged identity must be denied.
"""
