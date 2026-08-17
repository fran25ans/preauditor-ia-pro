"""Safe dynamic attack tests for authorized ProofSec targets."""

from __future__ import annotations

import json
from pathlib import Path
import time
from urllib import error as urlerror
from urllib import request as urlrequest

from proofsec.contract import load_security_model
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
from proofsec.proof_validator import validate_bola_response
from proofsec.regression import generate_spring_mockmvc_test
from proofsec.remediation import suggest_fix_for_bola
from proofsec.runtime_config import (
    assert_target_authorized,
    auth_headers,
    load_identities,
    load_resource_examples,
    load_runtime_config,
    load_target,
    redacted_headers,
)


READ_METHODS = {"GET", "HEAD"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SUCCESS_STATUSES = set(range(200, 300))
FORBIDDEN_STATUSES = {401, 403, 404}


def endpoint_url(target: ProofSecTarget, endpoint: EndpointNode, resource_id: str) -> str:
    path = endpoint.path
    for parameter in endpoint.parameters:
        path = path.replace("{" + parameter + "}", resource_id)
    return target.base_url.rstrip("/") + "/" + path.lstrip("/")


def run_http_request(
    target: ProofSecTarget,
    method: str,
    url: str,
    headers: dict[str, str],
) -> HttpExchangeEvidence:
    safe_headers = dict(headers)
    if target.dry_run:
        return HttpExchangeEvidence(
            method=method,
            url=url,
            request_headers=redacted_headers(safe_headers),
            status=None,
            response_headers={},
            response_body_preview="DRY RUN: request was not executed.",
        )
    request = urlrequest.Request(url, headers=safe_headers, method=method)
    try:
        with urlrequest.urlopen(request, timeout=target.timeout_seconds) as response:
            body = response.read(4096).decode("utf-8", errors="replace")
            return HttpExchangeEvidence(
                method=method,
                url=url,
                request_headers=redacted_headers(safe_headers),
                status=int(response.status),
                response_headers=redacted_headers(dict(response.headers.items())),
                response_body_preview=redact_body(body),
            )
    except urlerror.HTTPError as exc:
        try:
            body = exc.read(4096).decode("utf-8", errors="replace")
            return HttpExchangeEvidence(
                method=method,
                url=url,
                request_headers=redacted_headers(safe_headers),
                status=int(exc.code),
                response_headers=redacted_headers(dict(exc.headers.items())),
                response_body_preview=redact_body(body),
            )
        finally:
            exc.close()
    except Exception as exc:
        return HttpExchangeEvidence(
            method=method,
            url=url,
            request_headers=redacted_headers(safe_headers),
            status=None,
            response_headers={},
            response_body_preview="",
            error=str(exc),
        )


def redact_body(body: str) -> str:
    trimmed = body[:2000]
    for marker in ("token", "password", "secret", "api_key", "authorization"):
        trimmed = trimmed.replace(marker, f"{marker[:2]}****")
        trimmed = trimmed.replace(marker.upper(), f"{marker[:2].upper()}****")
    return trimmed


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
    ]


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
) -> SecurityProof:
    proven = evidence.status in SUCCESS_STATUSES
    fixed = evidence.status in FORBIDDEN_STATUSES
    if proven:
        state = "PROVEN"
        exploitability = "PROVEN"
        conclusion = "SECURITY INVARIANT VIOLATED. Lower-privileged identity accessed a restricted function."
        confidence = 1.0
    elif fixed:
        state = "FIXED"
        exploitability = "FIXED"
        conclusion = "Authorization check respected during this run. Restricted function was denied."
        confidence = 0.95
    else:
        state = "LIKELY"
        exploitability = "UNKNOWN"
        conclusion = "Dynamic authorization test was inconclusive and needs manual review."
        confidence = 0.55
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
        conclusion=conclusion,
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
    resources = load_resource_examples(config)
    proofs: list[SecurityProof] = []
    requests_executed = 0
    invariants = matching_confirmed_bola_invariants(contract_path)
    for invariant in invariants:
        for endpoint in matching_read_endpoints(model_path, invariant):
            for identity in identities.values():
                for resource in resources:
                    if resource.resource != invariant.resource or resource.owner_identity == identity.name:
                        continue
                    if identity.role not in endpoint.roles:
                        continue
                    if requests_executed >= target.max_requests:
                        return proof_payload(proofs, target, limited=True)
                    url = endpoint_url(target, endpoint, resource.resource_id)
                    evidence = run_http_request(target, endpoint.method, url, auth_headers(identity))
                    requests_executed += 1
                    proofs.append(build_bola_proof(invariant, endpoint, identity, resource, evidence))
                    if target.rate_limit_seconds:
                        time.sleep(target.rate_limit_seconds)
    return proof_payload(proofs, target)


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
            url = endpoint_url(target, endpoint, "1")
            evidence = run_http_request(target, endpoint.method, url, auth_headers(identity))
            requests_executed += 1
            classification = "BFLA" if test_type == "bfla" else "PRIVILEGE_ESCALATION"
            proofs.append(build_authorization_proof(endpoint, identity, evidence, classification))
            if target.rate_limit_seconds:
                time.sleep(target.rate_limit_seconds)
    return proof_payload(proofs, target)


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


def proof_payload(proofs: list[SecurityProof], target: ProofSecTarget, limited: bool = False) -> dict:
    return proof_payload_dicts([proof.to_dict() for proof in proofs], target, limited)


def proof_payload_dicts(proofs: list[dict], target: ProofSecTarget, limited: bool = False) -> dict:
    return {
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
