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


def is_cross_owner_success(evidence: HttpExchangeEvidence, resource: ProofSecResourceExample) -> bool:
    if evidence.status not in SUCCESS_STATUSES:
        return False
    if resource.resource_id and resource.resource_id in evidence.response_body_preview:
        return True
    return bool(evidence.response_body_preview.strip())


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
    proven = is_cross_owner_success(evidence, resource)
    fixed = evidence.status in FORBIDDEN_STATUSES
    if proven:
        state = "PROVEN"
        exploitability = "PROVEN"
        conclusion = "SECURITY INVARIANT VIOLATED. Cross-owner resource access returned data."
        severity = "HIGH"
        confidence = 1.0
    elif fixed:
        state = "FIXED"
        exploitability = "FIXED"
        conclusion = "Invariant respected during this run. Cross-owner access was rejected."
        severity = "HIGH"
        confidence = 0.95
    else:
        state = "LIKELY"
        exploitability = "UNKNOWN"
        conclusion = "Dynamic test was inconclusive and needs manual review."
        severity = "HIGH"
        confidence = 0.55
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
        conclusion=conclusion,
        evidence=evidence,
        affected_code=affected_code,
        suggested_fix=suggest_fix_for_bola(endpoint, invariant),
        regression_test=generate_spring_mockmvc_test(endpoint, invariant, identity, resource),
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


def proof_payload(proofs: list[SecurityProof], target: ProofSecTarget, limited: bool = False) -> dict:
    return {
        "schema_version": "1.0",
        "target": {
            "base_url": target.base_url,
            "authorized": target.authorized,
            "dry_run": target.dry_run,
        },
        "limited_by_request_budget": limited,
        "kpis": {
            "tests_executed": len(proofs),
            "proven_vulnerabilities": sum(1 for proof in proofs if proof.exploitability == "PROVEN"),
            "fixed_vulnerabilities": sum(1 for proof in proofs if proof.exploitability == "FIXED"),
            "inconclusive": sum(1 for proof in proofs if proof.exploitability == "UNKNOWN"),
        },
        "proofs": [proof.to_dict() for proof in proofs],
    }


def write_proofs(payload: dict, output: Path) -> None:
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def retest_proof(model_path: Path, contract_path: Path, config_path: Path, proof_path: Path) -> dict:
    previous = json.loads(proof_path.expanduser().resolve().read_text(encoding="utf-8"))
    result = run_bola_tests(model_path, contract_path, config_path)
    previous_ids = {proof.get("invariant_id") for proof in previous.get("proofs", [])}
    for proof in result["proofs"]:
        if proof["invariant_id"] in previous_ids and proof["exploitability"] == "FIXED":
            proof["finding_state"] = "FIXED"
            proof["conclusion"] = "FIX VERIFIED. The original dynamic test now returns an authorization denial."
    result["previous_proof_file"] = str(proof_path.expanduser().resolve())
    return result
