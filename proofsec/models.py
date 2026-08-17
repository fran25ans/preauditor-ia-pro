"""Core data models for ProofSec security modelling."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
from typing import Any, Literal


EdgeType = Literal[
    "declares",
    "requires_role",
    "accesses_resource",
    "invokes",
    "owns",
    "trust_boundary",
]
ContractSource = Literal["detected", "inferred", "user-confirmed"]
ContractStatus = Literal["proposed", "confirmed", "rejected"]
InvariantStatus = Literal["proposed", "confirmed", "rejected", "testing", "respected", "violated", "unknown"]
Exploitability = Literal["UNVERIFIED", "VALIDATED", "PROVEN", "FIXED", "UNKNOWN"]
FindingState = Literal["POTENTIAL", "LIKELY", "VALIDATED", "PROVEN", "INCONCLUSIVE", "FALSE_POSITIVE", "FIXED"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stable_hash(parts: list[str]) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", errors="replace"))
        digest.update(b"\0")
    return digest.hexdigest()[:16]


@dataclass(frozen=True)
class EndpointNode:
    method: str
    path: str
    controller: str
    handler: str
    file: str
    line: int
    authorization: str = "unknown"
    roles: tuple[str, ...] = ()
    resource: str = ""
    action: str = "unknown"
    parameters: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return "endpoint:" + stable_hash([self.method, self.path, self.controller, self.handler])


@dataclass(frozen=True)
class RoleNode:
    name: str
    source: str = "detected"
    evidence: str = ""

    @property
    def id(self) -> str:
        return f"role:{self.name}"


@dataclass(frozen=True)
class ResourceNode:
    name: str
    source: str = "detected"
    evidence: str = ""

    @property
    def id(self) -> str:
        return f"resource:{self.name}"


@dataclass(frozen=True)
class SecurityEdge:
    source: str
    target: str
    type: EdgeType
    evidence: str = ""

    @property
    def id(self) -> str:
        return "edge:" + stable_hash([self.source, self.target, self.type, self.evidence])


@dataclass
class ProjectSecurityModel:
    project_path: str
    generated_at: str = field(default_factory=utc_now)
    framework: str = "unknown"
    languages: tuple[str, ...] = ()
    endpoints: list[EndpointNode] = field(default_factory=list)
    roles: list[RoleNode] = field(default_factory=list)
    resources: list[ResourceNode] = field(default_factory=list)
    edges: list[SecurityEdge] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "project_path": self.project_path,
            "generated_at": self.generated_at,
            "framework": self.framework,
            "languages": list(self.languages),
            "endpoints": [asdict(endpoint) | {"id": endpoint.id} for endpoint in self.endpoints],
            "roles": [asdict(role) | {"id": role.id} for role in self.roles],
            "resources": [asdict(resource) | {"id": resource.id} for resource in self.resources],
            "edges": [asdict(edge) | {"id": edge.id} for edge in self.edges],
            "notes": self.notes,
            "kpis": self.kpis(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    def kpis(self) -> dict[str, int]:
        return {
            "endpoints_discovered": len(self.endpoints),
            "resources_discovered": len(self.resources),
            "roles_discovered": len(self.roles),
            "security_edges": len(self.edges),
        }


@dataclass(frozen=True)
class ContractPermission:
    permission: str
    source: ContractSource
    confidence: float
    evidence: str
    status: ContractStatus = "proposed"

    @property
    def id(self) -> str:
        return "permission:" + stable_hash([self.permission, self.source, self.evidence])


@dataclass(frozen=True)
class ContractRole:
    name: str
    permissions: tuple[ContractPermission, ...] = ()
    source: ContractSource = "detected"
    confidence: float = 1.0
    status: ContractStatus = "proposed"


@dataclass(frozen=True)
class ContractInvariant:
    invariant_id: str
    name: str
    description: str
    resource: str
    action: str
    expected_behavior: str
    source: ContractSource
    confidence: float
    status: InvariantStatus
    evidence: str


@dataclass(frozen=True)
class InvariantEvaluation:
    invariant_id: str
    name: str
    status: InvariantStatus
    readiness: str
    reason: str
    matching_endpoints: tuple[str, ...] = ()
    requires_dynamic_test: bool = True


@dataclass
class SecurityContract:
    project_path: str
    generated_at: str = field(default_factory=utc_now)
    source_model_generated_at: str = ""
    roles: list[ContractRole] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    invariants: list[ContractInvariant] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "project_path": self.project_path,
            "generated_at": self.generated_at,
            "source_model_generated_at": self.source_model_generated_at,
            "roles": [
                {
                    "name": role.name,
                    "source": role.source,
                    "confidence": role.confidence,
                    "status": role.status,
                    "permissions": [asdict(permission) | {"id": permission.id} for permission in role.permissions],
                }
                for role in self.roles
            ],
            "resources": self.resources,
            "invariants": [asdict(invariant) for invariant in self.invariants],
            "notes": self.notes,
            "kpis": self.kpis(),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)

    def write_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")

    def kpis(self) -> dict[str, int]:
        return {
            "roles": len(self.roles),
            "resources": len(self.resources),
            "permissions": sum(len(role.permissions) for role in self.roles),
            "invariants": len(self.invariants),
            "confirmed_invariants": sum(1 for invariant in self.invariants if invariant.status == "confirmed"),
        }


@dataclass(frozen=True)
class ProofSecIdentity:
    name: str
    role: str
    auth_type: str = "none"
    token_env: str = ""
    token_value: str = ""
    attributes: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ProofSecResourceExample:
    name: str
    resource: str
    resource_id: str
    owner_identity: str
    observed_by: tuple[str, ...] = ()
    ownership_source: str = "manual"
    ownership_confidence: float = 1.0
    sensitive_markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProofSecTarget:
    base_url: str
    authorized: bool
    allow_non_local: bool = False
    dry_run: bool = False
    max_requests: int = 20
    timeout_seconds: float = 5.0
    rate_limit_seconds: float = 0.0
    allow_mutating: bool = False


@dataclass(frozen=True)
class HttpExchangeEvidence:
    method: str
    url: str
    request_headers: dict[str, str]
    status: int | None
    response_headers: dict[str, str]
    response_body_preview: str
    response_body: str = ""
    error: str = ""


@dataclass(frozen=True)
class SecurityProof:
    proof_id: str
    finding_state: FindingState
    invariant_id: str
    invariant_name: str
    vulnerability: str
    severity: str
    confidence: float
    exploitability: Exploitability
    expected: str
    actual: str
    identity: str
    resource: str
    resource_owner: str
    endpoint: str
    classification: str
    conclusion: str
    evidence: HttpExchangeEvidence
    affected_code: str
    suggested_fix: str
    regression_test: str
    generated_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence"].pop("response_body", None)
        return payload
