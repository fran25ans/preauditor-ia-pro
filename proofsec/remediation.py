"""Remediation suggestions for proven ProofSec vulnerabilities."""

from __future__ import annotations

from proofsec.models import ContractInvariant, EndpointNode


def suggest_fix_for_bola(endpoint: EndpointNode, invariant: ContractInvariant) -> str:
    resource_singular = invariant.resource.rstrip("s")
    role = endpoint.roles[0] if endpoint.roles else "USER"
    repository_method = f"findByIdAnd{role.title().replace('_', '')}Id"
    return (
        "Apply the authorization check on the server side, close to the data access path.\n\n"
        "Conceptual Spring Boot patch:\n"
        "```diff\n"
        f"- repository.findById(id)\n"
        f"+ repository.{repository_method}(id, authenticated{role.title().replace('_', '')}.getId())\n"
        "```\n\n"
        f"The fix must guarantee that the authenticated {role} can only read {resource_singular} records "
        "explicitly assigned to that identity. Do not rely on frontend filtering or hidden UI controls."
    )
