"""Regression test generation for ProofSec findings."""

from __future__ import annotations

from proofsec.models import ContractInvariant, EndpointNode, ProofSecIdentity, ProofSecResourceExample


def generate_spring_mockmvc_test(
    endpoint: EndpointNode,
    invariant: ContractInvariant,
    identity: ProofSecIdentity,
    resource: ProofSecResourceExample,
) -> str:
    method = endpoint.method.lower()
    path = endpoint.path
    for parameter in endpoint.parameters:
        path = path.replace("{" + parameter + "}", resource.resource_id)
    test_name = f"{identity.name}_cannot_read_{resource.name}_owned_by_{resource.owner_identity}"
    return f"""@Test
void {test_name}() throws Exception {{
    mockMvc.perform({method}(\"{path}\")
            .header(\"Authorization\", \"Bearer \" + tokenFor(\"{identity.name}\")))
        .andExpect(status().isForbidden());
}}

// Linked ProofSec invariant: {invariant.invariant_id}
// Expected behaviour: {invariant.expected_behavior}
"""
