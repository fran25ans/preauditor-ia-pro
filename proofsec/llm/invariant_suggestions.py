"""LLM-assisted invariant suggestions with strict validation."""

from __future__ import annotations

from proofsec.models import ContractInvariant, ProjectSecurityModel, stable_hash

from .prompts import INVARIANT_SUGGESTION_SYSTEM, invariant_suggestion_prompt
from .providers import LLMProvider
from .schemas import validate_invariant_suggestions


def suggest_invariants_with_llm(model: ProjectSecurityModel, provider: LLMProvider, timeout: int = 60) -> list[ContractInvariant]:
    allowed_resources = {resource.name for resource in model.resources}
    allowed_actions = {endpoint.action for endpoint in model.endpoints}
    if not allowed_resources or not allowed_actions:
        return []
    data = provider.chat_json(
        INVARIANT_SUGGESTION_SYSTEM,
        invariant_suggestion_prompt(model),
        timeout=timeout,
    )
    validated = validate_invariant_suggestions(data, allowed_resources, allowed_actions)
    invariants: list[ContractInvariant] = []
    for item in validated:
        invariant_id = "llm_inv_" + stable_hash(
            [item["name"], item["resource"], item["action"], item["expected_behavior"]]
        )
        invariants.append(
            ContractInvariant(
                invariant_id=invariant_id,
                name=item["name"],
                description=item["description"],
                resource=item["resource"],
                action=item["action"],
                expected_behavior=item["expected_behavior"],
                source="inferred",
                confidence=min(float(item["confidence"]), 0.65),
                status="proposed",
                evidence=f"LLM suggestion via {provider.name}/{provider.model}: {item['evidence']}",
            )
        )
    return invariants
