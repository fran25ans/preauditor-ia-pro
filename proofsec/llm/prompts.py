"""Centralized ProofSec LLM prompts."""

from __future__ import annotations

import json

from proofsec.models import ProjectSecurityModel


INVARIANT_SUGGESTION_SYSTEM = """You are helping an AppSec reviewer propose authorization invariants.
Return only valid JSON. Never mark rules as confirmed. Never claim exploitability.
Focus only on business logic and authorization. Do not propose SQLi, XSS, SSRF or RCE checks."""


def invariant_suggestion_prompt(model: ProjectSecurityModel) -> str:
    endpoints = [
        {
            "method": endpoint.method,
            "path": endpoint.path,
            "roles": list(endpoint.roles),
            "resource": endpoint.resource,
            "action": endpoint.action,
            "parameters": list(endpoint.parameters),
            "file": endpoint.file,
            "line": endpoint.line,
        }
        for endpoint in model.endpoints[:80]
    ]
    resources = [resource.name for resource in model.resources]
    roles = [role.name for role in model.roles]
    return f"""Given this deterministic application security model, suggest candidate authorization invariants.

Output schema:
{{
  "invariants": [
    {{
      "name": "short_snake_case_name",
      "description": "human readable rule",
      "resource": "resource_name_from_input",
      "action": "read|create|update|delete|unknown",
      "expected_behavior": "expected authorization outcome",
      "confidence": 0.0,
      "evidence": "why this is suggested from the input"
    }}
  ]
}}

Rules:
- Use only resources and actions present in the input.
- Suggest at most 10 invariants.
- Use confidence between 0.0 and 1.0.
- These are only proposed rules for human confirmation.

Security model:
{json.dumps({"roles": roles, "resources": resources, "endpoints": endpoints}, ensure_ascii=False, indent=2)}
"""
