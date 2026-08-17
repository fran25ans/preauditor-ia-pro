"""Runtime configuration for authorized ProofSec dynamic validation."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

from proofsec.models import ProofSecIdentity, ProofSecResourceExample, ProofSecTarget


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def load_runtime_config(path: Path) -> dict:
    path = path.expanduser().resolve()
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("ProofSec runtime config must be a JSON object.")
    return data


def load_target(config: dict) -> ProofSecTarget:
    target = config.get("target") or {}
    parsed = urlparse(str(target.get("base_url", "")))
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target.base_url must be an absolute http(s) URL.")
    return ProofSecTarget(
        base_url=f"{parsed.scheme}://{parsed.netloc}",
        authorized=bool(target.get("authorized", False)),
        allow_non_local=bool(target.get("allow_non_local", False)),
        dry_run=bool(target.get("dry_run", False)),
        max_requests=max(int(target.get("max_requests", 20)), 0),
        timeout_seconds=max(float(target.get("timeout_seconds", 5)), 0.1),
        rate_limit_seconds=max(float(target.get("rate_limit_seconds", 0)), 0.0),
        allow_mutating=bool(target.get("allow_mutating", False)),
    )


def assert_target_authorized(target: ProofSecTarget) -> None:
    if not target.authorized:
        raise ValueError("Dynamic validation blocked: target.authorized must be true.")
    hostname = urlparse(target.base_url).hostname or ""
    if hostname not in LOCAL_HOSTS and not target.allow_non_local:
        raise ValueError("Dynamic validation blocked: only localhost targets are allowed by default.")


def load_identities(config: dict) -> dict[str, ProofSecIdentity]:
    identities: dict[str, ProofSecIdentity] = {}
    for name, raw in (config.get("identities") or {}).items():
        auth = raw.get("auth") or {}
        token_env = str(auth.get("token_env") or "").strip()
        token_value = os.environ.get(token_env, "") if token_env else str(auth.get("token", "") or "")
        identities[name] = ProofSecIdentity(
            name=name,
            role=str(raw.get("role", "")).upper(),
            auth_type=str(auth.get("type", "none")).lower(),
            token_env=token_env,
            token_value=token_value,
        )
    if not identities:
        raise ValueError("At least one test identity is required.")
    return identities


def load_resource_examples(config: dict) -> list[ProofSecResourceExample]:
    examples: list[ProofSecResourceExample] = []
    for name, raw in (config.get("resources") or {}).items():
        examples.append(
            ProofSecResourceExample(
                name=name,
                resource=str(raw.get("resource", "")),
                resource_id=str(raw.get("id", "")),
                owner_identity=str(raw.get("owner_identity", "")),
                sensitive_markers=tuple(str(item) for item in raw.get("sensitive_markers", [])),
            )
        )
    if not examples:
        raise ValueError("At least one resource example is required.")
    return examples


def redact_secret(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "****"
    return f"{value[:4]}****{value[-4:]}"


def auth_headers(identity: ProofSecIdentity) -> dict[str, str]:
    if identity.auth_type == "bearer":
        return {"Authorization": f"Bearer {identity.token_value}"}
    return {}


def redacted_headers(headers: dict[str, str]) -> dict[str, str]:
    redacted = dict(headers)
    if "Authorization" in redacted:
        scheme = redacted["Authorization"].split(" ", 1)[0]
        redacted["Authorization"] = f"{scheme} ****"
    if "Cookie" in redacted:
        redacted["Cookie"] = "****"
    return redacted
