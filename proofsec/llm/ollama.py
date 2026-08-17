"""Ollama provider for local ProofSec LLM tasks."""

from __future__ import annotations

import json
import re
from urllib import error as urlerror
from urllib import request as urlrequest

from .providers import LLMError


class OllamaProvider:
    name = "ollama"

    def __init__(self, base_url: str = "http://127.0.0.1:11434", model: str = "llama3.1") -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    def chat_json(self, system: str, user: str, timeout: int = 60) -> dict:
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        request = urlrequest.Request(
            self.base_url + "/api/chat",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlrequest.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8"))
        except (OSError, urlerror.URLError, json.JSONDecodeError) as exc:
            raise LLMError(f"Ollama request failed: {exc}") from exc

        content = data.get("message", {}).get("content", "")
        parsed = parse_json_object(content)
        if parsed is None:
            raise LLMError("Ollama did not return a valid JSON object.")
        return parsed


def parse_json_object(text: str) -> dict | None:
    text = text.strip()
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, flags=re.DOTALL)
        if not match:
            return None
        try:
            parsed = json.loads(match.group(0))
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
