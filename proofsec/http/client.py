"""Safe HTTP client used by ProofSec dynamic validation."""

from __future__ import annotations

from urllib import error as urlerror
from urllib import request as urlrequest

from proofsec.models import HttpExchangeEvidence, ProofSecTarget
from proofsec.runtime_config import redacted_headers


MAX_ANALYSIS_BODY_BYTES = 1024 * 1024


def redact_body(body: str) -> str:
    trimmed = body[:2000]
    for marker in ("token", "password", "secret", "api_key", "authorization"):
        trimmed = trimmed.replace(marker, f"{marker[:2]}****")
        trimmed = trimmed.replace(marker.upper(), f"{marker[:2].upper()}****")
    return trimmed


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
            response_body="",
        )
    request = urlrequest.Request(url, headers=safe_headers, method=method)
    try:
        with urlrequest.urlopen(request, timeout=target.timeout_seconds) as response:
            body = response.read(MAX_ANALYSIS_BODY_BYTES).decode("utf-8", errors="replace")
            return HttpExchangeEvidence(
                method=method,
                url=url,
                request_headers=redacted_headers(safe_headers),
                status=int(response.status),
                response_headers=redacted_headers(dict(response.headers.items())),
                response_body_preview=redact_body(body),
                response_body=body,
            )
    except urlerror.HTTPError as exc:
        try:
            body = exc.read(MAX_ANALYSIS_BODY_BYTES).decode("utf-8", errors="replace")
            return HttpExchangeEvidence(
                method=method,
                url=url,
                request_headers=redacted_headers(safe_headers),
                status=int(exc.code),
                response_headers=redacted_headers(dict(exc.headers.items())),
                response_body_preview=redact_body(body),
                response_body=body,
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
            response_body="",
            error=str(exc),
        )

