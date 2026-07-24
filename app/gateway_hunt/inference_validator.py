"""固定预算的最小模型推理验证。"""
from __future__ import annotations

import secrets

from app.gateway_hunt.credential_validators.base import (
    DEFAULT_TIMEOUT,
    ValidationResponse,
    ValidationResult,
    ValidationStatus,
    classify_response,
    endpoint,
    parse_json,
    request,
)
import httpx


def _valid_chat_response(response: ValidationResponse) -> bool:
    payload = parse_json(response)
    if not isinstance(payload, dict) or "error" in payload:
        return False
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        return False
    first = choices[0]
    if not isinstance(first, dict):
        return False
    message = first.get("message")
    return isinstance(message, dict) and isinstance(message.get("content"), str)


def validate_minimal_inference(
    *,
    base_url: str,
    model: str,
    transport: object,
    api_key: str | None = None,
    path: str = "/v1/chat/completions",
    headers: dict[str, str] | None = None,
    timeout: httpx.Timeout = DEFAULT_TIMEOUT,
) -> ValidationResult:
    nonce = secrets.token_hex(8)
    request_json: dict[str, object] = {
        "model": model,
        "messages": [{"role": "user", "content": f"Reply OK. nonce={nonce}"}],
        "stream": False,
        "max_tokens": 1,
    }
    request_headers = {"Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    if api_key and "Authorization" not in request_headers:
        request_headers["Authorization"] = f"Bearer {api_key}"
    try:
        response = request(
            transport,
            "POST",
            endpoint(base_url, path),
            headers=request_headers,
            json_body=request_json,
            timeout=timeout,
        )
    except ConnectionError as exc:
        return ValidationResult(
            status="network_error",
            provider="",
            detail=str(exc),
            request_count=1,
            request_json=request_json,
        )
    if 200 <= response.status_code < 300 and _valid_chat_response(response):
        return ValidationResult(
            status="valid",
            provider="",
            detail="minimal OpenAI chat response matched",
            request_count=1,
            request_json=request_json,
        )
    status: ValidationStatus = classify_response(response)
    return ValidationResult(
        status=status,
        provider="",
        detail="minimal inference response did not match a valid chat result",
        request_count=1,
        request_json=request_json,
    )


__all__ = ["validate_minimal_inference"]
