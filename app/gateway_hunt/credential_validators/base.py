"""凭据验证器共用的传输、响应和结果契约。"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Literal, Protocol, runtime_checkable

import httpx

from app.gateway_hunt.profiles.response_matchers import WAF_MARKERS
from app.gateway_hunt.schemas import SecretArtifact


ValidationStatus = Literal[
    "valid",
    "invalid",
    "expired",
    "quota_exhausted",
    "permission_denied",
    "rate_limited",
    "network_error",
    "unknown",
]
DEFAULT_TIMEOUT = httpx.Timeout(15.0, connect=5.0)


@dataclass(frozen=True, slots=True)
class ValidationResponse:
    status_code: int
    content_type: str = "application/json"
    body: str = ""


@dataclass(frozen=True, slots=True)
class ValidationContext:
    base_url: str
    transport: object
    timeout: httpx.Timeout = field(
        default_factory=lambda: DEFAULT_TIMEOUT
    )


@dataclass(frozen=True, slots=True)
class ValidationResult:
    status: ValidationStatus
    provider: str
    detail: str = ""
    model_ids: tuple[str, ...] = ()
    request_count: int = 0
    request_json: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class CredentialValidator(Protocol):
    provider: str

    def validate(
        self,
        artifact: SecretArtifact,
        context: ValidationContext,
    ) -> ValidationResult: ...


def endpoint(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def request(
    transport: object,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_body: dict[str, object] | None = None,
    content_body: bytes | None = None,
    timeout: httpx.Timeout | None = None,
) -> ValidationResponse:
    try:
        requester = getattr(transport, "request")
        kwargs: dict[str, object] = {
            "headers": headers or {},
            "timeout": timeout or DEFAULT_TIMEOUT,
        }
        if content_body is not None:
            kwargs["content"] = content_body
        else:
            kwargs["json"] = json_body
        response = requester(method, url, **kwargs)
    except (httpx.HTTPError, OSError, TimeoutError) as exc:
        raise ConnectionError(str(exc)) from exc
    return coerce_response(response)


def coerce_response(response: object) -> ValidationResponse:
    if isinstance(response, ValidationResponse):
        return response
    status_code = int(getattr(response, "status_code"))
    headers = getattr(response, "headers", {})
    content_type = str(headers.get("content-type", "application/json"))
    body = getattr(response, "text", "")
    return ValidationResponse(status_code, content_type, str(body))


def parse_json(response: ValidationResponse) -> object | None:
    content_type = response.content_type.partition(";")[0].strip().lower()
    if content_type != "application/json" and not content_type.endswith("+json"):
        return None
    try:
        return json.loads(response.body)
    except (TypeError, ValueError):
        return None


def classify_response(response: ValidationResponse) -> ValidationStatus:
    body = response.body.strip().lower()
    if response.status_code == 401:
        return "invalid"
    if response.status_code == 403:
        return "permission_denied"
    if response.status_code == 404:
        return "unknown"
    if response.status_code == 429:
        return "rate_limited"
    if response.status_code in {408, 425} or response.status_code >= 500:
        return "network_error"
    if response.status_code in {402, 409}:
        return "quota_exhausted"
    if any(marker in body for marker in WAF_MARKERS):
        return "unknown"
    payload = parse_json(response)
    if isinstance(payload, dict) and "error" in payload:
        error = payload["error"]
        message = str(error).lower()
        if isinstance(error, dict):
            message = " ".join(str(value).lower() for value in error.values())
        if any(token in message for token in ("quota", "credit", "billing")):
            return "quota_exhausted"
        if any(token in message for token in ("expired", "revoked")):
            return "expired"
        if any(token in message for token in ("permission", "forbidden", "access")):
            return "permission_denied"
        if any(token in message for token in ("rate", "limit", "throttle")):
            return "rate_limited"
        return "invalid"
    return "unknown"


def parse_model_ids(response: ValidationResponse, provider: str) -> tuple[str, ...]:
    if not 200 <= response.status_code < 300:
        return ()
    payload = parse_json(response)
    if not isinstance(payload, dict) or "error" in payload:
        return ()
    records = payload.get("data")
    if not isinstance(records, list):
        records = payload.get("models")
    if not isinstance(records, list):
        return ()
    values: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        value = record.get("id") or record.get("name")
        if isinstance(value, str) and value.strip():
            values.append(value.strip().removeprefix("models/"))
    return tuple(dict.fromkeys(values))


class HttpxTransport:
    """生产环境默认传输；测试可注入只实现 request 的 FixtureTransport。"""

    def request(self, method: str, url: str, **kwargs: object) -> httpx.Response:
        timeout = kwargs.pop("timeout", DEFAULT_TIMEOUT)
        with httpx.Client(timeout=timeout, follow_redirects=False) as client:
            return client.request(method, url, **kwargs)


__all__ = [
    "CredentialValidator",
    "DEFAULT_TIMEOUT",
    "HttpxTransport",
    "ValidationContext",
    "ValidationResponse",
    "ValidationResult",
    "ValidationStatus",
    "classify_response",
    "endpoint",
    "parse_json",
    "parse_model_ids",
    "request",
]
