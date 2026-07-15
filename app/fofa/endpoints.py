"""Shared FOFA endpoint resolution and HTTP transport."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

import httpx

from app.tools import netguard

_PURPOSE_PATHS = {
    "info": "/api/v1/info/my",
    "search": "/api/v1/search/all",
}
_DAILY_MARKERS = (
    "820041",
    "daily quota",
    "daily limit",
    "daily request limit",
    "每日额度",
    "每日配额",
    "每日限额",
    "每日",
)


@dataclass(frozen=True)
class FofaEndpointCandidate:
    url: str
    mode: str


@dataclass(frozen=True)
class FofaTransportResult:
    """Response plus the endpoint selected by the compatibility transport."""

    response: Any | None
    resolved_url: str
    endpoint_mode: str
    http_status: int | None
    category: str
    error: BaseException | None = None

    @property
    def status_code(self) -> int | None:
        return self.http_status


FofaEndpointResult = FofaTransportResult


def standard_endpoint(base_url: str, *, purpose: str) -> str:
    """Build the same-origin standard endpoint for ``info`` or ``search``."""
    try:
        path = _PURPOSE_PATHS[purpose]
    except KeyError as exc:
        raise ValueError(f"unsupported FOFA endpoint purpose: {purpose}") from exc
    parsed = urlsplit(str(base_url or "").strip().rstrip("/"))
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("FOFA base_url must be absolute")
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def resolve_endpoint(base_url: str, *, purpose: str) -> tuple[str, str]:
    """Return ``(url, mode)`` for a configured FOFA base URL."""
    raw = str(base_url or "").strip()
    parsed = urlsplit(raw)
    if parsed.path in {"", "/"}:
        return standard_endpoint(raw.rstrip("/"), purpose=purpose), "root"
    if parsed.path == "/api.php":
        return raw, "api_php"
    if parsed.path in _PURPOSE_PATHS.values():
        return raw, "known"
    return raw, "exact"


def endpoint_candidates(base_url: str, *, purpose: str) -> tuple[FofaEndpointCandidate, ...]:
    """Return immutable exact/fallback candidates for a configured endpoint."""
    initial_url, mode = resolve_endpoint(base_url, purpose=purpose)
    initial = FofaEndpointCandidate(initial_url, mode)
    if mode in {"root", "known"}:
        return (initial,)
    return (
        FofaEndpointCandidate(initial.url, "exact"),
        FofaEndpointCandidate(standard_endpoint(base_url, purpose=purpose), "fallback"),
    )


def _response_payload(response: Any) -> str:
    try:
        payload = response.json()
    except Exception:
        return str(getattr(response, "text", "") or "")[:400]
    if isinstance(payload, Mapping):
        parts = [payload.get(key) for key in ("code", "errcode", "error_code", "errmsg", "message", "error")]
        return " ".join(str(item) for item in parts if item is not None)
    return str(payload)[:400]


def classify_response(response: Any) -> str:
    status = int(getattr(response, "status_code", 0) or 0)
    text = _response_payload(response).lower()
    if status in {404, 405}:
        return "endpoint"
    if any(marker in text for marker in _DAILY_MARKERS):
        return "daily_limit"
    if "q3005" in text or "too many" in text or "rate limit" in text:
        return "rate_limit"
    if status == 401 or status == 403:
        return "auth"
    if status == 429:
        return "rate_limit"
    if "invalid key" in text or "unauthorized" in text or "forbidden" in text:
        return "auth"
    if 200 <= status < 300:
        try:
            payload = response.json()
        except Exception:
            payload = None
        if isinstance(payload, Mapping) and payload.get("error"):
            return "upstream_error"
        return "ok"
    if 400 <= status < 500:
        return "http_4xx"
    if status >= 500:
        return "http_5xx"
    return "http_error"


def _request_kwargs(key: str, params: Mapping[str, Any] | None, headers: Mapping[str, str] | None, json_body: Any) -> dict[str, Any]:
    request_params = dict(params or {})
    if key:
        request_params["key"] = key
    kwargs: dict[str, Any] = {"params": request_params}
    if headers:
        kwargs["headers"] = dict(headers)
    if json_body is not None:
        kwargs["json"] = json_body
    return kwargs


def _safe_url(url: str, allow_extra_hosts: set[str] | None) -> None:
    netguard.assert_safe_outbound_url(url, allow_extra_hosts=allow_extra_hosts)


def _sync_call(client: Any, method: str, url: str, kwargs: dict[str, Any]) -> Any:
    return client.get(url, **kwargs) if method == "GET" else client.post(url, **kwargs)


async def _async_call(client: Any, method: str, url: str, kwargs: dict[str, Any]) -> Any:
    return await (client.get(url, **kwargs) if method == "GET" else client.post(url, **kwargs))


def _result(response: Any, url: str, mode: str) -> FofaTransportResult:
    return FofaTransportResult(
        response=response,
        resolved_url=url,
        endpoint_mode=mode,
        http_status=int(getattr(response, "status_code", 0) or 0),
        category=classify_response(response),
    )


def request_sync(
    key: str = "",
    base_url: str | None = None,
    *,
    purpose: str,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: Any = None,
    timeout: float = 30,
    allow_extra_hosts: set[str] | None = None,
) -> FofaTransportResult:
    """Send one FOFA request with compatibility endpoint fallback."""
    if base_url is None:
        base_url, key = key, ""
    candidates = endpoint_candidates(base_url, purpose=purpose)
    initial = candidates[0]
    kwargs = _request_kwargs(key, params, headers, json_body)
    try:
        with httpx.Client(timeout=timeout) as client:
            _safe_url(initial.url, allow_extra_hosts)
            response = _sync_call(client, "GET", initial.url, kwargs)
            category = classify_response(response)
            if initial.mode == "exact" and category == "endpoint" and int(response.status_code) == 405:
                _safe_url(initial.url, allow_extra_hosts)
                response = _sync_call(client, "POST", initial.url, kwargs)
                category = classify_response(response)
            if len(candidates) > 1 and category == "endpoint":
                fallback = candidates[1]
                _safe_url(fallback.url, allow_extra_hosts)
                response = _sync_call(client, "GET", fallback.url, kwargs)
                return _result(response, fallback.url, fallback.mode)
            return _result(response, initial.url, initial.mode)
    except netguard.SsrfBlocked:
        raise
    except httpx.HTTPError as exc:
        return FofaTransportResult(None, initial.url, initial.mode, None, "network", error=exc)


async def request_async(
    key: str = "",
    base_url: str | None = None,
    *,
    purpose: str,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: Any = None,
    timeout: float = 30,
    allow_extra_hosts: set[str] | None = None,
) -> FofaTransportResult:
    """Async counterpart of :func:`request_sync` using the same resolution rules."""
    if base_url is None:
        base_url, key = key, ""
    candidates = endpoint_candidates(base_url, purpose=purpose)
    initial = candidates[0]
    kwargs = _request_kwargs(key, params, headers, json_body)
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            _safe_url(initial.url, allow_extra_hosts)
            response = await _async_call(client, "GET", initial.url, kwargs)
            category = classify_response(response)
            if initial.mode == "exact" and category == "endpoint" and int(response.status_code) == 405:
                _safe_url(initial.url, allow_extra_hosts)
                response = await _async_call(client, "POST", initial.url, kwargs)
                category = classify_response(response)
            if len(candidates) > 1 and category == "endpoint":
                fallback = candidates[1]
                _safe_url(fallback.url, allow_extra_hosts)
                response = await _async_call(client, "GET", fallback.url, kwargs)
                return _result(response, fallback.url, fallback.mode)
            return _result(response, initial.url, initial.mode)
    except netguard.SsrfBlocked:
        raise
    except httpx.HTTPError as exc:
        return FofaTransportResult(None, initial.url, initial.mode, None, "network", error=exc)


request_fofa_sync = request_sync
request_fofa_async = request_async


__all__ = [
    "FofaEndpointCandidate",
    "FofaEndpointResult",
    "FofaTransportResult",
    "classify_response",
    "endpoint_candidates",
    "request_async",
    "request_sync",
    "request_fofa_async",
    "request_fofa_sync",
    "resolve_endpoint",
    "standard_endpoint",
]
