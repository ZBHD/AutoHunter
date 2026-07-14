"""Local authentication/session material summarizer with secret redaction."""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from http.cookies import SimpleCookie
from typing import Any


_MAX_BODY = 500_000
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*\b")
_CSRF_RE = re.compile(
    r"(?:name|id|key)\s*[=:]\s*[\"']?([A-Za-z0-9_.-]*(?:csrf|xsrf|nonce)[A-Za-z0-9_.-]*)",
    re.IGNORECASE,
)


def _headers(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(key).strip().lower(): str(item).strip() for key, item in value.items()}


def _fingerprint(value: str) -> dict[str, Any]:
    return {
        "length": len(value),
        "sha256_prefix": hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:12],
    }


def _b64url_json(value: str) -> dict[str, Any] | None:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(decoded.decode("utf-8"))
        return parsed if isinstance(parsed, dict) else None
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _sensitive_claim_key(key: str) -> bool:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", key).lower()
    parts = set(filter(None, re.split(r"[^a-z0-9]+", separated)))
    return bool(parts & {
        "secret", "password", "passwd", "token", "key", "credential",
        "authorization", "cookie", "session",
    }) or separated in {"apikey", "accesskey", "refreshjwt"}


def _sanitize_claim(value: Any, key: str = "", depth: int = 0) -> Any:
    if key and _sensitive_claim_key(key):
        raw = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
        return _fingerprint(raw)
    if depth >= 5:
        return str(value)[:240]
    if isinstance(value, dict):
        return {
            str(child_key): _sanitize_claim(child_value, str(child_key), depth + 1)
            for child_key, child_value in list(value.items())[:40]
        }
    if isinstance(value, list):
        return [_sanitize_claim(item, depth=depth + 1) for item in value[:20]]
    if isinstance(value, str):
        return value[:240]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(value)[:240]


def _clip_claims(value: dict[str, Any] | None) -> dict[str, Any]:
    return _sanitize_claim(value) if isinstance(value, dict) else {}


def _jwt_summary(token: str) -> dict[str, Any] | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    header = _b64url_json(parts[0])
    payload = _b64url_json(parts[1])
    if header is None or payload is None:
        return None
    exp = payload.get("exp")
    expired = None
    if isinstance(exp, (int, float)):
        expired = exp < time.time()
    return {
        **_fingerprint(token),
        "header": _clip_claims(header),
        "payload": _clip_claims(payload),
        "expired": expired,
        "signature_verified": False,
    }


def _cookie_names(raw: str) -> list[dict[str, Any]]:
    cookie = SimpleCookie()
    try:
        cookie.load(raw)
    except Exception:
        return []
    return [
        {"name": name, **_fingerprint(morsel.value)}
        for name, morsel in list(cookie.items())[:40]
    ]


def _response_cookies(raw: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    values = raw if isinstance(raw, (list, tuple)) else [raw]
    for header in values:
        cookie = SimpleCookie()
        try:
            cookie.load(str(header or ""))
        except Exception:
            continue
        for name, morsel in list(cookie.items())[:40]:
            out.append({
                "name": name,
                **_fingerprint(morsel.value),
                "http_only": bool(morsel["httponly"]),
                "secure": bool(morsel["secure"]),
                "same_site": str(morsel["samesite"] or ""),
                "path": str(morsel["path"] or ""),
                "domain": str(morsel["domain"] or ""),
            })
            if len(out) >= 40:
                return out
    return out


def _authorization_summary(value: str) -> dict[str, Any]:
    if not value:
        return {}
    scheme, _, credential = value.partition(" ")
    credential = credential.strip()
    result = {"scheme": scheme.lower(), **_fingerprint(credential)}
    jwt = _jwt_summary(credential)
    if jwt is not None:
        result["jwt"] = jwt
    return result


def analyze_auth_material(
    request_headers: dict[str, Any] | None = None,
    response_headers: dict[str, Any] | None = None,
    set_cookie_headers: list[str] | None = None,
    body: str = "",
) -> dict[str, Any]:
    """Summarize auth/session material while excluding complete secret values."""
    request = _headers(request_headers)
    response = _headers(response_headers)
    if not request and not response and not set_cookie_headers and not body:
        return {"ok": False, "error": "至少提供请求头、响应头或正文之一"}
    if not isinstance(body, str):
        body = str(body)
    body = body[:_MAX_BODY]

    authorization = _authorization_summary(request.get("authorization", ""))
    request_cookies = _cookie_names(request.get("cookie", ""))
    response_cookies = _response_cookies(set_cookie_headers or response.get("set-cookie", ""))
    api_key_headers = sorted(
        name for name in request
        if any(marker in name for marker in ("api-key", "apikey", "access-key", "x-auth-token"))
    )[:20]
    csrf_candidates = list(dict.fromkeys(match.group(1) for match in _CSRF_RE.finditer(body)))[:30]

    jwt_candidates: list[dict[str, Any]] = []
    authorization_jwt = authorization.get("jwt") if isinstance(authorization, dict) else None
    if authorization_jwt:
        jwt_candidates.append({"source": "authorization", **authorization_jwt})
    for token in _JWT_RE.findall(body)[:10]:
        summary = _jwt_summary(token)
        if summary:
            jwt_candidates.append({"source": "body", **summary})

    return {
        "ok": True,
        "authorization": authorization,
        "request_cookies": request_cookies,
        "response_cookies": response_cookies,
        "api_key_headers": api_key_headers,
        "csrf_candidates": csrf_candidates,
        "jwt_candidates": jwt_candidates,
        "session_signals": {
            "has_authorization": bool(authorization),
            "has_request_cookie": bool(request_cookies),
            "sets_cookie": bool(response_cookies),
            "has_csrf_candidate": bool(csrf_candidates),
        },
        "guidance": (
            "输出已隐藏完整令牌，仅用于识别会话材料。JWT 只做结构解码，signature_verified=false；"
            "后续用 session_set 固化合法登录态，并以基线/候选最小请求验证实际鉴权边界。"
        ),
    }
