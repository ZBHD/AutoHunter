"""网关 URL、同源跳转和挂载路径的稳定归一化。"""
from __future__ import annotations

import hashlib
import posixpath
import re
from urllib.parse import SplitResult, urljoin, urlsplit


def normalize_mount_path(path: str) -> str:
    raw = str(path or "").split("?", 1)[0].split("#", 1)[0].replace("\\", "/")
    collapsed = re.sub(r"/+", "/", f"/{raw.lstrip('/')}")
    normalized = posixpath.normpath(collapsed)
    if normalized in {"", ".", "/"}:
        return "/"
    return "/" + normalized.strip("/")


def _parsed_http_url(value: str) -> SplitResult:
    raw = str(value or "").strip()
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("gateway URL has an invalid authority") from exc
    scheme = parsed.scheme.lower()
    if (
        scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("gateway URL must be absolute HTTP(S) without credentials")
    return parsed


def _normalized_host(parsed: SplitResult) -> str:
    host = (parsed.hostname or "").lower()
    if ":" in host:
        return f"[{host}]"
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("gateway URL contains an invalid hostname") from exc


def _effective_port(parsed: SplitResult) -> int:
    return parsed.port or (443 if parsed.scheme.lower() == "https" else 80)


def _same_origin(left: SplitResult, right: SplitResult) -> bool:
    return (
        left.scheme.lower(),
        _normalized_host(left),
        _effective_port(left),
    ) == (
        right.scheme.lower(),
        _normalized_host(right),
        _effective_port(right),
    )


def normalize_base_url(
    base_url: str,
    *,
    redirect_url: str | None = None,
    mount_path: str | None = None,
) -> str:
    parsed = _parsed_http_url(base_url)
    selected_path = parsed.path

    if redirect_url:
        redirected = _parsed_http_url(urljoin(base_url, redirect_url))
        if _same_origin(parsed, redirected):
            selected_path = redirected.path
    if mount_path is not None:
        selected_path = mount_path

    scheme = parsed.scheme.lower()
    host = _normalized_host(parsed)
    port = parsed.port
    default_port = 443 if scheme == "https" else 80
    authority = host if port is None or port == default_port else f"{host}:{port}"
    path = normalize_mount_path(selected_path)
    suffix = "" if path == "/" else path
    return f"{scheme}://{authority}{suffix}"


def origin_key(
    base_url: str,
    *,
    redirect_url: str | None = None,
    mount_path: str | None = None,
) -> str:
    return normalize_base_url(
        base_url,
        redirect_url=redirect_url,
        mount_path=mount_path,
    )


def gateway_target_source(normalized_origin_key: str) -> str:
    canonical = origin_key(normalized_origin_key)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
    return f"gw:llm:{digest}"


__all__ = [
    "gateway_target_source",
    "normalize_base_url",
    "normalize_mount_path",
    "origin_key",
]
