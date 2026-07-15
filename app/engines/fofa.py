"""FOFA 搜索引擎适配。"""
from __future__ import annotations

import base64
import os
from typing import Any

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine
from app.fofa.client import FofaError, classify_fofa_failure, redact_fofa_secrets

BASE = "https://fofa.info"

# 允许指向内网/私有的 FOFA base_url 白名单
_FOFA_ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("FOFA_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


def _structured_error(
    message: str,
    *,
    status: int | None = None,
    retry_after: Any = None,
    display_message: str | None = None,
    key: str | None = None,
) -> FofaError:
    safe_message = redact_fofa_secrets(message, key)
    safe_display_message = (
        redact_fofa_secrets(display_message, key) if display_message else None
    )
    kind, code, retry_seconds = classify_fofa_failure(
        message,
        status=status,
        retry_after=retry_after,
    )
    return FofaError(
        safe_display_message or safe_message,
        kind=kind,
        code=code,
        retry_after=retry_seconds,
    )


def _retry_after(response: Any) -> Any:
    headers = getattr(response, "headers", None)
    return headers.get("Retry-After") if headers is not None else None


def _error_message(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        message = data.get("errmsg") or data.get("message")
        if message:
            return str(message)
    return fallback


def _classification_message(message: str, data: Any) -> str:
    if not isinstance(data, dict):
        return message
    error_code = data.get("code") or data.get("errcode") or data.get("error_code")
    return f"[{error_code}] {message}" if error_code else message


@register_engine
class FofaEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "fofa"

    @property
    def display_name(self) -> str:
        return "FOFA"

    @property
    def env_key_name(self) -> str:
        return "FOFA"

    def get_default_base_url(self) -> str:
        return BASE

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
    ) -> EngineResult:
        if not api_key:
            raise FofaError("缺少 FOFA key")
        base = (base_url or BASE).rstrip("/")
        # SSRF 防护
        from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url
        try:
            assert_safe_outbound_url(
                f"{base}/api/v1/search/all", allow_extra_hosts=_FOFA_ALLOWED_HOSTS
            )
        except SsrfBlocked as e:
            raise FofaError(f"FOFA base_url 不被允许：{e}") from e

        fields = "host,ip,port,title,domain,org"
        params = {
            "key": api_key, "qbase64": _qbase64(query),
            "fields": fields, "page": str(page), "size": str(page_size), "full": "false",
        }
        try:
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.get(f"{base}/api/v1/search/all", params=params)
                if not 200 <= resp.status_code < 300:
                    raise _structured_error(
                        f"HTTP {resp.status_code}",
                        status=resp.status_code,
                        retry_after=_retry_after(resp),
                        display_message=f"FOFA 返回 HTTP {resp.status_code}",
                        key=api_key,
                    )
                try:
                    data = resp.json()
                except Exception:
                    message = str(getattr(resp, "text", ""))[:200]
                    raise _structured_error(
                        message,
                        status=resp.status_code,
                        retry_after=_retry_after(resp),
                        display_message=f"FOFA 返回非 JSON (HTTP {resp.status_code})",
                        key=api_key,
                    ) from None
        except FofaError:
            raise
        except httpx.HTTPError as e:
            message = f"{type(e).__name__}: {e}"
            raise _structured_error(
                message,
                display_message=f"FOFA 请求失败: {message}",
                key=api_key,
            ) from None

        if not isinstance(data, dict):
            raise _structured_error(
                "FOFA 返回无效 JSON 数据",
                status=resp.status_code,
                key=api_key,
            )
        if data.get("error"):
            errmsg = _error_message(data, "未知错误")
            raise _structured_error(
                _classification_message(errmsg, data),
                status=resp.status_code,
                retry_after=_retry_after(resp),
                display_message=f"FOFA 错误: {errmsg}",
                key=api_key,
            )

        return EngineResult(
            fields=fields.split(","),
            results=data.get("results", []),
            size=data.get("size", 0),
            page=page,
            engine="fofa",
        )
