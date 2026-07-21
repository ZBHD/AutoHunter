"""LLM 客户端：HTTP/TLS/错误分类，协议逻辑委托给 ProtocolAdapter。

24x7 健壮性：请求级超时 + TLS 自适应。不自动重试——重试由 LLMRouter 通过切换 provider 完成。
"""
from __future__ import annotations

import os
import logging
import re
from typing import Any
from urllib.parse import quote, quote_plus

import httpx

from app.config import LLMProviderConfig
from app.llm.protocols import (
    LLMResponse, ADAPTER_REGISTRY, ProtocolAdapter,
    OpenAIChatAdapter, AnthropicMessagesAdapter, OpenAIResponsesAdapter,
)
from app.llm.usage import record_usage

logger = logging.getLogger("autohunter.llm")

_SECRET_RE = re.compile(r"\b(sk-[A-Za-z0-9_-]{8,})\b")
_REQUEST_TIMEOUT = float(os.environ.get("LLM_REQUEST_TIMEOUT", "120"))


class LLMError(RuntimeError):
    """归一化 LLM 错误。"""

    def __init__(
        self,
        kind: str,
        message: str,
        original: Exception | None = None,
        *,
        status: int | None = None,
        code: str = "",
        detail: str = "",
    ):
        super().__init__(message)
        self.kind = kind
        self.original = original
        self.status = status
        self.code = code
        self.detail = detail

    def diagnostic(self) -> str:
        parts = [f"kind={self.kind}"]
        if self.status:
            parts.append(f"status={self.status}")
        if self.code:
            parts.append(f"code={self.code}")
        parts.append(f"message={super().__str__()}")
        if self.detail:
            parts.append(f"detail={self.detail}")
        return "；".join(parts)

    def __str__(self) -> str:
        return self.diagnostic()


def _sanitize_error_detail(
    text: str,
    limit: int = 1200,
    redact_values: tuple[str, ...] = (),
) -> str:
    for value in redact_values:
        if value:
            variants = {
                value,
                quote(value, safe=""),
                quote_plus(value, safe=""),
            }
            for variant in sorted(variants, key=len, reverse=True):
                text = (text or "").replace(variant, "<masked>")
    text = _SECRET_RE.sub("sk-<masked>", text or "")
    text = " ".join(text.split())
    return text[:limit]


def _classify_error(e: Exception, redact_values: tuple[str, ...] = ()) -> LLMError:
    response = getattr(e, "response", None)
    status = getattr(e, "status_code", None) or getattr(response, "status_code", None)
    code = getattr(e, "code", "") or ""
    raw = str(e)
    if response is not None:
        try:
            raw = f"{raw} {response.text[:500]}"
        except Exception:
            pass
    detail = _sanitize_error_detail(raw, redact_values=redact_values)
    safe_code = _sanitize_error_detail(str(code), redact_values=redact_values)
    text = f"{status or ''} {code} {raw}".lower()

    try:
        status_number = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_number = None

    if status_number is not None and status_number >= 500:
        return LLMError("upstream", "LLM 上游服务临时异常，请稍后重试。",
                        e, status=status, code=safe_code, detail=detail)
    if any(k in text for k in ("insufficient_quota", "quota", "billing", "余额", "额度", "balance")):
        return LLMError("quota", "LLM 额度不足或账户余额不足，请更换/充值模型 API Key 后重试。",
                        e, status=status, code=safe_code, detail=detail)
    if status_number in {401, 403} or any(k in text for k in (
        "unauthorized",
        "invalid api key",
        "incorrect api key",
        "permission_error",
        "forbidden",
        "api key 无效",
        "密钥无效",
        "鉴权失败",
        "未授权",
        "无权限",
    )):
        return LLMError("auth", "LLM API Key 无效或无权限，请检查任务配置或服务端 .env。",
                        e, status=status, code=safe_code, detail=detail)
    if status_number == 429 or any(k in text for k in ("rate limit", "too many requests", "限流")):
        return LLMError("rate_limit", "LLM 请求被限流，请稍后重试或降低并发。",
                        e, status=status, code=safe_code, detail=detail)
    if any(k in text for k in ("timeout", "timed out", "readtimeout", "connecttimeout", "超时")):
        return LLMError("timeout", "LLM 请求超时，可能是模型服务或网络临时不可用。",
                        e, status=status, code=safe_code, detail=detail)
    if any(k in text for k in ("connection", "network", "name resolution", "连接")):
        return LLMError("network", "LLM 网络连接失败，请检查服务器出网或代理。",
                        e, status=status, code=safe_code, detail=detail)
    if any(k in text for k in (
        "unknown variant",
        "failed to deserialize",
        "tools[",
        "unsupported model",
        "invalid tool schema",
    )):
        return LLMError(
            "protocol",
            "LLM Provider 协议或工具格式不兼容，请检查协议配置。",
            e,
            status=status,
            code=safe_code,
            detail=detail,
        )
    logger.warning("LLM unknown error: type=%s status=%s code=%s detail=%s",
                   type(e).__name__, status, safe_code, detail[:600])
    return LLMError("unknown", "LLM 调用失败：模型服务返回未知错误。",
                    e, status=status, code=safe_code, detail=detail)


class LLMClient:
    """封装单个 LLM provider 的 HTTP 通信。

    职责：HTTP client 管理（TLS 降级、超时） + 错误分类 + 委托协议适配器。
    不负责：协议逻辑（→ ProtocolAdapter）、重试（→ LLMRouter 切换 provider）。
    """

    def __init__(self, config: LLMProviderConfig | None = None, usage_key: str | None = None):
        self.config = config or LLMProviderConfig()
        self._usage_key = usage_key
        if not self.config.api_key:
            raise RuntimeError("缺少 LLM api_key")
        protocol_cls = ADAPTER_REGISTRY.get(self.config.protocol)
        if protocol_cls is None:
            raise RuntimeError(f"未知协议: {self.config.protocol}，支持: {list(ADAPTER_REGISTRY)}")
        self.adapter: ProtocolAdapter = protocol_cls()
        self._is_https = self.config.base_url.lower().startswith("https")
        self._insecure_tls = os.environ.get("LLM_INSECURE_TLS", "").strip() in ("1", "true", "True")
        self._client = self._build_http_client()

    def _build_http_client(self) -> httpx.Client:
        return httpx.Client(
            verify=not self._insecure_tls,
            timeout=_REQUEST_TIMEOUT,
        )

    def _maybe_downgrade_tls(self, exc: Exception) -> bool:
        if self._insecure_tls or not self._is_https:
            return False
        text = f"{exc} {getattr(exc, '__cause__', '')} {getattr(exc, '__context__', '')}".lower()
        tls_markers = (
            "certificate verify failed", "certificate_verify_failed",
            "self signed certificate", "self-signed certificate",
            "sslcertverificationerror", "ssl: certificate", "unable to get local issuer",
        )
        if any(m in text for m in tls_markers):
            self._insecure_tls = True
            self._client = httpx.Client(verify=False, timeout=_REQUEST_TIMEOUT)
            logger.warning("检测到 LLM 中转 TLS 证书校验失败，已自动降级为不校验证书重试")
            return True
        return False

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """单次 LLM 调用。不自动重试——失败直接抛异常，由 Router 接管。"""
        temp = self.config.temperature if temperature is None else temperature
        mt = int(max_tokens or os.environ.get("LLM_MAX_TOKENS", "4096"))

        payload = self.adapter.build_request(
            base_url=self.config.base_url,
            api_key=self.config.api_key,
            model=self.config.model,
            messages=messages,
            tools=tools,
            tool_choice=tool_choice,
            temperature=temp,
            max_tokens=mt,
        )

        try:
            resp = self._client.post(payload.url, headers=payload.headers, json=payload.body)
            # TLS 自适应
        except Exception as e:
            if self._maybe_downgrade_tls(e):
                try:
                    resp = self._client.post(payload.url, headers=payload.headers, json=payload.body)
                except Exception as e2:
                    raise _classify_error(e2, (self.config.api_key,)) from e2
            else:
                raise _classify_error(e, (self.config.api_key,)) from e

        try:
            resp.raise_for_status()
        except Exception as e:
            raise _classify_error(e, (self.config.api_key,)) from e

        data = resp.json()
        self._record_usage(data)
        return self.adapter.parse_response(data)

    def _record_usage(self, data: dict[str, Any]) -> None:
        usage = self.adapter.extract_usage(data)
        record_usage(
            self._usage_key,
            self.config.model,
            prompt_tokens=usage.prompt_tokens,
            completion_tokens=usage.completion_tokens,
            total_tokens=usage.total_tokens,
            cache_hit_tokens=usage.cache_hit_tokens,
            cache_miss_tokens=usage.cache_miss_tokens,
        )


# ── 保留导出兼容旧引用（外部包/测试可能 import 这些） ──
__all__ = ["LLMClient", "LLMError", "_classify_error"]
