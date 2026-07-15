"""FOFA 官方 API 客户端（移植自项目已有 fofa-team 逻辑）。"""
from __future__ import annotations

import base64
import os
import re
from typing import Any
from urllib.parse import quote, quote_plus

import httpx

from app.fofa.endpoints import request_async
from app.tools.netguard import SsrfBlocked

BASE = "https://fofa.info"

# 允许指向内网/私有的 FOFA base_url 白名单（私有部署/镜像场景，逗号分隔的 host）。
# 默认空——即默认阻断把携带 FOFA key 的请求发往内网/云元数据。
_FOFA_ALLOWED_HOSTS = {
    h.strip().lower()
    for h in os.environ.get("FOFA_ALLOWED_HOSTS", "").split(",")
    if h.strip()
}


class FofaError(Exception):
    """带稳定分类信息的 FOFA 调用错误。"""

    def __init__(
        self,
        message: str,
        kind: str | bool = "transient",
        code: str = "",
        retry_after: int | None = None,
        *,
        account_error: bool | None = None,
    ):
        super().__init__(message)
        # 兼容旧调用方式 FofaError(message, True) 和 account_error=True。
        if isinstance(kind, bool):
            kind = "auth" if kind else "transient"
        if account_error:
            kind = "auth"
        self.kind = kind
        self.code = str(code or "")
        self.retry_after = retry_after

    @property
    def account_error(self) -> bool:
        return self.kind == "auth"


_FOFA_DAILY_LIMIT_MARKERS = (
    "820041", "daily quota", "daily limit", "daily request limit",
    "daily search limit", "每日额度", "每日配额", "每日限额", "当日额度",
    "当日配额", "今日额度", "今日配额", "每日",
)
_FOFA_RATE_LIMIT_MARKERS = (
    "q3005", "too many", "rate limit", "ratelimit",
    "request frequency", "requests too frequent", "请求太频繁", "访问太频繁",
    "请求频率", "频率限制", "操作频繁",
)
_FOFA_AUTH_ERROR_MARKERS = (
    "820000", "820001", "-700", "账号无效", "账号已过期", "账号过期", "过期",
    "无效的fofa", "无效的 fofa", "f点不足", "f币不足", "余额不足", "配额",
    "权限不足", "没有权限", "无权限", "会员", "account invalid", "invalid key",
    "expired", "insufficient", "quota", "permission", "unauthorized", "forbidden",
)
_FOFA_KNOWN_CODES = ("820041", "820000", "820001", "-700")
_FOFA_Q_CODE_RE = re.compile(r"(?<![a-z0-9])(q\d+)(?![a-z0-9])", re.IGNORECASE)
_FOFA_BRACKETED_CODE_RE = re.compile(r"\[\s*(-?\d{3,})\s*\]")
_FOFA_NAMED_CODE_RE = re.compile(
    r"(?:error[_ -]?code|errcode|code)\s*[:=]\s*['\"]?(-?[a-z]?\d+)",
    re.IGNORECASE,
)


def _normalise_retry_after(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        seconds = int(float(value))
    except (TypeError, ValueError):
        return None
    return seconds if seconds >= 0 else None


def _extract_error_code(message: str, status: int | None) -> str:
    q_code = _FOFA_Q_CODE_RE.search(message)
    if q_code:
        return q_code.group(1).upper()
    bracketed_code = _FOFA_BRACKETED_CODE_RE.search(message)
    if bracketed_code:
        return bracketed_code.group(1)
    named_code = _FOFA_NAMED_CODE_RE.search(message)
    if named_code:
        return named_code.group(1).upper()
    for code in _FOFA_KNOWN_CODES:
        if code in message:
            return code
    if status is not None and not 200 <= status < 300:
        return str(status)
    return ""


def classify_fofa_failure(
    message: str,
    *,
    status: int | None = None,
    retry_after: Any = None,
) -> tuple[str, str, int | None]:
    """将 FOFA/HTTP 失败归一为 (kind, code, retry_after)。"""
    text = str(message or "")
    lowered = text.lower()
    code = _extract_error_code(lowered, status)
    retry_seconds = _normalise_retry_after(retry_after)

    # 820041 和每日额度文案也包含 quota，必须先于通用账号额度标记。
    if any(marker in lowered for marker in _FOFA_DAILY_LIMIT_MARKERS):
        return "daily_limit", code, retry_seconds if retry_seconds is not None else 3600
    if status == 429:
        return "rate_limit", code, retry_seconds
    if status in {401, 403}:
        return "auth", code, None
    if status is not None and not 200 <= status < 300:
        return "transient", code, retry_seconds
    if any(marker in lowered for marker in _FOFA_RATE_LIMIT_MARKERS):
        return "rate_limit", code, retry_seconds
    if any(marker in lowered for marker in _FOFA_AUTH_ERROR_MARKERS):
        return "auth", code, None
    return "transient", code, retry_seconds


def extract_fofa_error(data: Any, fallback: str) -> tuple[str, str]:
    """提取用于分类的完整错误文本和用于展示的原始错误文案。"""
    if isinstance(data, dict):
        message = fallback
        for key in ("errmsg", "message"):
            value = data.get(key)
            if value:
                message = str(value)
                break
        else:
            if isinstance(data.get("error"), str) and data["error"]:
                message = str(data["error"])
        error_code = data.get("code") or data.get("errcode") or data.get("error_code")
        classification_message = f"[{error_code}] {message}" if error_code else message
        return classification_message, message
    if isinstance(data, str) and data:
        message = data[:200]
        return message, message
    return fallback, fallback


def extract_fofa_response_failure(response: Any) -> str:
    """尽力从非 2xx 响应提取分类信号；调用方应使用固定展示文案。"""
    status = int(getattr(response, "status_code", 0) or 0)
    fallback = f"HTTP {status}"
    try:
        data = response.json()
    except Exception:
        text = str(getattr(response, "text", ""))[:200]
        return text or fallback
    classification_message, _display_message = extract_fofa_error(data, fallback)
    return classification_message


def _retry_after(response: Any) -> Any:
    headers = getattr(response, "headers", None)
    return headers.get("Retry-After") if headers is not None else None


def redact_fofa_secrets(message: Any, key: str | None) -> str:
    """移除异常消息中的明文和常见 URL 编码形式的 FOFA key。"""
    text = str(message or "")
    if not key:
        return text
    candidates = {
        key,
        quote(key, safe=""),
        quote_plus(key, safe=""),
    }
    for candidate in sorted((item for item in candidates if item), key=len, reverse=True):
        if candidate == key:
            text = text.replace(candidate, "[REDACTED]")
        else:
            text = re.sub(re.escape(candidate), "[REDACTED]", text, flags=re.IGNORECASE)
    return text


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


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


async def search(key: str, query: str, page: int = 1, size: int = 100,
                 fields: str = "host,ip,port,title,domain,org",
                 base_url: str | None = None) -> dict[str, Any]:
    """调用 FOFA search/all，返回 {results: [...], size, page}。

    base_url 留空则用官方 https://fofa.info；可传入私有部署/镜像/代理网关地址。
    """
    if not key:
        raise FofaError("缺少 FOFA key")
    base = (base_url or BASE).rstrip("/")
    params = {
        "key": key, "qbase64": _qbase64(query),
        "fields": fields, "page": str(page), "size": str(size), "full": "false",
    }
    try:
        result = await request_async(
            key,
            base,
            purpose="search",
            params=params,
            timeout=30,
            allow_extra_hosts=_FOFA_ALLOWED_HOSTS,
        )
        if result.category == "network":
            error = result.error
            message = f"{type(error).__name__}: {error}" if error else "网络错误"
            raise _structured_error(
                message,
                display_message=f"FOFA 请求失败: {message}",
                key=key,
            ) from None
        resp = result.response
        if resp is None:
            raise _structured_error("FOFA 返回为空", key=key)
        if not 200 <= resp.status_code < 300:
            raise _structured_error(
                extract_fofa_response_failure(resp),
                status=resp.status_code,
                retry_after=_retry_after(resp),
                display_message=f"FOFA 返回 HTTP {resp.status_code}",
                key=key,
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
                key=key,
            ) from None
    except SsrfBlocked as exc:
        safe_message = redact_fofa_secrets(str(exc), key)
        exc.args = (safe_message,)
        raise FofaError(f"FOFA base_url 不被允许：{safe_message}") from None
    except FofaError:
        raise
    except httpx.HTTPError as e:
        message = f"{type(e).__name__}: {e}"
        raise _structured_error(message, display_message=f"FOFA 请求失败: {message}", key=key) from None
    if not isinstance(data, dict):
        raise _structured_error(
            "FOFA 返回无效 JSON 数据",
            status=resp.status_code,
            key=key,
        )
    if data.get("error"):
        failure_message, errmsg = extract_fofa_error(data, "未知错误")
        raise _structured_error(
            failure_message,
            status=resp.status_code,
            retry_after=_retry_after(resp),
            display_message=f"FOFA 错误: {errmsg}",
            key=key,
        )
    return {
        "fields": fields.split(","),
        "results": data.get("results", []),
        "size": data.get("size", 0),
        "page": page,
    }


async def get_userinfo(key: str, base_url: str | None = None) -> dict[str, Any]:
    """调用 FOFA 官方账号信息接口验证 Key，不消耗搜索额度。"""
    if not key:
        raise FofaError("缺少 FOFA key", account_error=True)
    try:
        result = await request_async(
            key,
            base_url or BASE,
            purpose="info",
            params={"key": key},
            timeout=15,
            allow_extra_hosts=_FOFA_ALLOWED_HOSTS,
        )
        if result.category == "network":
            error = result.error
            message = f"{type(error).__name__}: {error}" if error else "网络错误"
            raise _structured_error(
                message,
                display_message=f"FOFA 请求失败: {message}",
                key=key,
            ) from None
        response = result.response
        if response is None:
            raise _structured_error("FOFA 返回为空", key=key)
        if not 200 <= response.status_code < 300:
            raise _structured_error(
                extract_fofa_response_failure(response),
                status=response.status_code,
                retry_after=_retry_after(response),
                display_message=f"FOFA 返回 HTTP {response.status_code}",
                key=key,
            )
        try:
            data = response.json()
        except Exception as exc:
            message = str(getattr(response, "text", ""))[:200]
            raise _structured_error(
                message,
                status=response.status_code,
                retry_after=_retry_after(response),
                display_message="FOFA 账号接口返回非 JSON",
                key=key,
            ) from None
    except SsrfBlocked as exc:
        safe_message = redact_fofa_secrets(str(exc), key)
        exc.args = (safe_message,)
        raise FofaError(f"FOFA base_url 不被允许：{safe_message}") from None
    except FofaError:
        raise
    except httpx.HTTPError as exc:
        message = type(exc).__name__
        raise _structured_error(
            message,
            display_message=f"FOFA 请求失败: {message}",
            key=key,
        ) from None

    if not isinstance(data, dict):
        raise _structured_error(
            "FOFA 账号接口返回无效 JSON 数据",
            status=response.status_code,
            key=key,
        )
    if data.get("error"):
        failure_message, message = extract_fofa_error(data, "账号不可用")
        raise _structured_error(
            failure_message,
            status=response.status_code,
            retry_after=_retry_after(response),
            display_message=f"FOFA 错误: {message}",
            key=key,
        )
    return data
