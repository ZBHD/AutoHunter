from __future__ import annotations

from dataclasses import dataclass
import logging
import re
from typing import Any, Callable

logger = logging.getLogger(__name__)

_SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9_-]{8,}"
    r"|Bearer\s+[A-Za-z0-9._-]{12,}"
    r"|(?i:api[_-]?key|token|secret|password|passwd|pwd|fofa[_-]?key)"
    r"\s*[=:]\s*[^\s'\"&]{3,})"
)


@dataclass(frozen=True)
class ToolDispatchOutcome:
    result: dict[str, Any]
    failed: bool
    retryable: bool = False
    error_kind: str = ""


def _safe_error_message(exc: Exception, limit: int = 400) -> str:
    text = _SECRET_RE.sub("<masked>", f"{type(exc).__name__}: {exc}")
    return text[:limit]


def dispatch_tool_safely(
    dispatch: Callable[[str, dict[str, Any]], dict[str, Any]],
    name: str,
    arguments: dict[str, Any],
    *,
    emit: Callable[..., None],
) -> ToolDispatchOutcome:
    try:
        result = dispatch(name, arguments)
        if not isinstance(result, dict):
            result = {"ok": True, "result": result}
        return ToolDispatchOutcome(result=result, failed=False)
    except Exception as exc:
        logger.exception("tool dispatch failed: %s", name)
        message = _safe_error_message(exc)
        emit("tool_exception", tool=name, error=message)
        result = {
            "ok": False,
            "error": {
                "kind": "tool_exception",
                "retryable": True,
                "message": message,
            },
        }
        return ToolDispatchOutcome(
            result=result,
            failed=True,
            retryable=True,
            error_kind="tool_exception",
        )
