"""Weighted LLM provider routing with request-local failover."""
from __future__ import annotations

import logging
import random
from dataclasses import dataclass
from typing import Any, Callable

from app.config import LLMProviderConfig
from app.llm.client import LLMClient, LLMError, _classify_error
from app.llm.protocols import LLMResponse
from app.llm.usage import UsageContext

logger = logging.getLogger("autohunter.llm.router")


@dataclass(frozen=True)
class ProviderFailure:
    provider_name: str
    error: LLMError


class AllProvidersExhaustedError(RuntimeError):
    """Every enabled provider failed during one chat request."""

    def __init__(self, failures: list[ProviderFailure]):
        self.failures = failures
        # Compatibility for callers that consumed the early prototype shape.
        self.errors = [(item.provider_name, str(item.error)) for item in failures]
        detail = "；".join(f"{item.provider_name}: {item.error}" for item in failures)
        super().__init__(f"所有 LLM provider 暂不可用 ({len(failures)} 个): {detail}")


class LLMRouter:
    """Select one provider by weight, then fail over in stable ring order."""

    def __init__(
        self,
        providers: list[LLMProviderConfig],
        usage_key: str | UsageContext | None = None,
        on_provider_disabled: Callable[[str, str], None] | None = None,
        client_factory: Callable[..., LLMClient] = LLMClient,
        rng: random.Random | None = None,
    ):
        if not providers:
            raise RuntimeError("未配置任何 LLM provider，请在设置中添加至少一个 LLM 提供商")
        self._usage_key = usage_key
        self._on_provider_disabled = on_provider_disabled
        self._rng = rng or random.Random()
        self._entries: list[tuple[LLMProviderConfig, LLMClient]] = []

        for source in providers:
            cfg = source.model_copy(deep=True)
            if not cfg.enabled or not cfg.api_key:
                continue
            try:
                client = client_factory(config=cfg, usage_key=self._usage_key)
            except Exception as exc:
                logger.warning(
                    "LLM provider '%s' 初始化失败: %s",
                    cfg.name,
                    self._redact(str(exc), cfg.api_key),
                )
                continue
            self._entries.append((cfg, client))

        if not self._entries:
            raise RuntimeError("没有已启用且配置有效 API Key 的 LLM provider")

    @property
    def enabled_providers(self) -> list[str]:
        return [cfg.name for cfg, _ in self._entries if cfg.enabled]

    def _weighted_start(self) -> int | None:
        candidates = [
            (index, cfg.weight)
            for index, (cfg, _client) in enumerate(self._entries)
            if cfg.enabled
        ]
        if not candidates:
            return None
        total = sum(weight for _index, weight in candidates)
        ticket = self._rng.randint(1, total)
        upto = 0
        for index, weight in candidates:
            upto += weight
            if ticket <= upto:
                return index
        return candidates[-1][0]

    def _request_order(self) -> list[int]:
        """Weight affects only the first provider; failover order stays stable."""
        start = self._weighted_start()
        if start is None:
            return []
        size = len(self._entries)
        return [
            index
            for offset in range(size)
            if self._entries[index := (start + offset) % size][0].enabled
        ]

    def _disable_provider(self, cfg: LLMProviderConfig, reason: str) -> None:
        if not cfg.enabled:
            return
        cfg.enabled = False
        logger.warning("LLM provider '%s' 已自动禁用: %s", cfg.name, reason)
        if not self._on_provider_disabled:
            return
        try:
            self._on_provider_disabled(cfg.name, reason)
        except Exception:
            logger.exception("持久化 LLM provider 自动禁用状态失败: %s", cfg.name)

    @staticmethod
    def _redact(text: str, api_key: str) -> str:
        if api_key:
            text = text.replace(api_key, "<masked>")
        return text

    @classmethod
    def _safe_error(cls, error: LLMError, api_key: str) -> LLMError:
        message = cls._redact(str(error.args[0]) if error.args else error.kind, api_key)
        detail = cls._redact(str(error.detail or ""), api_key)
        code = cls._redact(str(error.code or ""), api_key)
        return LLMError(
            error.kind,
            message,
            None,
            status=error.status,
            code=code,
            detail=detail,
        )

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: Any = "auto",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        failures: list[ProviderFailure] = []
        for index in self._request_order():
            cfg, client = self._entries[index]
            try:
                return client.chat(
                    messages=messages,
                    tools=tools,
                    tool_choice=tool_choice,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
            except Exception as exc:
                classified = (
                    exc
                    if isinstance(exc, LLMError)
                    else _classify_error(exc, (cfg.api_key,))
                )
                error = self._safe_error(classified, cfg.api_key)
                failures.append(ProviderFailure(cfg.name, error))
                if error.kind in {"auth", "quota"}:
                    message = str(error.args[0]) if error.args else error.kind
                    self._disable_provider(cfg, f"{error.kind}: {message}")

        raise AllProvidersExhaustedError(failures)


__all__ = [
    "AllProvidersExhaustedError",
    "LLMRouter",
    "ProviderFailure",
]
