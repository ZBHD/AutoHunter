"""LLMRouter: weighted random provider selection with chain failover."""
from __future__ import annotations

import logging
import random
from typing import Any

from app.config import LLMProviderConfig
from app.llm.client import LLMClient
from app.llm.protocols import LLMResponse, ADAPTER_REGISTRY

logger = logging.getLogger("autohunter.llm.router")


class AllProvidersExhaustedError(RuntimeError):
    """所有 LLM provider 均已尝试但全部失败。"""

    def __init__(self, errors: list[tuple[str, str]]):
        self.errors = errors  # [(provider_name, error_message), ...]
        detail = "；".join(f"{name}: {msg}" for name, msg in errors)
        super().__init__(f"所有 LLM provider 暂不可用 ({len(errors)} 个): {detail}")


class LLMRouter:
    """多 provider 加权池 + 故障链式切换。

    用法：
        router = LLMRouter(providers, usage_key=task_id)
        response = router.chat(messages, tools=[...])
    """

    def __init__(
        self,
        providers: list[LLMProviderConfig],
        usage_key: str | None = None,
        on_provider_disabled: callable | None = None,
    ):
        if not providers:
            raise RuntimeError("未配置任何 LLM provider，请在设置中添加至少一个 LLM 提供商")
        self._usage_key = usage_key
        self._on_provider_disabled = on_provider_disabled
        # Build (config, client) pairs for enabled providers
        self._entries: list[tuple[LLMProviderConfig, LLMClient]] = []
        for cfg in providers:
            if not cfg.api_key:
                logger.warning("LLM provider '%s' 未配置 api_key，已跳过", cfg.name)
                continue
            try:
                client = LLMClient(config=cfg, usage_key=self._usage_key)
                self._entries.append((cfg, client))
            except Exception as exc:
                logger.warning("LLM provider '%s' 初始化失败: %s", cfg.name, exc)
        if not self._entries:
            raise RuntimeError("所有 LLM provider 初始化失败或无有效 api_key")

    @property
    def enabled_providers(self) -> list[str]:
        return [cfg.name for cfg, _ in self._entries if cfg.enabled]

    def _weighted_select(self, tried_indices: set[int]) -> int | None:
        """从 enabled 且未尝试过的 provider 中加权随机选一个。"""
        candidates = [
            (i, cfg.weight)
            for i, (cfg, _) in enumerate(self._entries)
            if cfg.enabled and i not in tried_indices
        ]
        if not candidates:
            return None
        total = sum(w for _, w in candidates)
        r = random.randint(1, total)
        cumulative = 0
        for idx, w in candidates:
            cumulative += w
            if r <= cumulative:
                return idx
        return candidates[-1][0]  # fallback

    def _disable_provider(self, cfg: LLMProviderConfig, reason: str) -> None:
        """将 provider 标记为 disabled（auth/quota 错误）并通知上层。"""
        cfg.enabled = False
        logger.warning("LLM provider '%s' 已自动禁用: %s", cfg.name, reason)
        if self._on_provider_disabled:
            try:
                self._on_provider_disabled(cfg.name, reason)
            except Exception:
                pass

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        tool_choice: str = "auto",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> LLMResponse:
        """发送 LLM 请求，失败时自动切换 provider 重试。"""
        tried: set[int] = set()
        errors: list[tuple[str, str]] = []
        while True:
            idx = self._weighted_select(tried)
            if idx is None:
                break
            cfg, client = self._entries[idx]
            tried.add(idx)
            try:
                result = client.chat(
                    messages=messages,
                    tools=tools,
                    tool_choice=tool_choice,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return LLMResponse(content=result.content, tool_calls=result.tool_calls)
            except Exception as exc:
                # Reuse LLMClient's error classification
                from app.llm.client import LLMError, _classify_error
                err = _classify_error(exc) if not isinstance(exc, LLMError) else exc
                kind = getattr(err, "kind", "unknown")
                msg = str(err)
                errors.append((cfg.name, msg))
                if kind in ("auth", "quota"):
                    self._disable_provider(cfg, f"{kind}: {msg}")
                # Continue to next provider
        raise AllProvidersExhaustedError(errors)
