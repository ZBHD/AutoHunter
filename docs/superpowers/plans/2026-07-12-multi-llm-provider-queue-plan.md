# Multi-LLM Provider Queue Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace single-LLM configuration with a weighted multi-provider pool supporting automatic failover across OpenAI Chat, Anthropic Messages, and OpenAI Responses protocols.

**Architecture:** LLMRouter holds a list of provider+LLMClient pairs, selects by weighted random, and chains through providers on failure. LLMClient delegates protocol-specific request/response handling to ProtocolAdapter implementations via strategy pattern. Provider config lives in DB as JSON column, managed through REST API and frontend panel.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy (async), Pydantic v2, httpx, openai SDK, Vue 3 (frontend)

## Global Constraints

- No backwards compatibility with `.env` LLM variables — they are removed
- No cooldown between provider failover — chain immediately on failure
- auth/quota errors auto-disable provider (persisted to DB)
- Per-provider retry is disabled (retry = switch provider)
- Token usage tracking continues to work across any provider
- `Task.model_config_json` retains its existing override behavior

---

## File Structure

| File | Responsibility |
|------|---------------|
| `app/llm/protocols.py` | **New.** 3 ProtocolAdapter implementations + LLMResponse/ToolCall dataclasses |
| `app/llm/router.py` | **New.** LLMRouter with weighted random selection and chain failover |
| `app/llm/client.py` | **Refactor.** Strip protocol logic, delegate to ProtocolAdapter, remove retry |
| `app/llm/__init__.py` | **Modify.** Export LLMRouter, LLMClient, LLMResponse, ToolCall |
| `app/config.py` | **Modify.** Replace LLMConfig with LLMProviderConfig; remove llm_config singleton |
| `app/db/models.py` | **Modify.** Add llm_providers JSON column to SystemSettings |
| `app/settings_service.py` | **Modify.** Add resolve_llm_providers, llm_router_for_task, provider CRUD, connectivity test |
| `app/api/settings.py` | **Modify.** Add 6 provider endpoints; expose llm_providers in public view |
| `app/api/dto.py` | **Modify.** Add LLMProviderDTO, LlmProvidersSettingsDTO |
| `app/orchestrator.py` | **Modify.** `_llm_for_task()` → returns LLMRouter |
| `app/agents/worker.py` | **Modify.** Accept LLMRouter in constructor |
| `app/agents/reviewer.py` | **Modify.** Accept LLMRouter in constructor |
| `app/agents/killsweep.py` | **Modify.** Accept LLMRouter in constructor |
| `app/agents/escalate.py` | **Modify.** Accept LLMRouter in constructor |
| `app/agents/collector.py` | **Modify.** Use optional LLMRouter |
| `app/api/findings.py` | **Modify.** Report assistant uses LLMRouter |
| `.env.example` | **Modify.** Remove LLM_* variables |
| `frontend/src/` | **Modify.** Add LLM Providers management panel |

---

### Task 1: Define core dataclasses and config model

**Files:**
- Create: `app/llm/protocols.py` (LLMResponse + ToolCall only, adapters come in Task 2)
- Modify: `app/config.py`

**Interfaces:**
- Produces: `LLMResponse`, `ToolCall`, `LLMProviderConfig`

- [ ] **Step 1: Add LLMResponse and ToolCall to new protocols.py**

```python
"""Protocol adapters for OpenAI Chat, Anthropic Messages, and OpenAI Responses APIs."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # JSON string


@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] | None = None
```

Create file: `app/llm/protocols.py`

- [ ] **Step 2: Run Python to verify imports**

```bash
python -c "from app.llm.protocols import LLMResponse, ToolCall; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Replace LLMConfig with LLMProviderConfig in config.py**

Replace the entire file content of `app/config.py`:

```python
"""配置模型：LLM provider 与 Worker 参数。"""
from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


def _load_dotenv() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


_load_dotenv()


class LLMProviderConfig(BaseModel):
    """单个 LLM provider 的配置。"""
    name: str = "Default"
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model: str = "deepseek-chat"
    temperature: float = 0.3
    weight: int = Field(default=5, ge=1, le=100)
    protocol: str = "openai_chat"  # openai_chat | anthropic_messages | openai_responses
    enabled: bool = True


class WorkerConfig(BaseModel):
    shell_timeout: int = int(os.environ.get("WORKER_SHELL_TIMEOUT", "120"))
    shell_timeout_max: int = int(os.environ.get("WORKER_SHELL_TIMEOUT_MAX", "600"))
    output_truncate: int = int(os.environ.get("WORKER_OUTPUT_TRUNCATE", "4096"))
    llm_tool_output_truncate: int = int(os.environ.get("WORKER_LLM_TOOL_OUTPUT_TRUNCATE", "4096"))
    history_full_tool_rounds: int = int(os.environ.get("WORKER_HISTORY_FULL_TOOL_ROUNDS", "4"))
    max_rounds: int = int(os.environ.get("WORKER_MAX_ROUNDS", "90"))
    soft_rounds: int = int(os.environ.get("WORKER_SOFT_ROUNDS", "45"))
    enterprise_max_rounds: int = int(os.environ.get("ENTERPRISE_WORKER_MAX_ROUNDS", "110"))
    enterprise_soft_rounds: int = int(os.environ.get("ENTERPRISE_WORKER_SOFT_ROUNDS", "60"))
    round_budget_cap: int = int(os.environ.get("WORKER_ROUND_BUDGET_CAP", "0"))
    soft_round_budget_cap: int = int(os.environ.get("WORKER_SOFT_ROUND_BUDGET_CAP", "0"))
    enterprise_round_budget_cap: int = int(os.environ.get("ENTERPRISE_WORKER_ROUND_BUDGET_CAP", "0"))
    enterprise_soft_round_budget_cap: int = int(os.environ.get("ENTERPRISE_WORKER_SOFT_ROUND_BUDGET_CAP", "0"))
    js_tool_always_on: bool = os.environ.get("WORKER_JS_TOOL_ALWAYS_ON", "0").lower() in {"1", "true", "yes"}
    prompt_version: str = os.environ.get("WORKER_PROMPT_VERSION", "legacy")
    work_root: str = os.environ.get("WORKER_WORK_ROOT", "/tmp/autohunter/work")

    def rounds_for(self, src_type: str | None) -> tuple[int, int]:
        st = (src_type or "").strip().lower()
        if st in {"enterprise", "corp", "company", "企业", "企业src"}:
            max_rounds = self._cap(self.enterprise_max_rounds, self.enterprise_round_budget_cap)
            soft_rounds = self._cap(self.enterprise_soft_rounds, self.enterprise_soft_round_budget_cap)
        else:
            max_rounds = self._cap(self.max_rounds, self.round_budget_cap)
            soft_rounds = self._cap(self.soft_rounds, self.soft_round_budget_cap)
        return max(1, max_rounds), max(1, min(soft_rounds, max_rounds))

    @staticmethod
    def _cap(value: int, cap: int) -> int:
        return min(value, cap) if cap > 0 else value


worker_config = WorkerConfig()
```

- [ ] **Step 4: Verify config.py loads**

```bash
python -c "from app.config import LLMProviderConfig; c = LLMProviderConfig(); print(c.model_dump())"
```

Expected: prints default provider config dict

- [ ] **Step 5: Commit**

```bash
git add app/llm/protocols.py app/config.py
git commit -m "feat: add LLMProviderConfig and LLMResponse dataclasses"
```

---

### Task 2: Implement ProtocolAdapter classes

**Files:**
- Modify: `app/llm/protocols.py` (append adapter classes)

**Interfaces:**
- Consumes: `LLMResponse`, `ToolCall` from Task 1
- Produces: `ProtocolAdapter` (ABC), `OpenAIChatAdapter`, `AnthropicMessagesAdapter`, `OpenAIResponsesAdapter`, `ADAPTER_REGISTRY`

- [ ] **Step 1: Add ProtocolAdapter base class and implementations**

Append to `app/llm/protocols.py` after the existing dataclasses:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from types import SimpleNamespace
import json
from typing import Any


@dataclass
class RequestPayload:
    url: str
    headers: dict[str, str]
    body: dict[str, Any]


@dataclass
class UsageInfo:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cache_hit_tokens: int = 0
    cache_miss_tokens: int = 0


class ProtocolAdapter(ABC):
    """策略接口：每个协议实现 build / parse / extract_usage 三个方法。"""

    @property
    @abstractmethod
    def protocol_name(self) -> str:
        ...

    @abstractmethod
    def build_request(
        self,
        base_url: str,
        api_key: str,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None,
        tool_choice: Any,
        temperature: float,
        max_tokens: int,
    ) -> RequestPayload:
        ...

    @abstractmethod
    def parse_response(self, raw: dict[str, Any]) -> LLMResponse:
        ...

    @abstractmethod
    def extract_usage(self, raw: dict[str, Any]) -> UsageInfo:
        ...


# ═══════════════════════════════════════════════════════════════
# OpenAI Chat Completions
# ═══════════════════════════════════════════════════════════════

class OpenAIChatAdapter(ProtocolAdapter):
    protocol_name = "openai_chat"

    def build_request(self, base_url, api_key, model, messages,
                      tools, tool_choice, temperature, max_tokens):
        url = base_url.rstrip("/")
        if not url.endswith("/chat/completions"):
            if url.endswith("/v1"):
                url += "/chat/completions"
            else:
                url += "/v1/chat/completions"
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if tools:
            body["tools"] = tools
            body["tool_choice"] = tool_choice
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return RequestPayload(url=url, headers=headers, body=body)

    def parse_response(self, raw):
        choice = raw.get("choices", [{}])[0]
        msg = choice.get("message") or {}
        content = msg.get("content") or ""
        calls = None
        raw_calls = msg.get("tool_calls") or []
        if raw_calls:
            calls = [
                ToolCall(
                    id=c.get("id", ""),
                    name=(c.get("function") or {}).get("name", ""),
                    arguments=json.dumps(
                        json.loads((c.get("function") or {}).get("arguments", "{}")),
                        ensure_ascii=False,
                    ),
                )
                for c in raw_calls
            ]
        return LLMResponse(content=content or "", tool_calls=calls or None)

    def extract_usage(self, raw):
        usage = raw.get("usage") or {}
        cache_hit = usage.get("prompt_cache_hit_tokens", 0) or 0
        cache_miss = usage.get("prompt_cache_miss_tokens", 0) or 0
        if not cache_hit:
            details = usage.get("prompt_tokens_details") or {}
            cache_hit = details.get("cached_tokens", 0) or 0
        return UsageInfo(
            prompt_tokens=usage.get("prompt_tokens", 0) or 0,
            completion_tokens=usage.get("completion_tokens", 0) or 0,
            total_tokens=usage.get("total_tokens", 0) or 0,
            cache_hit_tokens=cache_hit,
            cache_miss_tokens=cache_miss,
        )


# ═══════════════════════════════════════════════════════════════
# Anthropic Messages
# ═══════════════════════════════════════════════════════════════

class AnthropicMessagesAdapter(ProtocolAdapter):
    protocol_name = "anthropic_messages"

    def _messages_url(self, base_url: str) -> str:
        base = base_url.rstrip("/")
        if base.endswith("/v1"):
            return f"{base}/messages"
        return f"{base}/v1/messages"

    @staticmethod
    def _to_messages_tools(tools: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for item in tools or []:
            fn = item.get("function") or {}
            name = fn.get("name")
            if not name:
                continue
            out.append({
                "name": name,
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters") or {"type": "object", "properties": {}},
            })
        return out

    @staticmethod
    def _to_messages_tool_choice(tool_choice: Any) -> dict[str, Any] | None:
        if tool_choice in (None, "auto"):
            return {"type": "auto"}
        if tool_choice == "none":
            return {"type": "none"}
        if isinstance(tool_choice, dict):
            fn = (tool_choice.get("function") or {}).get("name")
            if fn:
                return {"type": "tool", "name": fn}
        return {"type": "auto"}

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        system_parts: list[str] = []
        out: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "tool":
                out.append({
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": msg.get("tool_call_id", ""),
                        "content": str(content),
                    }],
                })
                continue
            if role == "assistant":
                blocks: list[dict[str, Any]] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for call in msg.get("tool_calls") or []:
                    fn = call.get("function") or {}
                    try:
                        tool_input = json.loads(fn.get("arguments") or "{}")
                    except Exception:
                        tool_input = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": call.get("id", ""),
                        "name": fn.get("name", ""),
                        "input": tool_input,
                    })
                out.append({"role": "assistant", "content": blocks or str(content)})
                continue
            out.append({"role": "user", "content": str(content)})
        return "\n\n".join(system_parts), out

    def build_request(self, base_url, api_key, model, messages,
                      tools, tool_choice, temperature, max_tokens):
        system, converted = self._convert_messages(messages)
        body: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": converted,
            "temperature": temperature,
        }
        if system:
            body["system"] = system
        converted_tools = self._to_messages_tools(tools)
        if converted_tools:
            body["tools"] = converted_tools
            choice = self._to_messages_tool_choice(tool_choice)
            if choice:
                body["tool_choice"] = choice
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "anthropic-version": "2023-06-01",
        }
        return RequestPayload(url=self._messages_url(base_url), headers=headers, body=body)

    def parse_response(self, raw):
        text_parts: list[str] = []
        calls = []
        for block in raw.get("content") or []:
            btype = block.get("type")
            if btype == "text":
                text_parts.append(block.get("text") or "")
            elif btype == "tool_use":
                calls.append(ToolCall(
                    id=block.get("id", ""),
                    name=block.get("name", ""),
                    arguments=json.dumps(block.get("input") or {}, ensure_ascii=False),
                ))
        return LLMResponse(content="".join(text_parts), tool_calls=calls or None)

    def extract_usage(self, raw):
        usage = raw.get("usage") or {}
        return UsageInfo(
            prompt_tokens=usage.get("input_tokens") or 0,
            completion_tokens=usage.get("output_tokens") or 0,
            total_tokens=(usage.get("input_tokens") or 0) + (usage.get("output_tokens") or 0),
            cache_hit_tokens=usage.get("cache_read_input_tokens") or 0,
            cache_miss_tokens=usage.get("cache_creation_input_tokens") or 0,
        )


# ═══════════════════════════════════════════════════════════════
# OpenAI Responses
# ═══════════════════════════════════════════════════════════════

class OpenAIResponsesAdapter(ProtocolAdapter):
    protocol_name = "openai_responses"

    def build_request(self, base_url, api_key, model, messages,
                      tools, tool_choice, temperature, max_tokens):
        url = base_url.rstrip("/")
        if not url.endswith("/responses"):
            if url.endswith("/v1"):
                url += "/responses"
            else:
                url += "/v1/responses"

        # Convert messages to input format (Responses API uses "input")
        input_items: list[dict[str, Any]] = []
        for msg in messages:
            role = msg.get("role")
            content = msg.get("content") or ""
            if role == "system":
                input_items.append({"role": "system", "content": str(content)})
            elif role == "tool":
                # Tool result → function_call_output item
                input_items.append({
                    "type": "function_call_output",
                    "call_id": msg.get("tool_call_id", ""),
                    "output": str(content),
                })
            elif role == "assistant":
                item: dict[str, Any] = {"role": "assistant", "content": str(content)}
                input_items.append(item)
            else:
                input_items.append({"role": "user", "content": str(content)})

        body: dict[str, Any] = {
            "model": model,
            "input": input_items,
            "temperature": temperature,
            "max_output_tokens": max_tokens,
        }
        if tools:
            body["tools"] = [
                {
                    "type": "function",
                    "name": (t.get("function") or {}).get("name", ""),
                    "description": (t.get("function") or {}).get("description", ""),
                    "parameters": (t.get("function") or {}).get("parameters", {}),
                }
                for t in tools
                if (t.get("function") or {}).get("name")
            ]
            if tool_choice and tool_choice != "auto":
                if isinstance(tool_choice, dict):
                    fn = (tool_choice.get("function") or {}).get("name")
                    if fn:
                        body["tool_choice"] = {"type": "function", "name": fn}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return RequestPayload(url=url, headers=headers, body=body)

    def parse_response(self, raw):
        content = raw.get("output_text", "") or ""
        calls = []
        for item in raw.get("output", []):
            if item.get("type") == "function_call":
                calls.append(ToolCall(
                    id=item.get("call_id", ""),
                    name=item.get("name", ""),
                    arguments=json.dumps(json.loads(item.get("arguments", "{}")), ensure_ascii=False)
                    if isinstance(item.get("arguments"), str) else json.dumps(item.get("arguments", {}), ensure_ascii=False),
                ))
        return LLMResponse(content=content, tool_calls=calls or None)

    def extract_usage(self, raw):
        usage = raw.get("usage") or {}
        return UsageInfo(
            prompt_tokens=usage.get("input_tokens", 0) or 0,
            completion_tokens=usage.get("output_tokens", 0) or 0,
            total_tokens=usage.get("total_tokens", 0) or 0,
        )


# Registry: protocol string → adapter class
ADAPTER_REGISTRY: dict[str, type[ProtocolAdapter]] = {
    "openai_chat": OpenAIChatAdapter,
    "anthropic_messages": AnthropicMessagesAdapter,
    "openai_responses": OpenAIResponsesAdapter,
}
```

- [ ] **Step 2: Verify all adapters instantiate and registry works**

```bash
python -c "
from app.llm.protocols import ADAPTER_REGISTRY
for name, cls in ADAPTER_REGISTRY.items():
    a = cls()
    print(f'{name}: protocol={a.protocol_name}')
print('OK')
"
```

Expected: All three protocol names printed, then `OK`

- [ ] **Step 3: Verify OpenAIChatAdapter build + parse round-trip**

```bash
python -c "
from app.llm.protocols import OpenAIChatAdapter, LLMResponse
a = OpenAIChatAdapter()
req = a.build_request('https://api.deepseek.com/v1', 'sk-test', 'deepseek-chat',
    [{'role':'user','content':'hi'}], None, 'auto', 0.3, 100)
print(f'url={req.url}')
print(f'has_auth={req.headers.get(\"Authorization\",\"\")[:20]}...')
# Simulate response
fake = {'choices':[{'message':{'content':'hello','tool_calls':None}}],'usage':{'prompt_tokens':5,'completion_tokens':3,'total_tokens':8}}
resp = a.parse_response(fake)
print(f'content={resp.content}')
assert resp.content == 'hello'
print('OK')
"
```

Expected: `content=hello`, `OK`

- [ ] **Step 4: Verify AnthropicMessagesAdapter build**

```bash
python -c "
from app.llm.protocols import AnthropicMessagesAdapter
a = AnthropicMessagesAdapter()
req = a.build_request('https://api.anthropic.com', 'sk-test', 'claude-sonnet-5',
    [{'role':'user','content':'hi'}], None, 'auto', 0.3, 100)
print(f'url={req.url}')
print(f'has_version={req.headers.get(\"anthropic-version\",\"none\")}')
assert '/messages' in req.url
print('OK')
"
```

Expected: url contains `/messages`, version header present, `OK`

- [ ] **Step 5: Verify OpenAIResponsesAdapter build**

```bash
python -c "
from app.llm.protocols import OpenAIResponsesAdapter
a = OpenAIResponsesAdapter()
req = a.build_request('https://api.openai.com/v1', 'sk-test', 'gpt-5.6',
    [{'role':'user','content':'hi'}], None, 'auto', 0.3, 100)
print(f'url={req.url}')
print(f'input_len={len(req.body[\"input\"])}')
assert '/responses' in req.url
assert req.body['input'][0]['content'] == 'hi'
print('OK')
"
```

Expected: url contains `/responses`, input content matches, `OK`

- [ ] **Step 6: Commit**

```bash
git add app/llm/protocols.py
git commit -m "feat: add ProtocolAdapter implementations for 3 protocols"
```

---

### Task 3: Build LLMRouter

**Files:**
- Create: `app/llm/router.py`

**Interfaces:**
- Consumes: `LLMProviderConfig` from Task 1, `LLMClient` (existing), `ADAPTER_REGISTRY` from Task 2
- Produces: `LLMRouter` class with `chat()` method

- [ ] **Step 1: Read current LLMClient import path**

```bash
python -c "from app.llm.client import LLMClient; print('OK')"
```

- [ ] **Step 2: Create LLMRouter**

Create file `app/llm/router.py`:

```python
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
```

- [ ] **Step 3: Unit test - weighted selection distributes correctly**

```bash
python -c "
from app.config import LLMProviderConfig
from app.llm.router import LLMRouter

# 2 providers with different weights
p1 = LLMProviderConfig(name='A', api_key='sk-a', weight=7, base_url='https://x.com/v1')
p2 = LLMProviderConfig(name='B', api_key='sk-b', weight=3, base_url='https://y.com/v1')
# Patch LLMClient to avoid actual HTTP
import app.llm.client as client_mod
original_init = client_mod.LLMClient.__init__
def fake_init(self, config=None):
    self.config = config
client_mod.LLMClient.__init__ = fake_init

r = LLMRouter([p1, p2])
counts = {'A': 0, 'B': 0}
for _ in range(1000):
    idx = r._weighted_select(set())
    name = r._entries[idx][0].name
    counts[name] += 1
print(f'A={counts[\"A\"]} B={counts[\"B\"]}')
# A should be roughly 700, B roughly 300
assert 600 < counts['A'] < 800, f'Expected ~700 got {counts[\"A\"]}'
assert 200 < counts['B'] < 400, f'Expected ~300 got {counts[\"B\"]}'
print('OK')
client_mod.LLMClient.__init__ = original_init
"
```

Expected: `A≈700 B≈300`, `OK`

- [ ] **Step 4: Unit test - exhausted providers raises error**

```bash
python -c "
from app.config import LLMProviderConfig
from app.llm.router import LLMRouter, AllProvidersExhaustedError
import app.llm.client as client_mod
original_init = client_mod.LLMClient.__init__
def fake_init(self, config=None):
    self.config = config
client_mod.LLMClient.__init__ = fake_init

p1 = LLMProviderConfig(name='A', api_key='sk-a', weight=5, base_url='https://x.com/v1')
r = LLMRouter([p1])
# Make chat() always fail
def failing_chat(self, **kw):
    raise RuntimeError('boom')
client_mod.LLMClient.chat = failing_chat

try:
    r.chat([{'role':'user','content':'hi'}])
    assert False, 'should have raised'
except AllProvidersExhaustedError as e:
    print(f'exhausted: {e.errors[0][0]}={e.errors[0][1][:20]}...')
    print('OK')
finally:
    client_mod.LLMClient.__init__ = original_init
"
```

Expected: `exhausted: A=boom...`, `OK`

- [ ] **Step 5: Commit**

```bash
git add app/llm/router.py
git commit -m "feat: add LLMRouter with weighted random selection and chain failover"
```

---

### Task 4: Refactor LLMClient to use ProtocolAdapter

**Files:**
- Modify: `app/llm/client.py`

**Interfaces:**
- Consumes: `LLMProviderConfig` from Task 1, `ProtocolAdapter` + `ADAPTER_REGISTRY` from Task 2
- Produces: `LLMClient` — same public API but internal protocol logic removed

- [ ] **Step 1: Write the refactored LLMClient**

Replace `app/llm/client.py`:

```python
"""LLM 客户端：HTTP/TLS/错误分类，协议逻辑委托给 ProtocolAdapter。

24x7 健壮性：请求级超时 + TLS 自适应。不自动重试——重试由 LLMRouter 通过切换 provider 完成。
"""
from __future__ import annotations

import os
import logging
import re
from typing import Any

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


def _sanitize_error_detail(text: str, limit: int = 1200) -> str:
    text = _SECRET_RE.sub("sk-<masked>", text or "")
    text = " ".join(text.split())
    return text[:limit]


def _classify_error(e: Exception) -> LLMError:
    response = getattr(e, "response", None)
    status = getattr(e, "status_code", None) or getattr(response, "status_code", None)
    code = getattr(e, "code", "") or ""
    raw = str(e)
    if response is not None:
        try:
            raw = f"{raw} {response.text[:500]}"
        except Exception:
            pass
    detail = _sanitize_error_detail(raw)
    text = f"{status or ''} {code} {raw}".lower()

    if any(k in text for k in ("insufficient_quota", "quota", "billing", "余额", "额度", "balance")):
        return LLMError("quota", "LLM 额度不足或账户余额不足，请更换/充值模型 API Key 后重试。",
                        e, status=status, code=str(code), detail=detail)
    if status == 401 or any(k in text for k in ("unauthorized", "invalid api key", "incorrect api key", "无效")):
        return LLMError("auth", "LLM API Key 无效或无权限，请检查任务配置或服务端 .env。",
                        e, status=status, code=str(code), detail=detail)
    if status == 429 or any(k in text for k in ("rate limit", "too many requests", "限流")):
        return LLMError("rate_limit", "LLM 请求被限流，请稍后重试或降低并发。",
                        e, status=status, code=str(code), detail=detail)
    if any(k in text for k in ("timeout", "timed out", "readtimeout", "connecttimeout", "超时")):
        return LLMError("timeout", "LLM 请求超时，可能是模型服务或网络临时不可用。",
                        e, status=status, code=str(code), detail=detail)
    if any(k in text for k in ("connection", "network", "name resolution", "连接")):
        return LLMError("network", "LLM 网络连接失败，请检查服务器出网或代理。",
                        e, status=status, code=str(code), detail=detail)
    if status and int(status) >= 500:
        return LLMError("upstream", "LLM 上游服务临时异常，请稍后重试。",
                        e, status=status, code=str(code), detail=detail)
    logger.warning("LLM unknown error: type=%s status=%s code=%s detail=%s",
                   type(e).__name__, status, code, raw[:600])
    return LLMError("unknown", "LLM 调用失败：模型服务返回未知错误。",
                    e, status=status, code=str(code), detail=detail)


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
                    raise _classify_error(e2) from e2
            else:
                raise _classify_error(e) from e

        try:
            resp.raise_for_status()
        except Exception as e:
            raise _classify_error(e) from e

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
```

- [ ] **Step 2: Verify the refactored LLMClient imports cleanly**

```bash
python -c "from app.llm.client import LLMClient, LLMError, _classify_error; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Verify LLMClient can be created with a provider config**

```bash
python -c "
from app.config import LLMProviderConfig
from app.llm.client import LLMClient
cfg = LLMProviderConfig(name='test', api_key='sk-test', base_url='https://api.deepseek.com/v1', protocol='openai_chat')
c = LLMClient(config=cfg)
print(f'adapter={c.adapter.protocol_name}')
assert c.adapter.protocol_name == 'openai_chat'
print('OK')
"
```

Expected: `adapter=openai_chat`, `OK`

- [ ] **Step 4: Verify that the removed symbols are cleaned up**

Search for any remaining references that will break:

```bash
python -c "from app.llm import client; print(hasattr(client, '_messages_protocol')); print(hasattr(client, '_messages_chat')); print(hasattr(client, '_convert_messages'))"
```

Expected: `False` three times (these methods are now in protocols.py)

- [ ] **Step 5: Commit**

```bash
git add app/llm/client.py
git commit -m "refactor: strip protocol logic from LLMClient, delegate to ProtocolAdapter"
```

---

### Task 5: DB migration — add llm_providers column

**Files:**
- Modify: `app/db/models.py`

**Interfaces:**
- Produces: `SystemSettings.llm_providers` column

- [ ] **Step 1: Add column to SystemSettings model**

In `app/db/models.py`, add after the `defaults` line (line 278):

```python
    llm_providers: Mapped[list] = mapped_column(JSON, default=list)
```

The updated SystemSettings class:

```python
class SystemSettings(Base):
    """全局系统配置（单行 id=global）。任务级配置可覆盖此处默认值。"""
    __tablename__ = "system_settings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default="global")
    llm: Mapped[dict] = mapped_column(JSON, default=dict)
    fofa: Mapped[dict] = mapped_column(JSON, default=dict)
    engines: Mapped[dict] = mapped_column(JSON, default=dict)
    defaults: Mapped[dict] = mapped_column(JSON, default=dict)
    llm_providers: Mapped[list] = mapped_column(JSON, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=_now, onupdate=_now)
```

- [ ] **Step 2: Verify model loads**

```bash
python -c "from app.db.models import SystemSettings; print('llm_providers' in SystemSettings.__table__.columns); print('OK')"
```

Expected: `True`, `OK`

- [ ] **Step 3: Verify DB migration works (SQLite in-memory test)**

```bash
python -c "
from app.db.models import Base, SystemSettings
from sqlalchemy import create_engine
engine = create_engine('sqlite:///:memory:')
Base.metadata.create_all(engine)
from sqlalchemy.orm import Session
with Session(engine) as s:
    row = SystemSettings(id='global', llm_providers=[])
    s.add(row)
    s.commit()
    got = s.get(SystemSettings, 'global')
    print(f'llm_providers={got.llm_providers}')
    assert got.llm_providers == []
print('OK')
"
```

Expected: `llm_providers=[]`, `OK`

- [ ] **Step 4: Commit**

```bash
git add app/db/models.py
git commit -m "feat: add llm_providers JSON column to SystemSettings"
```

---

### Task 6: Update settings_service.py

**Files:**
- Modify: `app/settings_service.py`

**Interfaces:**
- Consumes: `LLMProviderConfig` from Task 1, `LLMRouter` from Task 3, `ADAPTER_REGISTRY` from Task 2
- Produces: `resolve_llm_providers()`, `llm_router_for_task()`, `llm_router_for_task_optional()`
- Removes: `resolve_llm_config()` (internal use only), old `_env_llm()` LLM env reading

- [ ] **Step 1: Replace LLM-related functions in settings_service.py**

Replace the LLM-related functions. The key changes:

1. Remove `_env_llm()` function
2. Remove `resolve_llm_config()` function
3. Add `resolve_llm_providers()` 
4. Replace `llm_client_for_task()` with `llm_router_for_task()`
5. Replace `llm_client_for_task_optional()` with `llm_router_for_task_optional()`
6. Update `public_settings_view()` to include `llm_providers`
7. Update `effective_settings()` to include `llm_providers`
8. Add provider CRUD helpers
9. Add connectivity test function

Edit `app/settings_service.py`:

**Step 1a: Remove `_env_llm()` function** (lines 40-46)

**Step 1b: Update `effective_settings()`** to include llm_providers:

```python
def effective_settings() -> dict[str, Any]:
    """合并 env + DB 缓存的有效配置。"""
    return {
        "llm": _merge_section(_cache.get("llm"), {}),
        "fofa": _merge_section(_cache.get("fofa"), _env_fofa()),
        "engines": _merge_section(_cache.get("engines"), _env_engines()),
        "defaults": _merge_section(_cache.get("defaults"), _env_defaults()),
        "llm_providers": _cache.get("llm_providers") or [],
    }
```

**Step 1c: Add resolve_llm_providers():**

```python
def resolve_llm_providers(task: Task | None = None) -> list:
    """返回任务可用 LLM provider 列表。
    
    优先级：任务 model_config_json → DB llm_providers → 空列表。
    """
    from app.config import LLMProviderConfig

    # 任务级覆盖：单 provider
    if task and task.model_config_json:
        mc = task.model_config_json
        if mc.get("api_key"):
            return [LLMProviderConfig(
                name="任务指定",
                base_url=mc.get("base_url", "https://api.deepseek.com/v1"),
                api_key=mc.get("api_key", ""),
                model=mc.get("model", "deepseek-chat"),
                temperature=float(mc.get("temperature", 0.3)),
                weight=1,
                enabled=True,
            ).model_dump()]

    eff = effective_settings()
    providers = eff.get("llm_providers") or []
    # Validate each provider dict
    result = []
    for p in providers:
        try:
            validated = LLMProviderConfig(**p)
            result.append(validated.model_dump())
        except Exception:
            continue
    return result


def llm_router_for_task(task: Task | None = None):
    """返回 LLMRouter；无有效 provider 时抛 RuntimeError。"""
    from app.config import LLMProviderConfig
    from app.llm.router import LLMRouter

    providers = [LLMProviderConfig(**p) for p in resolve_llm_providers(task)]
    if not providers:
        raise RuntimeError("未配置任何 LLM provider，请在设置页面添加至少一个 LLM 提供商")

    async def _on_disabled(name: str, reason: str):
        """provider 被自动禁用时同步到 DB。"""
        async with SessionLocal() as sess:
            row = await sess.get(SystemSettings, SETTINGS_ID)
            if row:
                lst = list(row.llm_providers or [])
                for item in lst:
                    if item.get("name") == name:
                        item["enabled"] = False
                        break
                row.llm_providers = lst
                await sess.commit()
                await refresh_cache(sess)

    return LLMRouter(providers, usage_key=task.id if task else None)


def llm_router_for_task_optional(task: Task | None = None):
    """返回 LLMRouter；无有效 provider 时返回 None（collector 降级）。"""
    from app.config import LLMProviderConfig
    from app.llm.router import LLMRouter

    providers = [LLMProviderConfig(**p) for p in resolve_llm_providers(task)]
    if not all(p.api_key for p in providers):
        providers = [p for p in providers if p.api_key]
    if not providers:
        return None
    try:
        return LLMRouter(providers, usage_key=task.id if task else None)
    except Exception:
        return None
```

**Step 1d: Update `public_settings_view()`** to expose llm_providers (keys masked):

Add to the returned dict in `public_settings_view()`:

```python
        "llm_providers": [
            {
                **p,
                "api_key": mask_secret(p.get("api_key", "")),
                "api_key_set": bool(p.get("api_key")),
            }
            for p in (_cache.get("llm_providers") or [])
        ],
```

**Step 1e: Add provider CRUD and connectivity test functions:**

```python
async def add_llm_provider(session: AsyncSession, provider: dict) -> list:
    row = await session.get(SystemSettings, SETTINGS_ID)
    if row is None:
        row = SystemSettings(id=SETTINGS_ID)
        session.add(row)
    lst = list(row.llm_providers or [])
    # Validate
    from app.config import LLMProviderConfig
    LLMProviderConfig(**provider)
    lst.append(provider)
    row.llm_providers = lst
    await session.commit()
    await refresh_cache(session)
    return row.llm_providers


async def update_llm_provider(session: AsyncSession, name: str, updates: dict) -> list:
    row = await session.get(SystemSettings, SETTINGS_ID)
    if row is None:
        raise RuntimeError("系统设置不存在")
    lst = list(row.llm_providers or [])
    for i, item in enumerate(lst):
        if item.get("name") == name:
            merged = {**item, **updates}
            # Don't overwrite key with masked placeholder
            if "api_key" in updates and is_masked_secret(updates["api_key"]):
                merged["api_key"] = item.get("api_key", "")
            lst[i] = merged
            break
    else:
        raise RuntimeError(f"Provider '{name}' 不存在")
    row.llm_providers = lst
    await session.commit()
    await refresh_cache(session)
    return row.llm_providers


async def delete_llm_provider(session: AsyncSession, name: str) -> list:
    row = await session.get(SystemSettings, SETTINGS_ID)
    if row is None:
        raise RuntimeError("系统设置不存在")
    lst = [p for p in (row.llm_providers or []) if p.get("name") != name]
    row.llm_providers = lst
    await session.commit()
    await refresh_cache(session)
    return row.llm_providers


async def test_llm_provider(provider: dict) -> dict:
    """连通测试：发送简单请求验证 provider 可用。"""
    import time
    from app.config import LLMProviderConfig
    from app.llm.client import LLMClient

    try:
        cfg = LLMProviderConfig(**provider)
        client = LLMClient(config=cfg)
        t0 = time.monotonic()
        resp = client.chat(
            messages=[{"role": "user", "content": "say pong"}],
            max_tokens=10,
        )
        latency_ms = int((time.monotonic() - t0) * 1000)
        return {
            "ok": True,
            "latency_ms": latency_ms,
            "model": cfg.model,
            "error": "",
        }
    except Exception as exc:
        return {
            "ok": False,
            "latency_ms": 0,
            "model": provider.get("model", ""),
            "error": str(exc),
        }
```

**Step 1f: Update `list_available_models()`** — this function already reads from `effective_settings()["llm"]`. Since we're removing old env LLM config, update it to accept explicit base_url and api_key as it already does (no change needed — it already accepts params).

- [ ] **Step 2: Verify imports and core functions**

```bash
python -c "
from app.settings_service import resolve_llm_providers, effective_settings
providers = resolve_llm_providers()
print(f'providers={providers}')
print('OK')
"
```

Expected: `providers=[]`, `OK` (no providers configured yet)

- [ ] **Step 3: Commit**

```bash
git add app/settings_service.py
git commit -m "feat: add resolve_llm_providers, router factories, provider CRUD, connectivity test"
```

---

### Task 7: Add LLM provider API endpoints

**Files:**
- Modify: `app/api/settings.py`
- Modify: `app/api/dto.py`

**Interfaces:**
- Consumes: provider CRUD functions from Task 6
- Produces: 6 REST endpoints for provider management

- [ ] **Step 1: Add DTOs to dto.py**

Append to `app/api/dto.py`:

```python
class LLMProviderDTO(BaseModel):
    name: str = "Default"
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model: str = "deepseek-chat"
    temperature: float = 0.3
    weight: int = Field(default=5, ge=1, le=100)
    protocol: str = "openai_chat"
    enabled: bool = True


class LLMProviderUpdateDTO(BaseModel):
    name: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    temperature: Optional[float] = None
    weight: Optional[int] = None
    protocol: Optional[str] = None
    enabled: Optional[bool] = None


class LLMProviderReorderDTO(BaseModel):
    """Provider 排序/权重批量更新。"""
    providers: list[LLMProviderDTO]
```

- [ ] **Step 2: Add endpoints to settings.py**

Append to `app/api/settings.py`:

```python
from app.api.dto import LLMProviderDTO, LLMProviderUpdateDTO
from app.settings_service import (
    add_llm_provider,
    update_llm_provider,
    delete_llm_provider,
    test_llm_provider,
)


@router.get("/llm-providers")
async def get_llm_providers(session: AsyncSession = Depends(get_session)):
    """列出所有 LLM provider（密钥脱敏）。"""
    await refresh_cache(session)
    view = public_settings_view()
    return view.get("llm_providers", [])


@router.post("/llm-providers")
async def create_llm_provider(
    body: LLMProviderDTO,
    session: AsyncSession = Depends(get_session),
):
    """新增 LLM provider。"""
    providers = await add_llm_provider(session, body.model_dump())
    await refresh_cache(session)
    return {"ok": True, "providers": providers}


@router.put("/llm-providers/{name}")
async def update_llm_provider_endpoint(
    name: str,
    body: LLMProviderUpdateDTO,
    session: AsyncSession = Depends(get_session),
):
    """修改 LLM provider。"""
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    providers = await update_llm_provider(session, name, updates)
    await refresh_cache(session)
    return {"ok": True, "providers": providers}


@router.delete("/llm-providers/{name}")
async def delete_llm_provider_endpoint(
    name: str,
    session: AsyncSession = Depends(get_session),
):
    """删除 LLM provider。"""
    providers = await delete_llm_provider(session, name)
    await refresh_cache(session)
    return {"ok": True, "providers": providers}


@router.post("/llm-providers/{name}/test")
async def test_llm_provider_endpoint(
    name: str,
    session: AsyncSession = Depends(get_session),
):
    """连通测试指定 provider。"""
    await refresh_cache(session)
    providers = _cache.get("llm_providers") or []
    provider = next((p for p in providers if p.get("name") == name), None)
    if not provider:
        return {"ok": False, "error": f"Provider '{name}' 不存在"}
    return await test_llm_provider(provider)


class ReorderRequest(BaseModel):
    providers: list[dict]


@router.put("/llm-providers/reorder")
async def reorder_llm_providers(
    body: ReorderRequest,
    session: AsyncSession = Depends(get_session),
):
    """批量更新 provider 排序/权重。"""
    row = await session.get(SystemSettings, SETTINGS_ID)
    if row is None:
        row = SystemSettings(id=SETTINGS_ID)
        session.add(row)
    row.llm_providers = body.providers
    await session.commit()
    await refresh_cache(session)
    return {"ok": True}
```

Need to import `_cache` and `SETTINGS_ID` at the top of settings.py:

```python
from app.settings_service import (
    ..., _cache,
)
from app.db.models import SystemSettings
SETTINGS_ID = "global"
```

- [ ] **Step 3: Verify API starts without errors**

```bash
python -c "from app.api.settings import router; print(f'routes={len(router.routes)}'); print('OK')"
```

Expected: `routes=...` (should show more routes than before), `OK`

- [ ] **Step 4: Commit**

```bash
git add app/api/settings.py app/api/dto.py
git commit -m "feat: add LLM provider CRUD and connectivity test API endpoints"
```

---

### Task 8: Update orchestrator to use LLMRouter

**Files:**
- Modify: `app/orchestrator.py`

- [ ] **Step 1: Update the import**

Change line 43 from:
```python
from app.settings_service import (
    llm_client_for_task,
    resolve_fofa_base_url,
    resolve_fofa_key,
    resolve_worker_prompt_version,
)
```

To:
```python
from app.settings_service import (
    llm_router_for_task,
    resolve_fofa_base_url,
    resolve_fofa_key,
    resolve_worker_prompt_version,
)
```

- [ ] **Step 2: Update _llm_for_task function**

Change lines 308-309 from:
```python
def _llm_for_task(task: Task) -> LLMClient:
    return llm_client_for_task(task)
```

To:
```python
def _llm_for_task(task: Task):
    return llm_router_for_task(task)
```

- [ ] **Step 3: Update type annotation in _run_worker_inner**

In `_run_worker_inner`, line 1533, change:
```python
llm = _llm_for_task(task_obj)
```
The variable type changes from `LLMClient` to the router, but the usage stays compatible since `router.chat()` has the same signature.

- [ ] **Step 4: Remove old LLMClient import if it's now unused**

Check if `LLMClient` is imported directly anywhere else in orchestrator.py (line 41):
```python
from app.llm.client import LLMClient
```
This import should be removed since the orchestrator no longer references `LLMClient` directly. The router is used instead.

- [ ] **Step 5: Verify orchestrator imports**

```bash
python -c "from app.orchestrator import TaskRunner; print('OK')"
```

Expected: `OK`

- [ ] **Step 6: Commit**

```bash
git add app/orchestrator.py
git commit -m "refactor: orchestrator uses LLMRouter instead of LLMClient"
```

---

### Task 9: Update agents to accept LLMRouter

**Files:**
- Modify: `app/agents/worker.py:59`
- Modify: `app/agents/reviewer.py:239`
- Modify: `app/agents/killsweep.py:141`
- Modify: `app/agents/escalate.py:49`

All four agents have the same pattern: `self.llm = llm or LLMClient()`. They need to accept a router-compatible object instead.

- [ ] **Step 1: Update worker.py constructor**

Change line 59 from:
```python
        self.llm = llm or LLMClient()
```

To:
```python
        self.llm = llm  # LLMRouter or LLMClient, set by caller
```

And remove the `from app.llm.client import LLMClient` import at line 21 (keep if used elsewhere in the file, but check — `LLMClient` is only used in the constructor default).

- [ ] **Step 2: Update reviewer.py constructor**

Change line 239 from:
```python
        self.llm = llm or LLMClient()
```

To:
```python
        self.llm = llm  # set by caller
```

Remove the `LLMClient` import if no longer referenced.

- [ ] **Step 3: Update killsweep.py constructor**

Change line 141 from:
```python
        self.llm = llm or LLMClient()
```

To:
```python
        self.llm = llm  # set by caller
```

- [ ] **Step 4: Update escalate.py constructor**

Change line 49 from:
```python
        self.llm = llm or LLMClient()
```

To:
```python
        self.llm = llm  # set by caller
```

- [ ] **Step 5: Update orchestrator.py worker creation**

In `_run_worker_inner` (line 1539), where Worker is instantiated:
```python
            worker = Worker(url, llm=llm, on_event=emit, ...
```
The `llm` variable is now the router (from `_llm_for_task`), which has a `.chat()` method. The Worker uses `self.llm.chat(...)`, so this is compatible.

- [ ] **Step 6: Update orchestrator.py reviewer/killsweep/escalate creation**

Search for where Reviewer/Killsweep/Escalate are instantiated and ensure they receive the router:
```bash
grep -n "Reviewer(\|Killsweep(\|Escalate(" app/orchestrator.py
```

These need to pass `llm=llm_router_for_task(task)` instead of `LLMClient()`.

- [ ] **Step 7: Verify all agents import**

```bash
python -c "from app.agents.worker import Worker; from app.agents.reviewer import Reviewer; from app.agents.killsweep import KillsweepAgent; from app.agents.escalate import EscalateAgent; print('OK')"
```

Expected: `OK`

- [ ] **Step 8: Commit**

```bash
git add app/agents/worker.py app/agents/reviewer.py app/agents/killsweep.py app/agents/escalate.py app/orchestrator.py
git commit -m "refactor: agents accept LLMRouter, remove LLMClient default fallback"
```

---

### Task 10: Update collector for optional router

**Files:**
- Modify: `app/agents/collector.py`

- [ ] **Step 1: Update import**

Change line 32 from:
```python
from app.settings_service import llm_client_for_task_optional, resolve_engine_config, resolve_skip_score_threshold
```

To:
```python
from app.settings_service import llm_router_for_task_optional, resolve_engine_config, resolve_skip_score_threshold
```

- [ ] **Step 2: Update _llm_for_task**

Change lines 225-226 from:
```python
def _llm_for_task(task: Task) -> LLMClient | None:
    return llm_client_for_task_optional(task)
```

To:
```python
def _llm_for_task(task: Task):
    return llm_router_for_task_optional(task)
```

- [ ] **Step 3: Verify collector usage**

Check how `llm` is used in `_resolve_query` and other collector functions — it's called like `llm.chat(...)` if not None. The router has the same `.chat()` method.

- [ ] **Step 4: Verify**

```bash
python -c "from app.agents.collector import _llm_for_task; print('OK')"
```

- [ ] **Step 5: Commit**

```bash
git add app/agents/collector.py
git commit -m "refactor: collector uses optional LLMRouter"
```

---

### Task 11: Update findings.py report assistant

**Files:**
- Modify: `app/api/findings.py`

- [ ] **Step 1: Update import**

Change line 20 from:
```python
from app.settings_service import llm_client_for_task
```

To:
```python
from app.settings_service import llm_router_for_task
```

- [ ] **Step 2: Update _llm_for_task**

Change lines 506-507 from:
```python
def _llm_for_task(task: Task) -> LLMClient:
    return llm_client_for_task(task)
```

To:
```python
def _llm_for_task(task: Task):
    return llm_router_for_task(task)
```

- [ ] **Step 3: Commit**

```bash
git add app/api/findings.py
git commit -m "refactor: report assistant uses LLMRouter"
```

---

### Task 12: Clean up .env.example and config references

**Files:**
- Modify: `.env.example`

- [ ] **Step 1: Remove old LLM env variables from .env.example**

Remove lines 12-16:
```ini
LLM_BASE_URL=https://api.deepseek.com/v1
LLM_API_KEY=
LLM_MODEL=deepseek-chat
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=4096
```

Replace with:
```ini
# ---------------------------------------------------------------------------
# 【必填】LLM 提供商（首次启动后通过 Web UI → 设置 → LLM 提供商 配置）
# 支持 OpenAI Chat / Anthropic Messages / OpenAI Responses 三种协议
# 支持多个 provider 按权重分配 + 故障自动切换
# ---------------------------------------------------------------------------
LLM_MAX_TOKENS=4096
LLM_REQUEST_TIMEOUT=120
LLM_INSECURE_TLS=0
```

- [ ] **Step 2: Verify .env.example syntax**

```bash
python -c "
from pathlib import Path
env = Path('.env.example').read_text()
# Should not contain LLM_API_KEY or LLM_BASE_URL
assert 'LLM_BASE_URL' not in env
assert 'LLM_API_KEY' not in env
assert 'LLM_MODEL' not in env.split('LLM_MAX_TOKENS')[0]  # only the new comment
print('OK')
"
```

Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add .env.example
git commit -m "chore: remove old single-LLM env vars from .env.example"
```

---

### Task 13: Clean up remaining references

**Files:**
- Various — grep for dead references

- [ ] **Step 1: Find remaining references to old symbols**

```bash
grep -rn "llm_client_for_task\|llm_client_for_task_optional\|from app.config import LLMConfig\|from app.config import llm_config" app/ --include="*.py"
```

Expected: No results outside of `settings_service.py` (where the new router factory functions are defined).

If any references found, update them.

- [ ] **Step 2: Find references to old env vars**

```bash
grep -rn "LLM_API_KEY\|LLM_BASE_URL\|LLM_MODEL\|LLM_TEMPERATURE" app/ --include="*.py" | grep -v "def \|#\|\.env\|settings_service\|test_"
```

Expected: No results — all old env var reads should be gone.

- [ ] **Step 3: Run full import test**

```bash
python -c "
import app.main
print('All imports OK')
"
```

Expected: `All imports OK`

- [ ] **Step 4: Commit**

```bash
git add -A
git commit -m "chore: remove remaining references to old single-LLM config"
```

---

### Task 14: Frontend — LLM Providers management panel

**Files:**
- Modify: `frontend/src/` (Vue components)

**Note:** Frontend implementation details depend on the existing component patterns. This task describes the behavior and leaves exact template code to the implementer.

- [ ] **Step 1: Add provider list component**

Create `frontend/src/components/settings/LlmProvidersPanel.vue`:

Features:
- Table listing all providers: name, base_url, model, protocol, weight, status (enabled/disabled)
- Weight distribution bar at top showing percentages
- "Add Provider" button → opens form modal
- Each row: edit button, test button, enable/disable toggle, delete button
- Drag handle for reordering

- [ ] **Step 2: Add provider form modal**

Form fields:
- Name (text)
- base_url (text with quick-select dropdown: DeepSeek/Qwen/OpenAI/Claude/Custom)
- API Key (password, masked display)
- Model (text + "Fetch Models" button that calls `/api/settings/models`)
- Protocol (select: OpenAI Chat / Anthropic Messages / OpenAI Responses)
- Temperature (slider 0-2)
- Weight (number 1-100)
- Enabled (toggle)

- [ ] **Step 3: Wire up API calls**

API integration:
- `GET /api/settings/llm-providers` → populate table
- `POST /api/settings/llm-providers` → add provider
- `PUT /api/settings/llm-providers/{name}` → update provider
- `DELETE /api/settings/llm-providers/{name}` → delete provider
- `POST /api/settings/llm-providers/{name}/test` → connectivity test (show latency + status toast)

- [ ] **Step 4: Integrate into settings page**

Add a new tab "LLM 提供商" in the settings page, alongside existing tabs.

- [ ] **Step 5: Verify frontend builds**

```bash
cd frontend && npm run build
```

Expected: Build succeeds.

- [ ] **Step 6: Commit**

```bash
git add frontend/
git commit -m "feat: add LLM Providers management panel to settings"
```

---

## Execution Order

```
Task 1 (dataclasses + config) ──┐
                                ├──▶ Task 2 (protocols)
                                │       │
                                │       ▼
                                ├──▶ Task 3 (router)
                                │       │
                                │       ▼
Task 5 (DB migration) ──────────┼──▶ Task 6 (settings_service)
                                        │
                                        ▼
                                   Task 7 (API endpoints)
                                        │
                         ┌──────────────┼──────────────┐
                         ▼              ▼              ▼
                   Task 8 (orch)  Task 4 (client)  Task 12 (.env)
                         │              │
                         ▼              │
                   Task 9 (agents)      │
                         │              │
                    ┌────┴────┐         │
                    ▼         ▼         │
              Task 10     Task 11       │
              (collector) (findings)    │
                    │         │         │
                    └────┬────┘         │
                         ▼              │
                   Task 13 (cleanup) ◄──┘
                         │
                         ▼
                   Task 14 (frontend)
```

Tasks 1-7 can be done in sequence; Tasks 8-12 are parallel-ready after Task 6.
Tasks 4 (client refactor) should be done before Tasks 8-11 so agents import correctly.
