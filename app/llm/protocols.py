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
