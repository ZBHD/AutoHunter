"""Protocol adapters for OpenAI Chat, Anthropic Messages, and OpenAI Responses APIs."""
from __future__ import annotations

from abc import ABC, abstractmethod
from copy import deepcopy
from dataclasses import dataclass, field
import json
from typing import Any


_CONTINUATION_KEY = "_llm_continuation"


def _openai_chat_text_payload(text: str) -> dict[str, Any]:
    return {
        "choices": [{
            "message": {"role": "assistant", "content": text},
        }],
    }


def coerce_response_payload(raw: Any, protocol_name: str) -> dict[str, Any]:
    """Normalize transport-level gateway variants before protocol parsing."""
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")

    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            raise ValueError("LLM returned an empty response")
        if text.startswith("data:") or "\ndata:" in text:
            chunks = [
                line[5:].strip()
                for line in text.splitlines()
                if line.startswith("data:")
                and line[5:].strip()
                and line[5:].strip() != "[DONE]"
            ]
            if chunks:
                text = chunks[-1]
        try:
            raw = json.loads(text)
        except json.JSONDecodeError:
            if protocol_name == "openai_chat":
                return _openai_chat_text_payload(text)
            raise ValueError(f"{protocol_name} response is not valid JSON") from None

    if not isinstance(raw, dict):
        if protocol_name == "openai_chat" and raw is not None:
            return _openai_chat_text_payload(str(raw))
        raise ValueError(f"{protocol_name} response must be a JSON object")

    if protocol_name != "openai_chat":
        return raw

    normalized = deepcopy(raw)
    choices = normalized.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, str):
            choices[0] = {"message": {"role": "assistant", "content": first}}
        elif isinstance(first, dict):
            message = first.get("message", first)
            if isinstance(message, str):
                first["message"] = {"role": "assistant", "content": message}
            elif "message" not in first and (
                "content" in first or "tool_calls" in first
            ):
                choices[0] = {"message": message}
    elif "content" in normalized or "tool_calls" in normalized:
        return {"choices": [{"message": normalized}]}
    return normalized


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str

    def as_history_dict(self) -> dict[str, Any]:
        """Serialize to the canonical OpenAI-style history shape."""
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": self.arguments},
        }


@dataclass
class LLMResponse:
    content: str = ""
    tool_calls: list[ToolCall] | None = None
    continuation: dict[str, Any] | None = field(default=None, repr=False)

    def as_history_message(self) -> dict[str, Any]:
        """Build canonical history while retaining opaque provider continuation data."""
        message: dict[str, Any] = {"role": "assistant", "content": self.content or ""}
        if self.tool_calls:
            message["tool_calls"] = [call.as_history_dict() for call in self.tool_calls]
        if self.continuation:
            message[_CONTINUATION_KEY] = deepcopy(self.continuation)
        return message


def _argument_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def _content_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if not isinstance(value, list):
        return "" if value is None else str(value)
    parts: list[str] = []
    for item in value:
        if isinstance(item, str):
            parts.append(item)
        elif isinstance(item, dict) and item.get("type") == "text":
            parts.append(str(item.get("text") or ""))
    return "".join(parts)


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
            "messages": [
                {
                    key: deepcopy(value)
                    for key, value in message.items()
                    if not str(key).startswith("_")
                }
                for message in messages
            ],
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
        choices = raw.get("choices") or []
        choice = choices[0] if choices else {}
        msg = choice.get("message") or {}
        content = _content_string(msg.get("content"))
        raw_calls = msg.get("tool_calls") or []
        calls = [
            ToolCall(
                id=call.get("id", ""),
                name=(call.get("function") or {}).get("name", ""),
                arguments=_argument_string(
                    (call.get("function") or {}).get("arguments", "{}")
                ),
            )
            for call in raw_calls
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

        def append_blocks(role: str, blocks: list[dict[str, Any]]) -> None:
            if not blocks:
                return
            if out and out[-1]["role"] == role:
                out[-1]["content"].extend(blocks)
                return
            out.append({"role": role, "content": blocks})

        for msg in messages:
            role = msg.get("role")
            content = msg.get("content") or ""
            if role == "system":
                if content:
                    system_parts.append(str(content))
                continue
            if role == "tool":
                append_blocks("user", [{
                    "type": "tool_result",
                    "tool_use_id": msg.get("tool_call_id", ""),
                    "content": str(content),
                }])
                continue
            if role == "assistant":
                blocks: list[dict[str, Any]] = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for call in msg.get("tool_calls") or []:
                    fn = call.get("function") or {}
                    raw_arguments = fn.get("arguments") or "{}"
                    try:
                        tool_input = json.loads(raw_arguments)
                    except Exception:
                        tool_input = raw_arguments
                    blocks.append({
                        "type": "tool_use",
                        "id": call.get("id", ""),
                        "name": fn.get("name", ""),
                        "input": tool_input,
                    })
                append_blocks("assistant", blocks)
                continue
            if content:
                append_blocks("user", [{"type": "text", "text": str(content)}])
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
            "x-api-key": api_key,
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
                continuation = msg.get(_CONTINUATION_KEY)
                if (
                    isinstance(continuation, dict)
                    and continuation.get("protocol") == self.protocol_name
                    and isinstance(continuation.get("output"), list)
                ):
                    input_items.extend(deepcopy(continuation["output"]))
                    continue
                if content:
                    input_items.append({"role": "assistant", "content": str(content)})
                for call in msg.get("tool_calls") or []:
                    fn = call.get("function") or {}
                    input_items.append({
                        "type": "function_call",
                        "call_id": call.get("id", ""),
                        "name": fn.get("name", ""),
                        "arguments": _argument_string(fn.get("arguments", "{}")),
                    })
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
            if tool_choice == "none":
                body["tool_choice"] = "none"
            elif isinstance(tool_choice, dict):
                fn = (tool_choice.get("function") or {}).get("name")
                if fn:
                    body["tool_choice"] = {"type": "function", "name": fn}

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return RequestPayload(url=url, headers=headers, body=body)

    def parse_response(self, raw):
        output = raw.get("output") or []
        content = raw.get("output_text", "") or ""
        if not content:
            text_parts: list[str] = []
            for item in output:
                if item.get("type") != "message":
                    continue
                for block in item.get("content") or []:
                    if block.get("type") == "output_text":
                        text_parts.append(block.get("text") or "")
            content = "".join(text_parts)
        calls = []
        for item in output:
            if item.get("type") == "function_call":
                calls.append(ToolCall(
                    id=item.get("call_id", ""),
                    name=item.get("name", ""),
                    arguments=_argument_string(item.get("arguments", "{}")),
                ))
        continuation = None
        if output:
            continuation = {
                "protocol": self.protocol_name,
                "output": deepcopy(output),
            }
        return LLMResponse(
            content=content,
            tool_calls=calls or None,
            continuation=continuation,
        )

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
