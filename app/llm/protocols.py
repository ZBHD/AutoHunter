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
