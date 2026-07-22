from __future__ import annotations

import json

import httpx
import pytest

from app.config import LLMProviderConfig
from app.llm.client import LLMClient, LLMError, _classify_error


class ProviderError(RuntimeError):
    def __init__(self, status_code: int | None, message: str, *, code: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.code = code


@pytest.mark.parametrize(
    ("status", "message", "code", "expected"),
    [
        (500, "upstream reported invalid api key and quota", "", "upstream"),
        (503, "billing service unavailable", "", "upstream"),
        (400, "模型参数无效", "", "unknown"),
        (401, "request rejected", "", "auth"),
        (403, "request rejected", "permission_error", "auth"),
        (403, "forbidden", "", "auth"),
    ],
)
def test_provider_error_classification_respects_status_before_body_keywords(
    status: int,
    message: str,
    code: str,
    expected: str,
) -> None:
    error = _classify_error(ProviderError(status, message, code=code))

    assert error.kind == expected


@pytest.mark.parametrize(
    "message",
    [
        "unknown variant `custom`; expected `web_search_20250305`",
        "failed to deserialize tools[0]: invalid tool schema",
        "unsupported model for this protocol",
    ],
)
def test_protocol_shape_errors_are_classified_as_protocol(message: str) -> None:
    error = _classify_error(ProviderError(400, message))

    assert error.kind == "protocol"
    assert error.status == 400
    assert "协议" in error.diagnostic()


def _openai_client(handler) -> LLMClient:
    client = LLMClient(LLMProviderConfig(
        name="Primary",
        base_url="https://llm.example/v1",
        api_key="sk-primary-secret-123456",
        model="test-model",
        protocol="openai_chat",
    ))
    client._client = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def test_forced_tool_choice_422_retries_same_provider_with_auto() -> None:
    bodies: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        bodies.append(json.loads(request.content))
        if len(bodies) == 1:
            return httpx.Response(
                422,
                request=request,
                json={"error": {"message": "Upstream error: 422"}},
            )
        return httpx.Response(
            200,
            request=request,
            json={"choices": [{"message": {"content": "ok"}}]},
        )

    client = _openai_client(handler)
    result = client.chat(
        [{"role": "user", "content": "review"}],
        tools=[{
            "type": "function",
            "function": {
                "name": "submit_review",
                "description": "Submit a review.",
                "parameters": {"type": "object", "properties": {}},
            },
        }],
        tool_choice={
            "type": "function",
            "function": {"name": "submit_review"},
        },
    )

    assert result.content == "ok"
    assert bodies[0]["tool_choice"]["function"]["name"] == "submit_review"
    assert bodies[1]["tool_choice"] == "auto"


def test_plain_422_without_forced_tool_choice_is_not_retried() -> None:
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            422,
            request=request,
            json={"error": {"message": "validation failed"}},
        )

    client = _openai_client(handler)
    with pytest.raises(LLMError) as exc_info:
        client.chat([{"role": "user", "content": "hello"}])

    assert exc_info.value.status == 422
    assert calls == 1
