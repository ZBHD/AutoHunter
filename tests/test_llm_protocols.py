from __future__ import annotations

from copy import deepcopy

import pytest

from app.llm.protocols import (
    AnthropicMessagesAdapter,
    LLMResponse,
    OpenAIChatAdapter,
    OpenAIResponsesAdapter,
    ToolCall,
    UsageInfo,
)


TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup",
            "description": "Look up a value.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"],
            },
        },
    }
]


def _build(adapter, messages, *, tool_choice="auto"):
    return adapter.build_request(
        base_url="https://llm.example/v1",
        api_key="test-secret",
        model="test-model",
        messages=messages,
        tools=TOOLS,
        tool_choice=tool_choice,
        temperature=0.2,
        max_tokens=256,
    )


def test_tool_call_serializes_flat_contract_to_history_shape() -> None:
    call = ToolCall(id="call-1", name="lookup", arguments='{"query":"alpha"}')

    assert call.as_history_dict() == {
        "id": "call-1",
        "type": "function",
        "function": {"name": "lookup", "arguments": '{"query":"alpha"}'},
    }


def test_llm_response_serializes_history_with_opaque_continuation() -> None:
    continuation = {
        "protocol": "openai_responses",
        "output": [{"type": "reasoning", "id": "reasoning-1", "summary": []}],
    }
    response = LLMResponse(
        content="checking",
        tool_calls=[ToolCall(id="call-1", name="lookup", arguments="{}")],
        continuation=continuation,
    )

    assert response.as_history_message() == {
        "role": "assistant",
        "content": "checking",
        "tool_calls": [
            {
                "id": "call-1",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{}"},
            }
        ],
        "_llm_continuation": continuation,
    }


def test_openai_chat_strips_private_metadata_without_mutating_history() -> None:
    messages = [
        {"role": "assistant", "content": "", "_llm_continuation": {"opaque": True}},
        {
            "role": "tool",
            "tool_call_id": "call-1",
            "content": "result",
            "_round": 2,
            "_tool": "lookup",
        },
    ]
    original = deepcopy(messages)

    payload = _build(OpenAIChatAdapter(), messages)

    assert payload.body["messages"] == [
        {"role": "assistant", "content": ""},
        {"role": "tool", "tool_call_id": "call-1", "content": "result"},
    ]
    assert messages == original


def test_openai_chat_preserves_invalid_tool_arguments() -> None:
    raw_arguments = '{"query":'
    response = OpenAIChatAdapter().parse_response(
        {
            "choices": [
                {
                    "message": {
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call-1",
                                "type": "function",
                                "function": {"name": "lookup", "arguments": raw_arguments},
                            }
                        ],
                    }
                }
            ]
        }
    )

    assert response.tool_calls == [
        ToolCall(id="call-1", name="lookup", arguments=raw_arguments)
    ]


@pytest.mark.parametrize("choices", [[], None])
def test_openai_chat_handles_missing_choices(choices) -> None:
    response = OpenAIChatAdapter().parse_response({"choices": choices})

    assert response == LLMResponse()


def test_anthropic_uses_native_key_and_merges_adjacent_roles() -> None:
    messages = [
        {"role": "system", "content": "system rules"},
        {"role": "user", "content": "static prefix"},
        {"role": "user", "content": "target details"},
        {
            "role": "assistant",
            "content": "I will check both.",
            "tool_calls": [
                ToolCall("call-1", "lookup", '{"query":"alpha"}').as_history_dict(),
                ToolCall("call-2", "lookup", '{"query":"beta"}').as_history_dict(),
            ],
            "_llm_continuation": {"ignored": True},
        },
        {"role": "tool", "tool_call_id": "call-1", "content": "alpha-result"},
        {"role": "tool", "tool_call_id": "call-2", "content": "beta-result"},
        {"role": "user", "content": "continue"},
    ]

    payload = _build(AnthropicMessagesAdapter(), messages)

    assert payload.headers["x-api-key"] == "test-secret"
    assert "Authorization" not in payload.headers
    assert payload.body["system"] == "system rules"
    assert payload.body["messages"] == [
        {
            "role": "user",
            "content": [
                {"type": "text", "text": "static prefix"},
                {"type": "text", "text": "target details"},
            ],
        },
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "I will check both."},
                {
                    "type": "tool_use",
                    "id": "call-1",
                    "name": "lookup",
                    "input": {"query": "alpha"},
                },
                {
                    "type": "tool_use",
                    "id": "call-2",
                    "name": "lookup",
                    "input": {"query": "beta"},
                },
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "call-1",
                    "content": "alpha-result",
                },
                {
                    "type": "tool_result",
                    "tool_use_id": "call-2",
                    "content": "beta-result",
                },
                {"type": "text", "text": "continue"},
            ],
        },
    ]


def test_anthropic_preserves_invalid_tool_arguments_from_cross_provider_history() -> None:
    raw_arguments = '{"query":'
    messages = [
        {"role": "user", "content": "look up alpha"},
        LLMResponse(
            tool_calls=[ToolCall("call-1", "lookup", raw_arguments)],
        ).as_history_message(),
        {"role": "tool", "tool_call_id": "call-1", "content": "invalid arguments"},
    ]

    payload = _build(AnthropicMessagesAdapter(), messages)

    tool_use = payload.body["messages"][1]["content"][0]
    assert tool_use["type"] == "tool_use"
    assert tool_use["input"] == raw_arguments


def test_responses_rebuilds_function_calls_before_outputs_and_sends_none() -> None:
    messages = [
        {"role": "user", "content": "find both"},
        LLMResponse(
            content="checking",
            tool_calls=[
                ToolCall("call-1", "lookup", '{"query":"alpha"}'),
                ToolCall("call-2", "lookup", '{"query":"beta"}'),
            ],
        ).as_history_message(),
        {"role": "tool", "tool_call_id": "call-1", "content": "alpha-result"},
        {"role": "tool", "tool_call_id": "call-2", "content": "beta-result"},
    ]

    payload = _build(OpenAIResponsesAdapter(), messages, tool_choice="none")
    items = payload.body["input"]

    assert payload.body["tool_choice"] == "none"
    assert [item.get("type", "message") for item in items] == [
        "message",
        "message",
        "function_call",
        "function_call",
        "function_call_output",
        "function_call_output",
    ]
    assert items[2] == {
        "type": "function_call",
        "call_id": "call-1",
        "name": "lookup",
        "arguments": '{"query":"alpha"}',
    }
    assert items[4] == {
        "type": "function_call_output",
        "call_id": "call-1",
        "output": "alpha-result",
    }


def test_responses_parses_nested_text_and_preserves_opaque_output() -> None:
    raw_arguments = '{"query":'
    output = [
        {"type": "reasoning", "id": "reasoning-1", "summary": []},
        {
            "type": "message",
            "id": "message-1",
            "role": "assistant",
            "content": [
                {"type": "output_text", "text": "First."},
                {"type": "output_text", "text": " Second."},
            ],
        },
        {
            "type": "function_call",
            "id": "function-1",
            "call_id": "call-1",
            "name": "lookup",
            "arguments": raw_arguments,
        },
    ]

    response = OpenAIResponsesAdapter().parse_response({"output": output})

    assert response.content == "First. Second."
    assert response.tool_calls == [
        ToolCall(id="call-1", name="lookup", arguments=raw_arguments)
    ]
    assert response.continuation == {
        "protocol": "openai_responses",
        "output": output,
    }


def test_responses_prefers_top_level_output_text() -> None:
    response = OpenAIResponsesAdapter().parse_response(
        {
            "output_text": "Top-level response.",
            "output": [
                {
                    "type": "message",
                    "content": [{"type": "output_text", "text": "Nested response."}],
                }
            ],
        }
    )

    assert response.content == "Top-level response."


def test_responses_reuses_reasoning_continuation_without_duplicate_calls() -> None:
    raw = {
        "output": [
            {"type": "reasoning", "id": "reasoning-1", "summary": []},
            {
                "type": "function_call",
                "id": "function-1",
                "call_id": "call-1",
                "name": "lookup",
                "arguments": '{"query":"alpha"}',
            },
        ]
    }
    response = OpenAIResponsesAdapter().parse_response(raw)
    messages = [
        {"role": "user", "content": "find alpha"},
        response.as_history_message(),
        {"role": "tool", "tool_call_id": "call-1", "content": "alpha-result"},
    ]

    payload = _build(OpenAIResponsesAdapter(), messages)

    assert payload.body["input"][1:] == [
        *raw["output"],
        {
            "type": "function_call_output",
            "call_id": "call-1",
            "output": "alpha-result",
        },
    ]


def test_openai_chat_extracts_usage_and_cached_prompt_tokens() -> None:
    usage = OpenAIChatAdapter().extract_usage(
        {
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 5,
                "total_tokens": 17,
                "prompt_tokens_details": {"cached_tokens": 4},
                "prompt_cache_miss_tokens": 8,
            }
        }
    )

    assert usage == UsageInfo(
        prompt_tokens=12,
        completion_tokens=5,
        total_tokens=17,
        cache_hit_tokens=4,
        cache_miss_tokens=8,
    )


def test_anthropic_extracts_usage_and_cache_tokens() -> None:
    usage = AnthropicMessagesAdapter().extract_usage(
        {
            "usage": {
                "input_tokens": 9,
                "output_tokens": 6,
                "cache_read_input_tokens": 3,
                "cache_creation_input_tokens": 2,
            }
        }
    )

    assert usage == UsageInfo(
        prompt_tokens=9,
        completion_tokens=6,
        total_tokens=15,
        cache_hit_tokens=3,
        cache_miss_tokens=2,
    )


def test_responses_extracts_usage() -> None:
    usage = OpenAIResponsesAdapter().extract_usage(
        {"usage": {"input_tokens": 7, "output_tokens": 4, "total_tokens": 11}}
    )

    assert usage == UsageInfo(
        prompt_tokens=7,
        completion_tokens=4,
        total_tokens=11,
    )


def test_protocol_usage_defaults_to_zero() -> None:
    for adapter in (
        OpenAIChatAdapter(),
        AnthropicMessagesAdapter(),
        OpenAIResponsesAdapter(),
    ):
        assert adapter.extract_usage({}) == UsageInfo()
