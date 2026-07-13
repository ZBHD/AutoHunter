from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from app.agents import reviewer as reviewer_module
from app.agents import worker as worker_module
from app.agents.collector_llm import generate_query
from app.api import findings as findings_api
from app.llm.protocols import LLMResponse, ToolCall
from app.schemas import Finding


class RecordingBackend:
    def __init__(self, responses: list[LLMResponse | Exception]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def chat(self, messages, **kwargs):
        self.calls.append({"messages": messages, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_collector_reads_normalized_tool_arguments_and_uses_auto_choice() -> None:
    backend = RecordingBackend([
        LLMResponse(tool_calls=[
            ToolCall(
                id="query-1",
                name="gen_query",
                arguments=json.dumps({"query": 'domain="example.edu.cn"', "reason": "scope"}),
            )
        ])
    ])

    result = generate_query(backend, "find assets", ["idor"], [])

    assert result == {"query": 'domain="example.edu.cn"', "reason": "scope"}
    assert backend.calls[0]["tool_choice"] == "auto"


def test_worker_preserves_response_continuation_in_next_round(monkeypatch) -> None:
    class FakeExecutor:
        def __init__(self, *args, **kwargs) -> None:
            pass

    monkeypatch.setattr(worker_module, "ToolExecutor", FakeExecutor)
    first = LLMResponse(
        content="checking",
        tool_calls=[ToolCall(id="probe-1", name="unknown_probe", arguments="{}")],
        continuation={
            "protocol": "openai_responses",
            "output": [{"type": "reasoning", "id": "reasoning-1"}],
        },
    )
    backend = RecordingBackend([first, RuntimeError("stop after history capture")])
    worker = worker_module.Worker("https://example.test", llm=backend)

    worker.run()

    assert len(backend.calls) == 2
    assert first.as_history_message() in backend.calls[1]["messages"]


def test_reviewer_answers_every_declared_tool_call_before_retrying() -> None:
    invalid = LLMResponse(tool_calls=[
        ToolCall(id="review-1", name="submit_review", arguments="{}"),
        ToolCall(id="review-2", name="submit_review", arguments="{}"),
    ])
    valid = LLMResponse(tool_calls=[
        ToolCall(
            id="review-3",
            name="submit_review",
            arguments=json.dumps({
                "verdict": "ignored",
                "confidence": "uncertain",
                "severity_final": None,
                "score": 1,
                "in_scope": True,
                "is_duplicate": False,
                "ignore_reasons": ["insufficient evidence"],
                "downgrade_reasons": [],
                "reproduced": False,
                "reviewer_notes": "not enough evidence",
                "deepen_directive": "",
            }),
        ),
    ])
    backend = RecordingBackend([invalid, valid])
    reviewer = reviewer_module.Reviewer(backend, enable_reproduce=False)
    finding = Finding(
        vuln_type="idor",
        title="Example finding",
        severity_claimed="中危",
        target_url="https://example.test/item/1",
        description="Insufficient evidence",
        steps=["Request the item"],
        poc="curl https://example.test/item/1",
    )

    result = reviewer._llm_review(finding)

    assert result is not None
    retry_messages = backend.calls[1]["messages"]
    answered_ids = [
        message["tool_call_id"]
        for message in retry_messages
        if message.get("role") == "tool"
    ]
    assert answered_ids == ["review-1", "review-2"]


def test_consumers_do_not_reference_legacy_client_shapes() -> None:
    root = Path(__file__).resolve().parents[1]
    paths = [
        "app/orchestrator.py",
        "app/agents/worker.py",
        "app/agents/reviewer.py",
        "app/agents/collector.py",
        "app/agents/collector_llm.py",
        "app/agents/killsweep.py",
        "app/agents/escalate.py",
        "app/api/findings.py",
    ]

    for relative in paths:
        source = (root / relative).read_text(encoding="utf-8")
        assert "tc.function." not in source, relative
        assert "llm_client_for_task" not in source, relative
        assert "LLMClient()" not in source, relative


@pytest.mark.parametrize(
    "endpoint",
    [findings_api.report_assistant, findings_api.report_assistant_stream],
)
def test_report_assistant_returns_safe_error_when_router_cannot_be_built(
    monkeypatch, endpoint
) -> None:
    finding = SimpleNamespace(task_id="task-1", assistant_messages=[])
    task = SimpleNamespace(id="task-1")

    class Result:
        def scalar_one_or_none(self):
            return None

    class Session:
        async def get(self, model, object_id):
            if model.__name__ == "Finding":
                return finding
            if model.__name__ == "Task":
                return task
            return None

        async def execute(self, _statement):
            return Result()

    def unavailable(_task):
        raise RuntimeError("no enabled providers")

    monkeypatch.setattr(findings_api, "_llm_for_task", unavailable)
    request = findings_api.ReportAssistantRequest(message="check")

    with pytest.raises(HTTPException) as exc_info:
        asyncio.run(endpoint("finding-1", request, Session()))

    assert exc_info.value.status_code == 503
    assert exc_info.value.detail == "报告助手暂不可用：请检查 LLM Provider 配置"


def test_streaming_report_assistant_reports_provider_exhaustion(monkeypatch) -> None:
    finding = SimpleNamespace(task_id="task-1", assistant_messages=[])
    task = SimpleNamespace(id="task-1")

    class Result:
        def scalar_one_or_none(self):
            return None

    class Session:
        async def get(self, model, object_id):
            if model.__name__ == "Finding":
                return finding
            if model.__name__ == "Task":
                return task
            return None

        async def execute(self, _statement):
            return Result()

        async def commit(self):
            return None

        async def rollback(self):
            return None

    def fail_assistant(*_args, **_kwargs):
        raise findings_api.AllProvidersExhaustedError([])

    monkeypatch.setattr(findings_api, "_report_assistant_llm", lambda _task: object())
    monkeypatch.setattr(findings_api, "_run_report_assistant", fail_assistant)
    monkeypatch.setattr(
        findings_api,
        "agent_semaphore",
        lambda _kind: asyncio.Semaphore(1),
    )

    async def consume() -> str:
        response = await findings_api.report_assistant_stream(
            "finding-1",
            findings_api.ReportAssistantRequest(message="check"),
            Session(),
        )
        chunks = []
        async for chunk in response.body_iterator:
            chunks.append(chunk.decode() if isinstance(chunk, bytes) else chunk)
        return "".join(chunks)

    stream = asyncio.run(consume())

    assert "报告助手暂不可用" in stream
    assert "已完成。" not in stream
    assert "报告助手暂不可用" in finding.assistant_messages[-1]["content"]
