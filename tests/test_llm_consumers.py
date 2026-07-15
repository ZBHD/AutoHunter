from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException

from app.agents import reviewer as reviewer_module
from app.agents import worker as worker_module
from app.agents.collector_llm import generate_query
from app.api import findings as findings_api
from app.deepen_context import build_finding_deepen_context
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


def _capture_first_worker_messages(monkeypatch, **worker_kwargs):
    class FakeExecutor:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

    monkeypatch.setattr(worker_module, "ToolExecutor", FakeExecutor)
    backend = RecordingBackend([RuntimeError("stop after first message capture")])
    worker = worker_module.Worker(
        "https://example.test",
        llm=backend,
        **worker_kwargs,
    )

    worker.run()

    assert len(backend.calls) == 1
    return backend.calls[0]["messages"]


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


def test_worker_places_hunt_direction_once_in_task_user_message(monkeypatch) -> None:
    direction = "优先测试后台 API 的对象级越权"

    directed = _capture_first_worker_messages(
        monkeypatch,
        hunt_direction=direction,
    )
    undirected = _capture_first_worker_messages(monkeypatch)

    task_message = directed[2]["content"]
    assert task_message.count("# 用户指定的任务挖掘方向") == 1
    assert task_message.count(direction) == 1
    assert "不得因此降低证据标准、越出授权范围" in task_message
    assert directed[0] == undirected[0]
    assert "# 用户指定的任务挖掘方向" not in undirected[2]["content"]


def test_worker_keeps_target_level_direction_ahead_of_task_direction(monkeypatch) -> None:
    messages = _capture_first_worker_messages(
        monkeypatch,
        hunt_direction="任务级方向 sentinel-task-direction",
        deepen_context={
            "directive": "目标级指令 sentinel-deepen-directive",
            "original_title": "待打穿线索",
        },
        target_meta={
            "source": "site-api",
            "site_collab_block": "目标级协作路线 sentinel-site-route\n\n",
        },
    )

    task_message = messages[2]["content"]
    direction_index = task_message.index("# 用户指定的任务挖掘方向")
    assert task_message.index("sentinel-site-route") < direction_index
    assert task_message.index("sentinel-deepen-directive") < direction_index
    assert "以更具体的目标级指令为先" in task_message


def test_worker_receives_v1_evidence_layers_without_assistant_answers(monkeypatch) -> None:
    finding = SimpleNamespace(
        id="finding-context",
        title="Context finding",
        vuln_type="idor",
        severity_claimed="高危",
        target_url="https://example.test/api/users/1",
        description="PRIOR_DESCRIPTION_SENTINEL",
        affected_scope="PRIOR_SCOPE_SENTINEL",
        steps=["PRIOR_STEP_SENTINEL"],
        poc="PRIOR_POC_SENTINEL",
        raw_request="RAW_REQUEST_SENTINEL",
        raw_response="RAW_RESPONSE_SENTINEL",
        evidence={"proof": "RAW_EVIDENCE_SENTINEL"},
        kill_chain=[],
        self_check={},
        assistant_messages=[
            {"role": "assistant", "content": "ASSISTANT_ANSWER_MUST_NOT_TRANSFER"},
            {"role": "user", "content": "USER_QUESTION_SENTINEL"},
        ],
    )
    context = build_finding_deepen_context(
        finding=finding,
        review=SimpleNamespace(
            verdict="accepted", confidence="likely", reproduced=False,
            reviewer_notes="REVIEW_NOTES_SENTINEL", user_notes="", user_edits={},
        ),
        directive="VERIFY_DIRECTIVE_SENTINEL",
        source="user",
        depth_policy={"objective": "DEPTH_OBJECTIVE_SENTINEL"},
    )

    messages = _capture_first_worker_messages(monkeypatch, deepen_context=context)
    task_message = messages[2]["content"]

    for sentinel in (
        "VERIFY_DIRECTIVE_SENTINEL",
        "RAW_REQUEST_SENTINEL",
        "RAW_RESPONSE_SENTINEL",
        "RAW_EVIDENCE_SENTINEL",
        "REVIEW_NOTES_SENTINEL",
        "USER_QUESTION_SENTINEL",
        "DEPTH_OBJECTIVE_SENTINEL",
    ):
        assert sentinel in task_message
    assert "ASSISTANT_ANSWER_MUST_NOT_TRANSFER" not in task_message
    assert "[RAW_OBSERVATION]" in task_message
    assert "[PRIOR_MODEL_CLAIM]" in task_message


def test_non_worker_agents_do_not_reference_task_hunt_direction() -> None:
    root = Path(__file__).resolve().parents[1]
    for relative in (
        "app/agents/collector.py",
        "app/agents/reviewer.py",
        "app/agents/escalate.py",
        "app/agents/killsweep.py",
    ):
        source = (root / relative).read_text(encoding="utf-8")
        assert "hunt_direction" not in source, relative


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


@pytest.mark.parametrize(
    "command",
    [
        "nuclei -u https://example.test",
        "dalfox url https://example.test/?q=x",
    ],
)
def test_enterprise_report_assistant_blocks_automated_scanners(monkeypatch, tmp_path, command: str) -> None:
    captured: dict[str, Any] = {}
    real_executor = findings_api.ToolExecutor

    def factory(*args, **kwargs):
        captured.update(kwargs)
        kwargs["work_dir"] = str(tmp_path)
        return real_executor(*args, **kwargs)

    monkeypatch.setattr(findings_api, "ToolExecutor", factory)
    backend = RecordingBackend([
        LLMResponse(tool_calls=[ToolCall(
            id="scan-1",
            name="run_shell",
            arguments=json.dumps({"command": command}),
        )]),
        LLMResponse(content="已完成最小验证。"),
    ])
    finding = SimpleNamespace(
        id="finding-1",
        vuln_type="idor",
        title="Example finding",
        severity_claimed="中危",
        target_url="https://example.test/item/1",
        owner="Example Corp",
        description="Example evidence",
        steps=["Request the item"],
        poc="curl https://example.test/item/1",
        affected_scope="one item",
        raw_request="GET /item/1 HTTP/1.1\r\nHost: example.test\r\n\r\n",
        raw_response="HTTP/1.1 200 OK\r\n\r\n{}",
        evidence={},
        kill_chain=[],
        self_check={},
    )

    result = findings_api._run_report_assistant(
        backend,
        finding,
        None,
        findings_api.ReportAssistantRequest(message="verify"),
        threading.Event(),
        enterprise=True,
    )

    assert captured["enterprise"] is True
    tool_result = result["tool_logs"][0]["result"]
    assert tool_result["blocked"] is True
    assert "自动化漏洞扫描" in tool_result["error"]


def test_report_assistant_endpoint_propagates_enterprise_mode(monkeypatch) -> None:
    captured: dict[str, Any] = {}
    finding = SimpleNamespace(task_id="task-1", assistant_messages=[])
    task = SimpleNamespace(id="task-1", src_type="enterprise")

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

    def run_assistant(*_args, **kwargs):
        captured.update(kwargs)
        return {"answer": "ok", "tool_logs": []}

    monkeypatch.setattr(findings_api, "_report_assistant_llm", lambda _task: object())
    monkeypatch.setattr(findings_api, "_run_report_assistant", run_assistant)
    monkeypatch.setattr(
        findings_api,
        "agent_semaphore",
        lambda _kind: asyncio.Semaphore(1),
    )

    asyncio.run(findings_api.report_assistant(
        "finding-1",
        findings_api.ReportAssistantRequest(message="verify"),
        Session(),
    ))

    assert captured["enterprise"] is True
