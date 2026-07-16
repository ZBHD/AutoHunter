from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents import worker as worker_module
from app.agents.history import bounded_tool_content
from app.db.models import Base, Target, Task, TaskEvent
from app.llm.protocols import LLMResponse, ToolCall


def _candidate(
    url: str = "https://app.test/admin",
    *,
    priority: int = 9,
) -> dict:
    return {
        "kind": "endpoint",
        "endpoint_key": url,
        "value": url,
        "method": "GET",
        "parameter": "",
        "location": "path",
        "status_code": 403,
        "confidence": 0.9,
        "priority": priority,
        "reason": "crawl_endpoints",
    }


def _src_result(candidate: dict | None = None) -> dict:
    items = [candidate or _candidate()]
    return {
        "ok": True,
        "process_ok": True,
        "parse_ok": True,
        "failure_kind": "",
        "tool": "crawl_endpoints",
        "summary": {
            "tool": "crawl_endpoints",
            "parse_ok": True,
            "count": len(items),
            "head_candidates": items,
            "tail_candidates": items,
            "priority_candidates": items,
            "omitted": 0,
            "parse_errors": [],
            "next_actions": ["verify"],
            "partial": False,
            "remaining_unknown": False,
            "failure_kind": "",
        },
        "_capture": {"id": "capture-cli", "channels": []},
    }


class _WorkflowExecutor:
    src_calls = 0

    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def run_src_tool(self, _name, _args):
        type(self).src_calls += 1
        return _src_result()

    def http_request(self, **kwargs):
        return {
            "ok": True,
            "status_code": 403,
            "url": kwargs["url"],
            "response_headers": {},
            "body": "forbidden",
            "_capture": {"id": "capture-http", "channels": []},
        }


class _ScriptedWorkflowLLM:
    def __init__(self) -> None:
        self.responses = [
            LLMResponse(tool_calls=[ToolCall(
                id="crawl-1",
                name="crawl_endpoints",
                arguments=json.dumps({"url": "https://app.test"}),
            )]),
            LLMResponse(tool_calls=[ToolCall(
                id="http-1",
                name="http_request",
                arguments=json.dumps({"url": "https://app.test/admin"}),
            )]),
            LLMResponse(tool_calls=[ToolCall(
                id="finish-1",
                name="finish",
                arguments=json.dumps({
                    "verdict": "no_vuln",
                    "summary": "候选端点已复核为 403，仅证明入口存在",
                }),
            )]),
        ]

    def chat(self, _messages, **_kwargs):
        return self.responses.pop(0)


def test_worker_cli_candidate_http_verification_then_finish(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _WorkflowExecutor)
    worker = worker_module.Worker(
        "https://app.test",
        llm=_ScriptedWorkflowLLM(),
    )

    result = worker.run()

    assert result.verdict.value == "no_vuln"
    assert result.lead_summary["counts"] == {"verified": 1}
    lead = next(iter(worker._pending_leads.values()))
    assert lead.status == "verified"
    assert lead.vulnerability_confirmed is False
    assert "capture-http" in lead.evidence_ids


def test_high_priority_pending_lead_blocks_no_vuln_finish(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _WorkflowExecutor)
    worker = worker_module.Worker("https://app.test", llm=SimpleNamespace())
    worker._register_src_leads(
        _src_result(),
        source_tool="crawl_endpoints",
        round_no=1,
    )

    result = worker._dispatch(
        "finish",
        {"verdict": "no_vuln", "summary": "done"},
        rnd=2,
    )

    assert result["ok"] is False
    assert result["kind"] == "premature_finish"
    assert "Verify GET https://app.test/admin" in result["error"]


def test_directed_deepen_and_submit_restore_workflow_stage(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _WorkflowExecutor)
    directed = worker_module.Worker(
        "https://app.test",
        llm=SimpleNamespace(),
        deepen_context={"directive": "verify admin"},
    )
    assert directed._workflow_stage == "verify"
    assert "crawl_endpoints" not in {
        item["function"]["name"] for item in directed._available_tool_schemas()
    }

    worker = worker_module.Worker("https://app.test", llm=SimpleNamespace())
    monkeypatch.setattr(worker, "_submit_finding", lambda _args: {"ok": True})
    first = worker._dispatch("submit_finding", {}, rnd=1)
    assert first["ok"] is True
    assert worker._workflow_stage == "locate"

    worker._register_src_leads(
        _src_result(),
        source_tool="crawl_endpoints",
        round_no=2,
    )
    second = worker._dispatch("submit_finding", {}, rnd=3)
    assert second["ok"] is True
    assert worker._workflow_stage == "verify"


def test_auto_finish_finalizes_pending_leads_into_deepen_summary(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _WorkflowExecutor)
    worker = worker_module.Worker("https://app.test", llm=SimpleNamespace())
    worker._register_src_leads(
        _src_result(),
        source_tool="crawl_endpoints",
        round_no=1,
    )

    worker._auto_finish("budget exhausted")

    assert worker._finished["lead_summary"]["counts"] == {"skipped": 1}
    assert worker._finished["deepen_lead"].startswith("Verify GET")
    assert next(iter(worker._pending_leads.values())).status == "skipped"


def test_cancel_exit_finalizes_leads_and_returns_summary(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _WorkflowExecutor)
    worker = worker_module.Worker("https://app.test", llm=SimpleNamespace())
    worker._register_src_leads(
        _src_result(),
        source_tool="crawl_endpoints",
        round_no=1,
    )
    worker.cancel_event.set()

    result = worker.run()

    assert result.verdict.value == "error"
    assert result.lead_summary["counts"] == {"skipped": 1}
    assert result.deepen_lead.startswith("Verify GET")


def test_finish_stops_later_tool_calls_in_same_llm_round(monkeypatch) -> None:
    monkeypatch.setattr(worker_module, "ToolExecutor", _WorkflowExecutor)
    _WorkflowExecutor.src_calls = 0

    class FinishThenCrawl:
        def chat(self, _messages, **_kwargs):
            return LLMResponse(tool_calls=[
                ToolCall(
                    id="finish-first",
                    name="finish",
                    arguments=json.dumps({
                        "verdict": "no_vuln",
                        "summary": "纯静态且无登录、无表单、无 API、无 JS",
                    }),
                ),
                ToolCall(
                    id="crawl-after-finish",
                    name="crawl_endpoints",
                    arguments=json.dumps({"url": "https://app.test"}),
                ),
            ])

    result = worker_module.Worker(
        "https://app.test",
        llm=FinishThenCrawl(),
    ).run()

    assert result.verdict.value == "no_vuln"
    assert _WorkflowExecutor.src_calls == 0


def test_src_history_keeps_head_tail_priority_and_failure_metadata(monkeypatch) -> None:
    monkeypatch.setattr(worker_module.worker_config, "output_truncate", 4000)
    monkeypatch.setattr(worker_module.worker_config, "llm_tool_output_truncate", 4000)

    def item(url: str, priority: int) -> dict:
        return _candidate(url, priority=priority)

    result = {
        "ok": False,
        "process_ok": False,
        "parse_ok": True,
        "failure_kind": "timeout",
        "tool": "crawl_endpoints",
        "output": "raw-output-should-not-dominate" * 1000,
        "summary": {
            "count": 99,
            "omitted": 90,
            "partial": True,
            "remaining_unknown": True,
            "head_candidates": [item("https://app.test/head-sentinel", 4)],
            "tail_candidates": [item("https://app.test/tail-sentinel", 6)],
            "priority_candidates": [item("https://app.test/priority-sentinel", 10)],
            "parse_errors": ["one", "two"],
            "next_actions": ["verify priority"],
        },
    }

    content = bounded_tool_content(result, "crawl_endpoints")

    assert "head-sentinel" in content
    assert "tail-sentinel" in content
    assert "priority-sentinel" in content
    assert '"failure_kind":"timeout"' in content
    assert '"remaining_unknown":true' in content
    assert "raw-output-should-not-dominate" not in content


def test_worker_emits_redacted_src_cli_lifecycle_and_finish_summary(monkeypatch) -> None:
    class QueryExecutor(_WorkflowExecutor):
        def run_src_tool(self, _name, _args):
            return _src_result(_candidate("https://app.test/admin?token=secret-value"))

    monkeypatch.setattr(worker_module, "ToolExecutor", QueryExecutor)
    events: list[tuple[str, dict]] = []
    worker = worker_module.Worker(
        "https://app.test",
        llm=_ScriptedWorkflowLLM(),
        on_event=lambda kind, data: events.append((kind, data)),
    )

    result = worker.run()

    started = next(data for kind, data in events if kind == "tool_src_cli_started")
    completed = next(data for kind, data in events if kind == "tool_src_cli_result")
    finished = next(data for kind, data in events if kind == "worker_finish")
    serialized = json.dumps([started, completed, finished], ensure_ascii=False)
    assert started == {"round": 1, "tool": "crawl_endpoints", "stage": "recon"}
    assert completed["count"] == 1
    assert completed["top_lead"].endswith("?token=")
    assert completed["stage"] == "verify"
    assert finished["lead_summary"]["counts"] == {"verified": 1}
    assert result.lead_summary["counts"] == {"verified": 1}
    for secret in ("secret-value", "_capture", "channels", "headers", "output"):
        assert secret not in serialized


def test_src_private_preview_keeps_bounded_summary_without_capture_descriptor() -> None:
    result = _src_result()
    result["_capture"] = {
        "id": "private-capture",
        "directory": "C:/private/path",
        "channels": [{"path": "C:/private/path/output.bin"}],
    }

    preview = worker_module.Worker._private_tool_preview(result)

    assert preview["process_ok"] is True
    assert preview["parse_ok"] is True
    assert preview["failure_kind"] == ""
    assert preview["summary"]["count"] == 1
    assert "_capture" not in preview
    assert "private-capture" not in repr(preview)


def test_public_src_projection_contains_status_and_bounded_candidates_only() -> None:
    from app.orchestrator import public_worker_event

    payload = {
        "tool": "crawl_endpoints",
        "url": "https://app.test/admin?token=secret-value",
        "capture": {
            "id": "private-capture",
            "directory": "C:/private/path",
            "channels": [{"path": "C:/private/path/output.bin"}],
        },
        "preview": {
            "ok": False,
            "process_ok": False,
            "parse_ok": True,
            "failure_kind": "timeout",
            "output": "raw-secret-output",
            "response_headers": {"Cookie": "secret-cookie"},
            "summary": {
                "count": 3,
                "remaining_unknown": True,
                "tail_candidates": [_candidate("https://app.test/tail?token=")],
            },
        },
    }

    projected = public_worker_event("tool_capture_private", payload)
    serialized = json.dumps(projected, ensure_ascii=False)

    assert projected["process_ok"] is False
    assert projected["parse_ok"] is True
    assert projected["failure_kind"] == "timeout"
    assert projected["summary"]["count"] == 3
    for secret in ("secret-value", "secret-cookie", "raw-secret-output", "private-capture", "output.bin"):
        assert secret not in serialized


def test_src_lead_summary_projection_is_bounded_and_scrubs_query_values() -> None:
    from app.orchestrator import _public_src_lead_summary

    projected = _public_src_lead_summary({
        "counts": {"verified": 4, "pending": 2, "unexpected": 999},
        "deepen_lead": "Verify GET https://app.test/admin?token=secret-value&next=one",
        "samples": [
            "https://app.test/a?cookie=secret-cookie",
            "https://app.test/b?x=1",
            "https://app.test/c?key=secret-key",
            "https://app.test/d?extra=drop",
        ],
        "capture": "private-capture",
    })

    assert projected["counts"] == {"verified": 4, "pending": 2}
    assert projected["deepen_lead"].endswith("?token=&next=")
    assert len(projected["samples"]) == 3
    serialized = json.dumps(projected, ensure_ascii=False)
    for secret in ("secret-value", "secret-cookie", "secret-key", "private-capture"):
        assert secret not in serialized


def test_worker_src_lead_summary_persists_as_bounded_event(tmp_path, monkeypatch) -> None:
    from app import orchestrator

    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'src-summary.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-src-summary", name="SRC summary", status="paused"))
            session.add(Target(
                id="target-src-summary",
                task_id="task-src-summary",
                url="https://app.test",
                host="app.test",
                status="scanning",
                assigned_worker="worker-1",
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-src-summary")
        await runner._persist_worker_result(
            "task-src-summary",
            "target-src-summary",
            {
                "verdict": "no_vuln",
                "findings": [],
                "summary": "候选已收敛",
                "lead_summary": {
                    "counts": {"verified": 2, "skipped": 1, "ignored": "drop"},
                    "deepen_lead": "Verify GET https://app.test/admin?token=secret-value",
                    "samples": [
                        "https://app.test/a?token=secret-value",
                        "https://app.test/b?sid=secret-cookie",
                        "https://app.test/c?key=secret-key",
                        "https://app.test/d?drop=4",
                    ],
                    "capture": "private-capture",
                },
            },
        )

        async with sessions() as session:
            event = await session.scalar(select(TaskEvent).where(
                TaskEvent.task_id == "task-src-summary",
                TaskEvent.kind == "worker_src_lead_summary",
            ))
            assert event is not None
            assert event.payload["counts"] == {"verified": 2, "skipped": 1}
            assert len(event.payload["samples"]) == 3
            serialized = json.dumps(event.payload, ensure_ascii=False)
            for secret in ("secret-value", "secret-cookie", "secret-key", "private-capture"):
                assert secret not in serialized
        await engine.dispose()

    asyncio.run(scenario())
