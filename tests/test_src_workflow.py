from __future__ import annotations

import json
from types import SimpleNamespace

from app.agents import worker as worker_module
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
