import json

from app.agents import escalate as escalate_module
from app.agents import killsweep as killsweep_module
from app.agents.tool_dispatch import dispatch_tool_safely
from app.llm.protocols import LLMResponse, ToolCall


class _FakeExecutor:
    def __init__(self, *_args, **_kwargs) -> None:
        self.cancelled = False

    def cancel_running(self) -> None:
        self.cancelled = True


class _SequenceLLM:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self.responses = responses
        self.calls: list[list[dict]] = []

    def chat(self, messages, **_kwargs) -> LLMResponse:
        self.calls.append(messages)
        return self.responses[len(self.calls) - 1]


def _tool_response(call_id: str, name: str) -> LLMResponse:
    return LLMResponse(
        tool_calls=[ToolCall(id=call_id, name=name, arguments=json.dumps({}))]
    )


def _tool_responses(*calls: tuple[str, str]) -> LLMResponse:
    return LLMResponse(
        tool_calls=[
            ToolCall(id=call_id, name=name, arguments=json.dumps({}))
            for call_id, name in calls
        ]
    )


def _escalate_hunter(monkeypatch, llm: _SequenceLLM, *, max_rounds: int):
    monkeypatch.setattr(escalate_module, "ToolExecutor", _FakeExecutor)
    return escalate_module.EscalateHunter(
        {
            "severity": "high",
            "title": "Finding",
            "vuln_type": "idor",
            "target_url": "https://example.test",
        },
        llm=llm,
        max_rounds=max_rounds,
    )


def _killsweep_hunter(monkeypatch, llm: _SequenceLLM, *, max_rounds: int):
    monkeypatch.setattr(killsweep_module, "ToolExecutor", _FakeExecutor)
    monkeypatch.setattr(killsweep_module, "_MAX_ROUNDS", max_rounds)
    return killsweep_module.KillsweepHunter(
        {
            "title": "Finding",
            "vuln_type": "idor",
            "target_url": "https://example.test",
        },
        fofa_key="",
        llm=llm,
    )


def test_dispatch_tool_safely_returns_success_unchanged() -> None:
    events = []
    outcome = dispatch_tool_safely(
        lambda name, args: {"ok": True, "name": name, "value": args["value"]},
        "lookup",
        {"value": 7},
        emit=lambda kind, **payload: events.append((kind, payload)),
    )

    assert outcome.failed is False
    assert outcome.result == {"ok": True, "name": "lookup", "value": 7}
    assert events == []


def test_dispatch_tool_safely_masks_secret_and_emits_failure() -> None:
    events = []

    def fail(_name, _args):
        raise RuntimeError("api_key=sk-super-secret-value password=hunter2")

    outcome = dispatch_tool_safely(
        fail,
        "lookup",
        {},
        emit=lambda kind, **payload: events.append((kind, payload)),
    )

    serialized = str(outcome.result)
    assert outcome.failed is True
    assert outcome.error_kind == "tool_exception"
    assert "sk-super-secret-value" not in serialized
    assert "hunter2" not in serialized
    assert outcome.result["error"]["kind"] == "tool_exception"
    assert events[0][0] == "tool_exception"


def test_dispatch_tool_safely_truncates_long_error() -> None:
    def fail(_name, _args):
        raise RuntimeError("x" * 2000)

    outcome = dispatch_tool_safely(
        fail,
        "lookup",
        {},
        emit=lambda *_args, **_kwargs: None,
    )

    assert len(outcome.result["error"]["message"]) <= 400


def test_escalate_continues_after_tool_exception_with_paired_response(
    monkeypatch,
) -> None:
    llm = _SequenceLLM(
        [
            _tool_response("call-failed", "lookup"),
            _tool_response("call-abandon", "abandon_escalation"),
        ]
    )
    hunter = _escalate_hunter(monkeypatch, llm, max_rounds=2)

    def dispatch(name, _args):
        if name == "lookup":
            raise RuntimeError("temporary tool failure")
        hunter._result = {"escalated": False, "reason": "done"}
        return {"ok": True}

    monkeypatch.setattr(hunter, "_dispatch", dispatch)

    result = hunter.run().model_dump()

    assert result["escalated"] is False
    assert any(
        item.get("role") == "tool" and item.get("tool_call_id") == "call-failed"
        for item in llm.calls[1]
    )


def test_escalate_injects_correction_after_three_consecutive_tool_exceptions(
    monkeypatch,
) -> None:
    llm = _SequenceLLM(
        [
            _tool_response("call-1", "lookup"),
            _tool_response("call-2", "lookup"),
            _tool_response("call-3", "lookup"),
            _tool_response("call-abandon", "abandon_escalation"),
        ]
    )
    hunter = _escalate_hunter(monkeypatch, llm, max_rounds=4)

    def dispatch(name, _args):
        if name == "lookup":
            raise RuntimeError("temporary tool failure")
        hunter._result = {"escalated": False, "reason": "done"}
        return {"ok": True}

    monkeypatch.setattr(hunter, "_dispatch", dispatch)

    hunter.run()

    assert any(
        "连续 3 次" in item.get("content", "")
        for item in llm.calls[3]
        if item.get("role") == "user"
    )


def test_escalate_stops_after_five_consecutive_tool_exceptions(monkeypatch) -> None:
    llm = _SequenceLLM(
        [_tool_response(f"call-{index}", "lookup") for index in range(1, 6)]
    )
    hunter = _escalate_hunter(monkeypatch, llm, max_rounds=6)
    monkeypatch.setattr(
        hunter,
        "_dispatch",
        lambda _name, _args: (_ for _ in ()).throw(
            RuntimeError("temporary tool failure")
        ),
    )

    result = hunter.run().model_dump()

    assert result["escalated"] is False
    assert result["failure_kind"] == "tool_exception"
    assert "连续 5 次工具执行异常" in result["reason"]
    assert len(llm.calls) == 5


def test_killsweep_pairs_all_tool_responses_when_first_call_raises(
    monkeypatch,
) -> None:
    llm = _SequenceLLM(
        [
            _tool_responses(
                ("call-failed", "lookup"),
                ("call-success", "lookup_backup"),
            ),
            _tool_response("call-submit", "submit_killsweep"),
        ]
    )
    hunter = _killsweep_hunter(monkeypatch, llm, max_rounds=2)

    def dispatch(name, _args):
        if name == "lookup":
            raise RuntimeError("temporary tool failure")
        if name == "submit_killsweep":
            hunter._result = {"is_killsweep": False, "reason": "done"}
        return {"ok": True}

    monkeypatch.setattr(hunter, "_dispatch", dispatch)

    result = hunter.run().model_dump()
    tool_messages = [
        item for item in llm.calls[1] if item.get("role") == "tool"
    ]

    assert [item["tool_call_id"] for item in tool_messages] == [
        "call-failed",
        "call-success",
    ]
    assert result["is_killsweep"] is False


def test_killsweep_injects_correction_after_three_consecutive_tool_exceptions(
    monkeypatch,
) -> None:
    llm = _SequenceLLM(
        [
            _tool_response("call-1", "lookup"),
            _tool_response("call-2", "lookup"),
            _tool_response("call-3", "lookup"),
            _tool_response("call-submit", "submit_killsweep"),
        ]
    )
    hunter = _killsweep_hunter(monkeypatch, llm, max_rounds=4)

    def dispatch(name, _args):
        if name == "lookup":
            raise RuntimeError("temporary tool failure")
        hunter._result = {"is_killsweep": False, "reason": "done"}
        return {"ok": True}

    monkeypatch.setattr(hunter, "_dispatch", dispatch)

    hunter.run()

    assert any(
        "连续 3 次" in item.get("content", "")
        for item in llm.calls[3]
        if item.get("role") == "user"
    )


def test_killsweep_stops_after_five_consecutive_tool_exceptions(monkeypatch) -> None:
    llm = _SequenceLLM(
        [_tool_response(f"call-{index}", "lookup") for index in range(1, 6)]
    )
    hunter = _killsweep_hunter(monkeypatch, llm, max_rounds=6)
    monkeypatch.setattr(
        hunter,
        "_dispatch",
        lambda _name, _args: (_ for _ in ()).throw(
            RuntimeError("temporary tool failure")
        ),
    )

    result = hunter.run().model_dump()

    assert result["failure_kind"] == "tool_exception"
    assert result["is_killsweep"] is False
    assert "连续 5 次工具执行异常" in result["error"]
    assert len(llm.calls) == 5
