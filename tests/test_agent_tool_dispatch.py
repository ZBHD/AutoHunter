from app.agents.tool_dispatch import dispatch_tool_safely


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
