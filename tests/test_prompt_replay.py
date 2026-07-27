import json

import pytest

from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    get_prompt_release,
)
from app.llm.protocols import LLMResponse, ToolCall
from app.prompt_replay import (
    PromptReplayRunner,
    ReplayFixtureError,
    build_replay_schedule,
    load_replay_fixtures,
)


def test_loads_four_unique_sanitized_replay_fixtures() -> None:
    fixtures = load_replay_fixtures()

    assert {fixture.case_id for fixture in fixtures} == {
        "ssrf-route",
        "xxe-route",
        "deserialization-route",
        "jwt-route",
    }


def test_loader_rejects_duplicate_case_ids(tmp_path) -> None:
    payload = {
        "schema_version": 1,
        "case_id": "duplicate",
        "src_type": "edusrc",
        "route_id": "generic_admin_api",
        "initial_context": {"target": "[TARGET]"},
        "scripted_tool_results": {"http_request": [{"ok": True}]},
        "allowed_tools": ["http_request", "finish"],
        "forbidden_tools": ["run_shell"],
        "expected_terminal_verdicts": ["no_vuln"],
        "required_evidence": ["status_code"],
        "max_rounds": 2,
        "max_total_tokens": 1000,
        "historical_human_outcome": "rejected",
    }
    (tmp_path / "a.json").write_text(json.dumps(payload), encoding="utf-8")
    (tmp_path / "b.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReplayFixtureError, match="duplicate"):
        load_replay_fixtures(tmp_path)


@pytest.mark.parametrize(
    "secret",
    [
        "Authorization: Bearer abcdefghijklmnop",
        "Cookie: session=plaintext-secret",
        "api_key=sk-super-secret-value",
        "13800138000",
        "11010519491231002X",
        "https://real-company.example.com/api",
        "192.168.10.22",
    ],
)
def test_loader_rejects_unsanitized_values(tmp_path, secret: str) -> None:
    payload = {
        "schema_version": 1,
        "case_id": "unsafe",
        "src_type": "edusrc",
        "route_id": "generic_admin_api",
        "initial_context": {"target": "[TARGET]", "unsafe": secret},
        "scripted_tool_results": {},
        "allowed_tools": ["finish"],
        "forbidden_tools": [],
        "expected_terminal_verdicts": ["no_vuln"],
        "required_evidence": [],
        "max_rounds": 1,
        "max_total_tokens": 1000,
        "historical_human_outcome": "rejected",
    }
    (tmp_path / "unsafe.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ReplayFixtureError, match="sanitized"):
        load_replay_fixtures(tmp_path)


def test_schedule_runs_each_release_three_times_in_seeded_pairs() -> None:
    fixtures = load_replay_fixtures()

    schedule = build_replay_schedule(
        fixtures,
        stable_release_id=COMPILED_STABLE_RELEASE_ID,
        candidate_release_id=CANDIDATE_RELEASE_ID,
        repeat=3,
        seed="seed",
    )

    assert len(schedule) == len(fixtures) * 2 * 3
    for fixture in fixtures:
        rows = [item for item in schedule if item.fixture.case_id == fixture.case_id]
        assert {item.run_number for item in rows} == {1, 2, 3}
        assert [item.release_id for item in rows].count(COMPILED_STABLE_RELEASE_ID) == 3
        assert [item.release_id for item in rows].count(CANDIDATE_RELEASE_ID) == 3
    assert schedule == build_replay_schedule(
        fixtures,
        stable_release_id=COMPILED_STABLE_RELEASE_ID,
        candidate_release_id=CANDIDATE_RELEASE_ID,
        repeat=3,
        seed="seed",
    )


class _SequenceLLM:
    def __init__(self, responses: list[LLMResponse]) -> None:
        self.responses = responses
        self.calls: list[list[dict]] = []

    def chat(self, messages, **_kwargs) -> LLMResponse:
        self.calls.append([dict(item) for item in messages])
        return self.responses[len(self.calls) - 1]


def test_runner_pairs_scripted_tool_results_without_target_network() -> None:
    fixture = load_replay_fixtures()[0]
    llm = _SequenceLLM([
        LLMResponse(tool_calls=[
            ToolCall(
                id="call-http",
                name="http_request",
                arguments=json.dumps({"url": "[TARGET]/preview?url=[CONTROLLED]"}),
            ),
        ]),
        LLMResponse(tool_calls=[
            ToolCall(
                id="call-finish",
                name="finish",
                arguments=json.dumps({"verdict": "no_vuln"}),
            ),
        ]),
    ])
    runner = PromptReplayRunner(lambda *_args, **_kwargs: llm)

    sample = runner.run_case(
        fixture,
        get_prompt_release(CANDIDATE_RELEASE_ID),
        experiment_id="experiment",
        run_number=1,
    )

    paired = [item for item in llm.calls[1] if item.get("role") == "tool"]
    assert [item["tool_call_id"] for item in paired] == ["call-http"]
    assert sample.terminal_verdict == "no_vuln"
    assert sample.tool_calls == 2
    assert sample.forbidden_action_count == 0


def test_runner_counts_undeclared_tool_and_external_url_as_forbidden() -> None:
    fixture = load_replay_fixtures()[0]
    llm = _SequenceLLM([
        LLMResponse(tool_calls=[
            ToolCall(
                id="call-forbidden",
                name="run_shell",
                arguments=json.dumps({"url": "https://outside.invalid/path"}),
            ),
            ToolCall(
                id="call-finish",
                name="finish",
                arguments=json.dumps({"verdict": "no_vuln"}),
            ),
        ]),
    ])
    runner = PromptReplayRunner(lambda *_args, **_kwargs: llm)

    sample = runner.run_case(
        fixture,
        get_prompt_release(CANDIDATE_RELEASE_ID),
        experiment_id="experiment",
        run_number=1,
    )

    assert sample.forbidden_action_count >= 1
    assert sample.metrics["protocol_error_count"] == 0


def test_runner_marks_compiled_stable_release_as_stable_cohort() -> None:
    fixture = load_replay_fixtures()[0]
    llm = _SequenceLLM([
        LLMResponse(tool_calls=[
            ToolCall(
                id="call-finish",
                name="finish",
                arguments=json.dumps({"verdict": "no_vuln"}),
            ),
        ]),
    ])

    sample = PromptReplayRunner(lambda *_args, **_kwargs: llm).run_case(
        fixture,
        get_prompt_release(COMPILED_STABLE_RELEASE_ID),
        experiment_id="experiment",
        run_number=1,
    )

    assert sample.cohort == "stable"
