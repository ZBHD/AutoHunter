from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.agents import escalate as escalate_module
from app.agents import worker as worker_module
from app.agents.deepen import apply_deepen
from app.agents.depth_policy import depth_policy_for
from app.agents.prompts import should_escalate
from app.agents.prompts import worker_system_prompt
from app.agents.worker import Worker


def test_depth_policy_normalizes_all_severity_tiers() -> None:
    assert depth_policy_for("low").severity == "低危"
    assert depth_policy_for("中").severity == "中危"
    assert depth_policy_for("high").severity == "高危"
    assert depth_policy_for("critical").severity == "严重"
    assert depth_policy_for("unexpected").severity == "中危"


def test_depth_policy_increases_deepening_effort_by_tier() -> None:
    policies = [
        depth_policy_for("低危"),
        depth_policy_for("中危"),
        depth_policy_for("高危"),
        depth_policy_for("严重"),
    ]

    assert [item.deepen_cap for item in policies] == [1, 2, 3, 3]
    assert [item.priority_bonus for item in policies] == [80.0, 100.0, 130.0, 160.0]
    assert [item.soft_round_ratio for item in policies] == [0.6, 0.72, 0.85, 0.95]
    assert [item.escalation_rounds for item in policies] == [6, 10, 14, 16]


def test_apply_deepen_uses_tier_cap_and_persists_policy_snapshot() -> None:
    low_finding = SimpleNamespace(
        id="finding-low",
        status="pending_review",
        dedup_key="low-key",
        vuln_type="xss",
        title="Low signal",
        description="description",
        severity_claimed="低危",
    )
    low_target = SimpleNamespace(
        deepen_count=1,
        priority_score=10.0,
        status="done",
        assigned_worker="w-low",
        retry_count=0,
        verdict="found",
        heartbeat_at=object(),
        dead_reason="",
        deepen_context=None,
    )

    applied, reason = apply_deepen(None, low_finding, low_target, "try one more step")

    assert applied is False
    assert low_finding.status == "reviewed"
    assert "上限(1)" in reason

    high_finding = SimpleNamespace(
        id="finding-high",
        status="pending_review",
        dedup_key="high-key",
        vuln_type="idor",
        title="High signal",
        description="description",
        severity_claimed="高危",
    )
    high_target = SimpleNamespace(
        deepen_count=2,
        priority_score=10.0,
        status="done",
        assigned_worker="w-high",
        retry_count=1,
        verdict="found",
        heartbeat_at=object(),
        dead_reason="old",
        deepen_context=None,
    )

    applied, _reason = apply_deepen(None, high_finding, high_target, "verify admin scope")

    assert applied is True
    assert high_target.status == "queued"
    assert high_target.priority_score == 140.0
    assert high_target.deepen_context["depth_policy"]["severity"] == "高危"
    assert high_target.deepen_context["depth_policy"]["deepen_cap"] == 3


def test_apply_deepen_prefers_effective_review_severity() -> None:
    finding = SimpleNamespace(
        id="finding-adjusted",
        status="reviewed",
        dedup_key="adjusted-key",
        vuln_type="idor",
        title="Adjusted severity",
        description="description",
        severity_claimed="低危",
    )
    target = SimpleNamespace(
        deepen_count=2,
        priority_score=10.0,
        status="done",
        assigned_worker="w-adjusted",
        retry_count=0,
        verdict="found",
        heartbeat_at=None,
        dead_reason="",
        deepen_context=None,
    )

    applied, _reason = apply_deepen(
        None,
        finding,
        target,
        "continue with high-risk scope",
        severity="高危",
    )

    assert applied is True
    assert target.deepen_context["depth_policy"]["severity"] == "高危"


@pytest.mark.parametrize("severity", ["低危", "中危", "高危", "严重"])
def test_every_valid_severity_can_trigger_post_review_deep_hunting(severity: str) -> None:
    assert should_escalate("business_logic", "accepted finding", severity) is True


def test_invalid_severity_does_not_trigger_post_review_deep_hunting() -> None:
    assert should_escalate("idor", "accepted finding", "") is False


def test_worker_soft_round_budget_uses_deepening_tier_without_raising_hard_cap() -> None:
    worker = Worker.__new__(Worker)
    worker.target_meta = {}
    worker._enterprise = False
    worker.deepen_context = {
        "depth_policy": depth_policy_for("高危").as_dict(),
    }

    max_rounds, soft_rounds = worker._route_rounds(90, 45)

    assert max_rounds == 90
    assert soft_rounds == 77


def test_worker_tier_soft_rounds_respect_explicit_budget_cap(monkeypatch) -> None:
    monkeypatch.setattr(worker_module.worker_config, "soft_round_budget_cap", 50)
    worker = Worker.__new__(Worker)
    worker.target_meta = {}
    worker._enterprise = False
    worker.deepen_context = {
        "depth_policy": depth_policy_for("高危").as_dict(),
    }

    max_rounds, soft_rounds = worker._route_rounds(90, 45)

    assert max_rounds == 90
    assert soft_rounds == 50


def test_escalation_hunter_uses_tier_objective_and_round_budget(monkeypatch) -> None:
    class FakeExecutor:
        def __init__(self, *_args, **_kwargs) -> None:
            pass

    monkeypatch.setattr(escalate_module, "ToolExecutor", FakeExecutor)
    hunter = escalate_module.EscalateHunter(
        {
            "severity": "高危",
            "title": "High finding",
            "vuln_type": "idor",
            "target_url": "https://example.test",
        },
        llm=object(),
    )
    policy = depth_policy_for("高危")

    assert hunter.max_rounds == policy.escalation_rounds
    assert policy.objective in hunter._brief()
    assert all(requirement in hunter._brief() for requirement in policy.evidence_requirements)


@pytest.mark.parametrize("src_type", ["edusrc", "enterprise"])
def test_worker_prompt_explains_structured_tool_selection(src_type: str) -> None:
    prompt = worker_system_prompt(src_type, "current")

    for tool_name in (
        "extract_http_surface",
        "analyze_javascript",
        "analyze_api_schema",
        "analyze_auth_material",
        "compare_http_responses",
    ):
        assert tool_name in prompt
