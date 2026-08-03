from __future__ import annotations

from app.agents.prompt_profiles import (
    CURRENT_PROFILE,
    LEGACY_PROFILE,
    compose_reviewer_policy,
    normalize_prompt_version,
    trim_policy_text,
)
from app.agents.prompts import (
    escalate_system_prompt,
    reviewer_system_prompt,
    worker_system_prompt,
)
from app.config import WorkerConfig


def test_prompt_profile_aliases_keep_legacy_compatibility() -> None:
    assert normalize_prompt_version(None) == CURRENT_PROFILE.name
    assert normalize_prompt_version("compact") == CURRENT_PROFILE.name
    assert normalize_prompt_version("2026-06-25") == LEGACY_PROFILE.name
    assert normalize_prompt_version("unknown") == CURRENT_PROFILE.name


def test_current_worker_prompt_is_materially_smaller_than_legacy() -> None:
    current = worker_system_prompt("edusrc", "current")
    legacy = worker_system_prompt("edusrc", "legacy")

    assert len(current) < len(legacy) * 0.6
    assert "check_duplicate_finding" in current
    assert "raw_request" in current
    assert "finish" in current


def test_reviewer_policy_trims_custom_rules_before_composition() -> None:
    rules = "RULE-BEGIN\n" + ("x" * 9000) + "\nRULE-END"

    trimmed = trim_policy_text(rules, limit=8000)
    composed = compose_reviewer_policy("BASE", rules)

    assert len(trimmed) == 8000
    assert trimmed.startswith("RULE-BEGIN")
    assert trimmed.endswith("[truncated]")
    assert composed.count("# 当前任务 SRC 规则") == 1
    assert composed.count("RULE-BEGIN") == 1
    assert "RULE-END" not in composed


def test_worker_runtime_default_uses_current_profile() -> None:
    assert WorkerConfig().prompt_version == "current"


def test_all_education_worker_profiles_keep_evidence_led_handoff_guard() -> None:
    for version in ("current", "modern", "legacy"):
        prompt = worker_system_prompt("edusrc", version)

        assert "经验先验 / 高产方向" in prompt
        assert "连续 2~3 轮原地打转" in prompt
        assert "finish.deepen_lead" in prompt


def test_escalation_and_reviewer_prompts_do_not_anchor_on_fixed_examples() -> None:
    escalation = escalate_system_prompt("edusrc")
    reviewer = reviewer_system_prompt("edusrc")

    assert "不是唯一路线" in escalation
    assert "不是系统名黑名单" in reviewer
    assert "同一把尺子" in reviewer


def test_write_actions_require_independent_readback_evidence() -> None:
    policy_texts = (
        worker_system_prompt("edusrc", "current"),
        worker_system_prompt("enterprise", "current"),
        reviewer_system_prompt("edusrc"),
        reviewer_system_prompt("enterprise"),
    )

    for policy in policy_texts:
        assert "侧面回读" in policy
        assert "before" in policy.lower()
        assert "after" in policy.lower()
        assert "200/success" in policy
