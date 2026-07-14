from __future__ import annotations

from app.agents.prompt_profiles import (
    CURRENT_PROFILE,
    LEGACY_PROFILE,
    compose_reviewer_policy,
    normalize_prompt_version,
    trim_policy_text,
)
from app.agents.prompts import worker_system_prompt
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
