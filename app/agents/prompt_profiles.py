"""Small, testable contracts shared by the prompt compatibility facade."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PromptProfile:
    name: str
    label: str


CURRENT_PROFILE = PromptProfile(name="current", label="balanced compact")
MODERN_PROFILE = PromptProfile(name="modern", label="full current")
LEGACY_PROFILE = PromptProfile(name="legacy", label="legacy compatibility")

PROMPT_PROFILES = {
    profile.name: profile
    for profile in (CURRENT_PROFILE, MODERN_PROFILE, LEGACY_PROFILE)
}

_PROMPT_VERSION_ALIASES = {
    "": CURRENT_PROFILE.name,
    "current": CURRENT_PROFILE.name,
    "compact": CURRENT_PROFILE.name,
    "now": CURRENT_PROFILE.name,
    "modern": MODERN_PROFILE.name,
    "full": MODERN_PROFILE.name,
    "legacy": LEGACY_PROFILE.name,
    "old": LEGACY_PROFILE.name,
    "20260625": LEGACY_PROFILE.name,
    "2026-06-25": LEGACY_PROFILE.name,
}


def normalize_prompt_version(version: str | None) -> str:
    return _PROMPT_VERSION_ALIASES.get(
        str(version or "").strip().lower(),
        CURRENT_PROFILE.name,
    )


def trim_policy_text(text: str | None, *, limit: int = 8000) -> str:
    value = str(text or "").strip()
    if limit <= 0 or not value:
        return ""
    if len(value) <= limit:
        return value
    suffix = "\n...[truncated]"
    if limit <= len(suffix):
        return suffix[-limit:]
    return value[: limit - len(suffix)].rstrip() + suffix


def compose_reviewer_policy(base_prompt: str, src_rules: str | None) -> str:
    rules = trim_policy_text(src_rules, limit=8000)
    if not rules:
        return base_prompt
    return f"{base_prompt.rstrip()}\n\n# 当前任务 SRC 规则\n{rules}"


__all__ = [
    "CURRENT_PROFILE",
    "LEGACY_PROFILE",
    "MODERN_PROFILE",
    "PROMPT_PROFILES",
    "PromptProfile",
    "compose_reviewer_policy",
    "normalize_prompt_version",
    "trim_policy_text",
]
