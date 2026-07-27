from dataclasses import FrozenInstanceError

import pytest

from app.agents import prompt_releases
from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    LEGACY_RELEASE_ID,
    MODERN_RELEASE_ID,
    PROMPT_RELEASES,
    PromptReleaseNotPromotableError,
    UnknownPromptReleaseError,
    get_prompt_release,
    prompt_release_fingerprint,
    require_promotable_release,
    resolve_prompt_release,
)


def test_release_ids_are_unique_and_versioned() -> None:
    assert set(PROMPT_RELEASES) == {
        LEGACY_RELEASE_ID,
        COMPILED_STABLE_RELEASE_ID,
        MODERN_RELEASE_ID,
        CANDIDATE_RELEASE_ID,
    }
    assert all(
        prompt_releases.RELEASE_ID_RE.fullmatch(release_id)
        for release_id in PROMPT_RELEASES
    )


def test_prompt_release_is_immutable() -> None:
    release = get_prompt_release(COMPILED_STABLE_RELEASE_ID)

    with pytest.raises(FrozenInstanceError):
        release.label = "changed"  # type: ignore[misc]


@pytest.mark.parametrize("alias", [None, "", "current", "compact", "now", "unknown"])
def test_current_and_unknown_alias_resolve_only_to_stable(alias: str | None) -> None:
    release = resolve_prompt_release(alias, stable_release_id=COMPILED_STABLE_RELEASE_ID)

    assert release.release_id == COMPILED_STABLE_RELEASE_ID


@pytest.mark.parametrize("alias", ["legacy", "old", "20260625", "2026-06-25"])
def test_legacy_aliases_resolve_to_fixed_release(alias: str) -> None:
    release = resolve_prompt_release(alias, stable_release_id=CANDIDATE_RELEASE_ID)

    assert release.release_id == LEGACY_RELEASE_ID
    assert release.base_profile == "legacy"


@pytest.mark.parametrize("alias", ["modern", "full"])
def test_modern_aliases_resolve_to_fixed_release(alias: str) -> None:
    release = resolve_prompt_release(alias, stable_release_id=CANDIDATE_RELEASE_ID)

    assert release.release_id == MODERN_RELEASE_ID
    assert release.base_profile == "modern"


def test_concrete_release_id_resolves_without_aliasing() -> None:
    release = resolve_prompt_release(
        CANDIDATE_RELEASE_ID,
        stable_release_id=COMPILED_STABLE_RELEASE_ID,
    )

    assert release.release_id == CANDIDATE_RELEASE_ID


def test_missing_concrete_release_raises() -> None:
    with pytest.raises(UnknownPromptReleaseError):
        get_prompt_release("worker-2099-01-01-r1")


def test_compatibility_release_cannot_be_promoted() -> None:
    with pytest.raises(PromptReleaseNotPromotableError):
        require_promotable_release(LEGACY_RELEASE_ID)

    assert require_promotable_release(CANDIDATE_RELEASE_ID).promotable is True


def test_fingerprint_is_stable_and_covers_control_surface(monkeypatch) -> None:
    release = get_prompt_release(COMPILED_STABLE_RELEASE_ID)
    baseline = prompt_release_fingerprint(release)

    assert len(baseline) == 64
    assert prompt_release_fingerprint(release) == baseline

    monkeypatch.setattr(
        prompt_releases,
        "CONTROL_SURFACE_VERSION",
        "worker-control-v2-test",
    )

    assert prompt_release_fingerprint(release) != baseline


def test_fingerprint_changes_when_tool_schema_changes(monkeypatch) -> None:
    release = get_prompt_release(COMPILED_STABLE_RELEASE_ID)
    baseline = prompt_release_fingerprint(release)

    monkeypatch.setattr(
        prompt_releases,
        "worker_tool_schemas",
        lambda **_kwargs: [{"type": "function", "function": {"name": "changed"}}],
    )

    assert prompt_release_fingerprint(release) != baseline
