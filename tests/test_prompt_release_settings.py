import logging

from app import settings_service
from app.agents.prompt_releases import (
    CANDIDATE_RELEASE_ID,
    COMPILED_STABLE_RELEASE_ID,
    LEGACY_RELEASE_ID,
    MODERN_RELEASE_ID,
)
from app.db.models import Task


def _set_defaults(monkeypatch, defaults: dict) -> None:
    cache = dict(settings_service._cache)
    cache["defaults"] = defaults
    monkeypatch.setattr(settings_service, "_cache", cache)


def _task(prompt_version: str) -> Task:
    return Task(
        name="Prompt task",
        model_config_json={"prompt_version": prompt_version},
    )


def test_stable_prompt_release_defaults_to_compiled_release(monkeypatch) -> None:
    _set_defaults(monkeypatch, {})

    assert (
        settings_service.resolve_stable_prompt_release_id()
        == COMPILED_STABLE_RELEASE_ID
    )


def test_registered_database_stable_release_takes_precedence(monkeypatch) -> None:
    _set_defaults(
        monkeypatch,
        {"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
    )

    assert settings_service.resolve_stable_prompt_release_id() == CANDIDATE_RELEASE_ID


def test_missing_database_release_logs_and_falls_back(monkeypatch, caplog) -> None:
    missing = "worker-2099-01-01-r1"
    _set_defaults(monkeypatch, {"stable_prompt_release_id": missing})

    with caplog.at_level(logging.ERROR, logger="autohunter.settings"):
        resolved = settings_service.resolve_stable_prompt_release_id()

    assert resolved == COMPILED_STABLE_RELEASE_ID
    assert missing in caplog.text


def test_legacy_and_modern_tasks_remain_fixed_when_stable_changes(monkeypatch) -> None:
    _set_defaults(
        monkeypatch,
        {"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
    )

    assert settings_service.resolve_worker_prompt_release(_task("legacy")).release_id == LEGACY_RELEASE_ID
    assert settings_service.resolve_worker_prompt_release(_task("modern")).release_id == MODERN_RELEASE_ID


def test_current_and_unknown_task_aliases_follow_stable(monkeypatch) -> None:
    _set_defaults(
        monkeypatch,
        {"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
    )

    assert settings_service.resolve_worker_prompt_release(_task("current")).release_id == CANDIDATE_RELEASE_ID
    assert settings_service.resolve_worker_prompt_release(_task("unknown")).release_id == CANDIDATE_RELEASE_ID


def test_legacy_prompt_version_facade_returns_release_base_profile(monkeypatch) -> None:
    _set_defaults(
        monkeypatch,
        {"stable_prompt_release_id": CANDIDATE_RELEASE_ID},
    )

    assert settings_service.resolve_worker_prompt_version(_task("legacy")) == "legacy"
    assert settings_service.resolve_worker_prompt_version(_task("current")) == "current"


def test_public_settings_exposes_read_only_stable_channel_and_compatibility_field(
    monkeypatch,
) -> None:
    _set_defaults(
        monkeypatch,
        {
            "stable_prompt_release_id": CANDIDATE_RELEASE_ID,
            "worker_prompt_version": "legacy",
        },
    )

    defaults = settings_service.public_settings_view()["defaults"]

    assert defaults["worker_prompt_channel"] == "stable"
    assert defaults["stable_prompt_release_id"] == CANDIDATE_RELEASE_ID
    assert defaults["worker_prompt_version"] == "legacy"
