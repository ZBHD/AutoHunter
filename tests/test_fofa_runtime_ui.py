from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.config import FofaKeyConfig
from app.fofa.router import FofaKeyRouter
from app.fofa.runtime import public_runtime_summary


NOW = datetime(2026, 7, 17, 0, 0, tzinfo=timezone.utc)


def test_public_runtime_summary_distinguishes_pool_active_and_task_last_key() -> None:
    router = FofaKeyRouter(
        [
            FofaKeyConfig(name="Primary", key="secret-a"),
            FofaKeyConfig(
                name="Backup",
                key="secret-b",
                runtime_state="rate_limited",
                cooldown_until=NOW + timedelta(hours=1),
            ),
        ],
        active_name="Primary",
    )
    task = SimpleNamespace(
        fofa_config={
            "last_key_name": "Backup",
            "last_rotation": {
                "from_key_name": "Primary",
                "to_key_name": "Backup",
                "reason": "rate_limit",
                "key": "must-not-leak",
            },
        }
    )

    result = public_runtime_summary(task, router, now=NOW)

    assert result == {
        "key_source": "global_pool",
        "active_key_name": "Primary",
        "last_key_name": "Backup",
        "pool_available": 1,
        "pool_total": 2,
        "pool_state": "ready",
        "last_rotation": {
            "from_key_name": "Primary",
            "to_key_name": "Backup",
            "reason": "rate_limit",
        },
        "cooldown_until": "2026-07-17T01:00:00Z",
    }
    assert "secret" not in repr(result)
    assert "must-not-leak" not in repr(result)


def test_public_runtime_summary_marks_all_cooling_with_earliest_retry() -> None:
    retry = NOW + timedelta(minutes=20)
    router = FofaKeyRouter(
        [
            FofaKeyConfig(
                name="Primary",
                key="secret-a",
                runtime_state="rate_limited",
                cooldown_until=NOW + timedelta(minutes=40),
            ),
            FofaKeyConfig(
                name="Backup",
                key="secret-b",
                runtime_state="daily_cooldown",
                cooldown_until=retry,
            ),
        ],
        active_name="Primary",
    )

    result = public_runtime_summary(SimpleNamespace(fofa_config={}), router, now=NOW)

    assert result["pool_state"] == "cooling"
    assert result["pool_available"] == 0
    assert result["cooldown_until"] == "2026-07-17T00:20:00Z"


def test_public_runtime_summary_marks_task_override_without_global_active_key() -> None:
    router = FofaKeyRouter(
        [FofaKeyConfig(name="Task override", key="secret")],
        active_name="Task override",
    )

    result = public_runtime_summary(
        SimpleNamespace(fofa_config={"key": "secret", "last_key_name": "Task override"}),
        router,
        now=NOW,
    )

    assert result["key_source"] == "task_override"
    assert result["active_key_name"] == ""
    assert result["last_key_name"] == "Task override"
    assert result["pool_total"] == 1


def test_public_runtime_summary_marks_legacy_even_when_key_is_missing() -> None:
    router = FofaKeyRouter(
        [FofaKeyConfig(name="Legacy Key", key="")],
        active_name="Legacy Key",
    )

    result = public_runtime_summary(SimpleNamespace(fofa_config={}), router, now=NOW)

    assert result["key_source"] == "legacy"
    assert result["active_key_name"] == ""
    assert result["pool_total"] == 0
    assert result["pool_state"] == "blocked"


def test_public_runtime_summary_distinguishes_disabled_blocked_and_expired_cooling() -> None:
    router = FofaKeyRouter(
        [
            FofaKeyConfig(name="Disabled", key="secret-a", enabled=False),
            FofaKeyConfig(
                name="Auth",
                key="secret-b",
                runtime_state="auth_invalid",
                failure_kind="auth",
            ),
            FofaKeyConfig(
                name="Daily",
                key="secret-c",
                runtime_state="daily_suspended",
                failure_kind="daily_limit",
            ),
            FofaKeyConfig(
                name="Recovered",
                key="secret-d",
                runtime_state="rate_limited",
                failure_kind="rate_limit",
                cooldown_until=NOW - timedelta(seconds=1),
            ),
        ]
    )

    result = public_runtime_summary(SimpleNamespace(fofa_config={}), router, now=NOW)

    assert result["pool_total"] == 4
    assert result["pool_available"] == 1
    assert result["pool_state"] == "ready"
    assert result["cooldown_until"] is None


def test_public_runtime_summary_drops_invalid_rotation_reason() -> None:
    router = FofaKeyRouter([FofaKeyConfig(name="Primary", key="secret-a")])
    task = SimpleNamespace(
        fofa_config={
            "last_rotation": {
                "from_key_name": "Primary",
                "to_key_name": "Backup",
                "reason": "transient",
            }
        }
    )

    result = public_runtime_summary(task, router, now=NOW)

    assert result["last_rotation"] is None
