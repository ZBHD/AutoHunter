from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timedelta, timezone

import pytest

from app.config import FofaKeyConfig
from app.fofa.client import FofaError
from app.fofa.router import (
    FofaFailureKind,
    FofaKeyRouter,
    FofaPoolExhaustedError,
)


UTC = timezone.utc


def key(
    name: str,
    secret: str,
    *,
    base_url: str | None = None,
    **kwargs,
) -> FofaKeyConfig:
    return FofaKeyConfig(
        name=name,
        key=secret,
        base_url=base_url or f"https://{name.lower()}.fofa.example/api",
        **kwargs,
    )


def clock(value: datetime):
    current = [value]

    def now() -> datetime:
        return current[0]

    def advance(**delta: int) -> None:
        current[0] += timedelta(**delta)

    return now, advance


def test_sync_router_is_sticky_after_auth_failover_and_keeps_key_url_pair() -> None:
    calls: list[tuple[str, str]] = []
    router = FofaKeyRouter([key("A", "secret-a"), key("B", "secret-b")], active_name="A")

    def first(secret: str, base_url: str) -> str:
        calls.append((secret, base_url))
        if secret == "secret-a":
            raise FofaError("invalid key", kind="auth")
        return "ok"

    assert router.execute_sync(first) == "ok"
    assert router.execute_sync(
        lambda secret, base_url: calls.append((secret, base_url)) or "again"
    ) == "again"
    assert calls == [
        ("secret-a", "https://a.fofa.example/api"),
        ("secret-b", "https://b.fofa.example/api"),
        ("secret-b", "https://b.fofa.example/api"),
    ]


def test_async_rate_failure_tries_each_key_once() -> None:
    calls: list[tuple[str, str]] = []
    router = FofaKeyRouter([key("A", "a"), key("B", "b")], active_name="A")

    async def fail(secret: str, base_url: str) -> str:
        calls.append((secret, base_url))
        raise FofaError("limited", kind="rate_limit")

    with pytest.raises(FofaPoolExhaustedError):
        asyncio.run(router.execute_async(fail))
    assert calls == [
        ("a", "https://a.fofa.example/api"),
        ("b", "https://b.fofa.example/api"),
    ]


def test_rate_limit_backoff_is_capped_and_honors_retry_after() -> None:
    start = datetime(2026, 7, 16, 0, 0, tzinfo=UTC)
    now, advance = clock(start)
    router = FofaKeyRouter([key("A", "secret")], now=now)

    delays = [60, 120, 240, 480, 600, 600]
    elapsed = 0
    for index, expected in enumerate(delays):
        with pytest.raises(FofaPoolExhaustedError):
            router.execute_sync(
                lambda secret, base_url, i=index: (_ for _ in ()).throw(
                    FofaError("limited", kind="rate_limit", retry_after=1000 if i == 5 else None)
                )
            )
        state = router.keys[0]
        assert state.failure_count == index + 1
        actual_delay = max(expected, 1000 if index == 5 else 0)
        assert state.cooldown_until == start + timedelta(seconds=elapsed + actual_delay)
        advance(seconds=actual_delay)
        elapsed += actual_delay


def test_daily_limit_cools_for_one_hour_then_suspends_on_twelfth_failure() -> None:
    start = datetime(2026, 7, 16, 0, 0, tzinfo=UTC)
    now, advance = clock(start)
    router = FofaKeyRouter([key("A", "secret")], now=now)

    elapsed = 0
    for count in range(1, 13):
        with pytest.raises(FofaPoolExhaustedError):
            router.execute_sync(
                lambda secret, base_url: (_ for _ in ()).throw(
                    FofaError("daily", kind="daily_limit")
                )
            )
        state = router.keys[0]
        assert state.failure_count == count
        if count < 12:
            assert state.runtime_state == "daily_cooldown"
            assert state.cooldown_until == start + timedelta(hours=elapsed + 1)
            advance(hours=1)
            elapsed += 1
        else:
            assert state.runtime_state == "daily_suspended"
            assert state.cooldown_until is None


def test_transient_failure_does_not_rotate_and_is_reraised_safely() -> None:
    router = FofaKeyRouter([key("A", "secret-a"), key("B", "secret-b")], active_name="A")
    calls: list[str] = []

    def transient(secret: str, base_url: str):
        calls.append(secret)
        raise FofaError("network secret-a", kind="transient")

    with pytest.raises(FofaError) as exc_info:
        router.execute_sync(transient)
    assert calls == ["secret-a"]
    assert router.active_name == "A"
    assert exc_info.value.kind == "transient"
    assert "secret-a" not in str(exc_info.value)
    assert router.keys[0].runtime_state == "ready"


def test_earliest_retry_and_all_blocked_pool_state() -> None:
    start = datetime(2026, 7, 16, 0, 0, tzinfo=UTC)
    now, _advance = clock(start)
    router = FofaKeyRouter(
        [
            key("A", "a", runtime_state="rate_limited", cooldown_until=start + timedelta(minutes=5)),
            key("B", "b", runtime_state="rate_limited", cooldown_until=start + timedelta(minutes=2)),
        ],
        now=now,
    )
    with pytest.raises(FofaPoolExhaustedError) as exc_info:
        router.execute_sync(lambda *_: pytest.fail("cooldown operation must not run"))
    assert exc_info.value.next_retry_at == start + timedelta(minutes=2)
    assert exc_info.value.failures == []

    blocked = FofaKeyRouter(
        [key("A", "a", enabled=False), key("B", "b", runtime_state="auth_invalid")],
        now=now,
    )
    with pytest.raises(FofaPoolExhaustedError) as blocked_info:
        blocked.execute_sync(lambda *_: pytest.fail("blocked operation must not run"))
    assert blocked_info.value.next_retry_at is None


def test_disabled_and_keyless_entries_are_excluded() -> None:
    router = FofaKeyRouter(
        [key("off", "off", enabled=False), key("empty", ""), key("good", "good")],
        active_name="off",
    )
    seen: list[tuple[str, str]] = []
    assert router.execute_sync(lambda secret, base: seen.append((secret, base)) or "ok") == "ok"
    assert seen == [("good", "https://good.fofa.example/api")]


def test_active_missing_disabled_and_reordered_construction_starts_at_first_eligible() -> None:
    configs = [key("B", "b"), key("A", "a")]
    router = FofaKeyRouter(configs, active_name="deleted")
    seen: list[str] = []
    router.execute_sync(lambda secret, _base: seen.append(secret) or "ok")
    assert seen == ["b"]

    router = FofaKeyRouter([key("A", "a", enabled=False), key("B", "b")], active_name="A")
    router.execute_sync(lambda secret, _base: seen.append(secret) or "ok")
    assert seen[-1] == "b"


def test_callbacks_only_fire_on_real_changes_and_callback_errors_are_ignored() -> None:
    events = []

    def callback(change):
        events.append(change)
        if len(events) == 1:
            raise RuntimeError("callback failure")

    router = FofaKeyRouter([key("A", "a")], on_state_change=callback)
    router.execute_sync(lambda *_: "ok")
    router.execute_sync(lambda *_: "ok")
    assert len(events) == 1
    assert events[0].active_key_name == "A"


def test_two_threads_reporting_same_auth_failure_emit_one_transition() -> None:
    events = []
    barrier = threading.Barrier(2)
    router = FofaKeyRouter([key("A", "secret")], on_state_change=events.append)

    def operation(_secret: str, _base: str):
        barrier.wait(timeout=2)
        raise FofaError("bad secret", kind="auth")

    def run() -> None:
        with pytest.raises(FofaPoolExhaustedError):
            router.execute_sync(operation)

    threads = [threading.Thread(target=run) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)
    assert len(events) == 1
    assert router.keys[0].runtime_state == "auth_invalid"


def test_state_change_and_pool_errors_never_expose_any_key_encoding() -> None:
    secret = "a key/with+symbols"
    router_events = []
    router = FofaKeyRouter([key("A", secret)], on_state_change=router_events.append)
    with pytest.raises(FofaPoolExhaustedError) as exc_info:
        router.execute_sync(
            lambda *_: (_ for _ in ()).throw(
                FofaError(f"failure {secret}", kind="auth")
            )
        )
    rendered = repr(exc_info.value) + str(exc_info.value) + repr(exc_info.value.failures)
    assert secret not in rendered
    assert "a+key%2Fwith%2Bsymbols" not in rendered
    assert all(secret not in repr(event) and secret not in str(event) for event in router_events)


def test_router_copies_input_models_and_now_must_be_aware() -> None:
    configs = [key("A", "secret")]
    router = FofaKeyRouter(configs)
    configs[0].key = "changed"
    configs[0].base_url = "https://changed.example"
    assert router.keys[0].key == "secret"
    assert router.keys[0].base_url == "https://a.fofa.example/api"

    naive_router = FofaKeyRouter([key("A", "a")], now=lambda: datetime(2026, 7, 16))
    with pytest.raises(ValueError, match="aware"):
        naive_router.execute_sync(lambda *_: "ok")


def test_unknown_failure_kind_maps_to_transient_without_rotation() -> None:
    router = FofaKeyRouter([key("A", "a"), key("B", "b")])
    with pytest.raises(FofaError) as exc_info:
        router.execute_sync(
            lambda *_: (_ for _ in ()).throw(FofaError("unknown", kind="future_kind"))
        )
    assert exc_info.value.kind == FofaFailureKind.TRANSIENT.value
    assert router.active_name == ""


def test_router_public_types_are_exported_from_package() -> None:
    from app.fofa import (
        FofaFailureKind as ExportedFailureKind,
        FofaKeyRouter as ExportedRouter,
        FofaKeyStateChange,
        FofaPoolExhaustedError as ExportedPoolError,
        FofaPoolFailure,
    )

    assert ExportedFailureKind is FofaFailureKind
    assert ExportedRouter is FofaKeyRouter
    assert ExportedPoolError is FofaPoolExhaustedError
    assert FofaKeyStateChange.__module__ == "app.fofa.router"
    assert FofaPoolFailure.__module__ == "app.fofa.router"
