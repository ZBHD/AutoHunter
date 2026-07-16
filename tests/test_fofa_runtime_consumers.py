from __future__ import annotations

import asyncio
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.config import FofaKeyConfig
from app.fofa.client import FofaError
from app.fofa.router import FofaKeyRouter
from app.fofa.router import FofaPoolExhaustedError, FofaPoolFailure


@pytest.fixture(autouse=True)
def isolated_fofa_router_cache(monkeypatch):
    import app.settings_service as settings

    cache = OrderedDict()
    monkeypatch.setattr(settings, "_fofa_router_cache", cache)
    yield
    cache.clear()


def _key(name: str, value: str, base_url: str = "https://fofa.info") -> FofaKeyConfig:
    return FofaKeyConfig(name=name, key=value, base_url=base_url)


def test_settings_global_router_is_sticky_and_task_override_isolated(monkeypatch):
    import app.settings_service as settings

    monkeypatch.setattr(settings, "_cache", {
        "llm": {}, "llm_providers": [], "fofa": {"active_key_name": "A"},
        "fofa_keys": [
            _key("A", "key-a").model_dump(mode="json"),
            _key("B", "key-b").model_dump(mode="json"),
        ], "engines": {}, "defaults": {},
    })
    first = settings.fofa_router_for_task()
    second = settings.fofa_router_for_task()
    assert first is second
    task = SimpleNamespace(fofa_config={"key": "task-key", "base_url": "https://task.example"})
    assert settings.fofa_router_for_task(task) is not first
    assert settings.fofa_router_for_task(task).state_snapshot[0].base_url == "https://task.example"


def test_health_state_writeback_invalidates_cached_router(monkeypatch):
    import app.settings_service as settings

    monkeypatch.setattr(settings, "_cache", {
        "llm": {}, "llm_providers": [], "fofa": {"active_key_name": "A"},
        "fofa_keys": [_key("A", "key-a").model_copy(update={
            "runtime_state": "auth_invalid", "failure_kind": "auth",
        }).model_dump(mode="json")],
        "engines": {}, "defaults": {},
    })
    blocked = settings.fofa_router_for_task()
    assert blocked.state_snapshot[0].runtime_state == "auth_invalid"

    settings._cache["fofa_keys"][0].update(
        runtime_state="ready", failure_kind="", failure_count=0, cooldown_until=None
    )
    settings._invalidate_fofa_router_cache()
    recovered = settings.fofa_router_for_task()
    assert recovered is not blocked
    assert recovered.state_snapshot[0].runtime_state == "ready"


def test_tool_executor_fofa_lookup_rotates_and_uses_endpoint_transport(monkeypatch, tmp_path):
    from app.tools.executor import ToolExecutor
    import app.fofa.endpoints as endpoints

    calls = []

    def fake_request(key, base_url, *, purpose, params, **kwargs):
        calls.append((key, base_url, purpose, dict(params)))
        if key == "key-a":
            raise FofaError("invalid key", kind="auth")
        return SimpleNamespace(
            category="ok", response=SimpleNamespace(status_code=200, json=lambda: {
                "size": 1, "results": [["h", "1.2.3.4", "443", "t", "d", "o", "https"]]
            }), error=None,
        )

    monkeypatch.setattr(endpoints, "request_sync", fake_request)
    router = FofaKeyRouter([_key("A", "key-a"), _key("B", "key-b")], active_name="A")
    executor = ToolExecutor("example.com", work_dir=str(tmp_path), fofa_router=router)
    result = executor.fofa_lookup('host="example.com"', size=1)
    assert result["ok"] is True
    assert result["sample"][0]["host"] == "h"
    assert [item[0] for item in calls] == ["key-a", "key-b"]
    assert calls[0][2] == "search"
    assert all("/api/v1/search/all" not in item[1] for item in calls)


def test_killsweep_search_uses_router_with_empty_legacy_key(monkeypatch):
    from app.agents import killsweep
    import app.fofa.endpoints as endpoints

    calls = []

    def fake_request(key, base_url, *, purpose, params, **kwargs):
        calls.append((key, base_url, purpose))
        if key == "key-a":
            raise FofaError("rate limit", kind="rate_limit", retry_after=1)
        return SimpleNamespace(
            category="ok", response=SimpleNamespace(status_code=200, json=lambda: {
                "size": 1, "results": [["h", "title", "org"]]
            }), error=None,
        )

    monkeypatch.setattr(endpoints, "request_sync", fake_request)
    router = FofaKeyRouter([
        _key("A", "key-a", "https://mirror.example/api.php"),
        _key("B", "key-b", "https://mirror.example/api.php"),
    ], active_name="A")
    result = killsweep._fofa_search_sync("", "title=\"x\"", router=router)
    assert result["size"] == 1
    assert result["sample"] == [{"host": "h", "title": "title", "org": "org"}]
    assert [item[0] for item in calls] == ["key-a", "key-b"]
    assert all(item[2] == "search" for item in calls)


def test_collector_auth_rotation_keeps_cursor(monkeypatch):
    async def scenario():
        from app.agents import collector

        progress_events = []

        class Engine:
            display_name = "FOFA"

            async def search(self, key, query, page, page_size, base_url=None):
                assert page == 1
                if key == "key-a":
                    raise FofaError("invalid key", kind="auth")
                return SimpleNamespace(fields=["host"], results=[])

        router = FofaKeyRouter([_key("A", "key-a"), _key("B", "key-b")], active_name="A")

        async def fake_query(*args, **kwargs):
            return "host=\"example.com\"", ""

        monkeypatch.setattr(collector, "get_engine", lambda name: Engine())
        monkeypatch.setattr(collector, "resolve_engine_config", lambda task: {
            "engine": "fofa", "key": "key-a", "base_url": "https://fofa.info",
            "max_pages": 2, "page_size": 1,
        })
        monkeypatch.setattr(collector, "_resolve_query", fake_query)
        monkeypatch.setattr(collector, "_llm_for_task", lambda task: None)
        task = SimpleNamespace(fofa_config={"current_query": "host=\"example.com\"", "cursor": 0}, src_type="edusrc", fofa_query="")
        seen = set()
        cluster = {}
        session = SimpleNamespace(add=lambda obj: None)
        await collector._fofa_collect(
            session,
            task,
            seen,
            cluster,
            lambda phase, text, **payload: _record_progress(progress_events, phase, text, payload),
            fofa_router=router,
        )
        assert task.fofa_config["cursor"] == 1
        assert task.fofa_config["last_key_name"] == "B"
        assert task.fofa_config["last_rotation"] == {
            "from_key_name": "A",
            "to_key_name": "B",
            "reason": "auth",
        }
        rotation = next(
            item for item in progress_events
            if item["payload"].get("event_kind") == "fofa_key_rotated"
        )
        assert rotation["payload"] == {
            "event_kind": "fofa_key_rotated",
            "from_key_name": "A",
            "to_key_name": "B",
            "reason": "auth",
        }
        assert "key-a" not in repr((task.fofa_config, progress_events))
        assert "key-b" not in repr((task.fofa_config, progress_events))
        assert "fofa.info" not in repr((task.fofa_config, progress_events))

    asyncio.run(scenario())


async def _record_progress(events, phase, text, payload):
    events.append({"phase": phase, "text": text, "payload": payload})


def test_collector_clean_success_records_key_without_rotation(monkeypatch):
    async def scenario():
        from app.agents import collector

        calls = []
        progress_events = []

        class Engine:
            display_name = "FOFA"

            async def search(self, key, query, page, page_size, base_url=None):
                calls.append((key, page))
                return SimpleNamespace(fields=["host"], results=[])

        monkeypatch.setattr(collector, "get_engine", lambda name: Engine())
        monkeypatch.setattr(collector, "resolve_engine_config", lambda task: {
            "engine": "fofa", "key": "", "base_url": "https://fofa.info",
            "max_pages": 2, "page_size": 1,
        })
        monkeypatch.setattr(collector, "_llm_for_task", lambda task: None)
        task = SimpleNamespace(
            fofa_config={
                "current_query": "host=\"example.com\"",
                "cursor": 0,
                "last_rotation": {
                    "from_key_name": "Old A",
                    "to_key_name": "Old B",
                    "reason": "rate_limit",
                },
            },
            src_type="edusrc",
            fofa_query="",
        )
        router = FofaKeyRouter([_key("A", "key-a"), _key("B", "key-b")], active_name="A")

        await collector._fofa_collect(
            SimpleNamespace(add=lambda obj: None),
            task,
            set(),
            {},
            lambda phase, text, **payload: _record_progress(progress_events, phase, text, payload),
            fofa_router=router,
        )

        assert calls == [("key-a", 1)]
        assert task.fofa_config["cursor"] == 1
        assert task.fofa_config["last_key_name"] == "A"
        assert "last_rotation" not in task.fofa_config
        assert not any(
            item["payload"].get("event_kind") == "fofa_key_rotated"
            for item in progress_events
        )

    asyncio.run(scenario())


def test_collector_pool_cooldown_marker_skips_second_network(monkeypatch):
    async def scenario():
        from app.agents import collector

        calls = []
        progress_events = []

        class Engine:
            display_name = "FOFA"

            async def search(self, *args, **kwargs):
                calls.append(1)
                raise AssertionError("engine should not be called while cooldown marker is active")

        class CoolingRouter:
            async def execute_async(self, operation, *, on_attempt=None):
                raise FofaPoolExhaustedError(
                    [FofaPoolFailure("A", "rate_limit", "cooldown")],
                    datetime.now(timezone.utc) + timedelta(minutes=5),
                )

        monkeypatch.setattr(collector, "get_engine", lambda name: Engine())
        monkeypatch.setattr(collector, "resolve_engine_config", lambda task: {
            "engine": "fofa", "key": "", "base_url": "https://fofa.info",
            "max_pages": 2, "page_size": 1,
        })
        monkeypatch.setattr(collector, "_llm_for_task", lambda task: None)
        task = SimpleNamespace(fofa_config={"current_query": "host=\"example.com\"", "cursor": 0}, src_type="edusrc", fofa_query="")
        session = SimpleNamespace(add=lambda obj: None)
        await collector._fofa_collect(
            session,
            task,
            set(),
            {},
            lambda phase, text, **payload: _record_progress(progress_events, phase, text, payload),
            fofa_router=CoolingRouter(),
        )
        assert task.fofa_config.get("fofa_next_retry_at")
        waiting = next(
            item for item in progress_events
            if item["payload"].get("event_kind") == "fofa_pool_waiting"
        )
        assert waiting["payload"]["fofa_error"] == "pool_cooldown"
        assert waiting["payload"]["cursor"] == 0
        assert waiting["payload"]["next_retry_at"] == task.fofa_config["fofa_next_retry_at"]
        assert "key" not in waiting["payload"]
        assert "base_url" not in waiting["payload"]
        await collector._fofa_collect(
            session,
            task,
            set(),
            {},
            lambda phase, text, **payload: _record_progress(progress_events, phase, text, payload),
            fofa_router=CoolingRouter(),
        )
        assert calls == []
        assert sum(
            item["payload"].get("event_kind") == "fofa_pool_waiting"
            for item in progress_events
        ) == 1

    asyncio.run(scenario())


def test_collector_transient_keeps_page_and_does_not_rotate(monkeypatch):
    async def scenario():
        from app.agents import collector

        calls = []

        class Engine:
            display_name = "FOFA"

            async def search(self, key, query, page, page_size, base_url=None):
                calls.append(key)
                raise FofaError("gateway timeout", kind="transient")

        monkeypatch.setattr(collector, "get_engine", lambda name: Engine())
        monkeypatch.setattr(collector, "resolve_engine_config", lambda task: {
            "engine": "fofa", "key": "", "base_url": "https://fofa.info",
            "max_pages": 2, "page_size": 1,
        })
        monkeypatch.setattr(collector, "_llm_for_task", lambda task: None)
        task = SimpleNamespace(fofa_config={"current_query": "host=\"example.com\"", "cursor": 0}, src_type="edusrc", fofa_query="")
        router = FofaKeyRouter([_key("A", "key-a"), _key("B", "key-b")], active_name="A")
        await collector._fofa_collect(SimpleNamespace(add=lambda obj: None), task, set(), {}, None, fofa_router=router)
        assert task.fofa_config["cursor"] == 0
        assert calls == ["key-a"]
        assert "last_rotation" not in task.fofa_config

    asyncio.run(scenario())


def test_collector_terminal_pool_marker_is_safe(monkeypatch):
    async def scenario():
        from app.agents import collector

        progress_events = []

        class TerminalRouter:
            async def execute_async(self, operation, *, on_attempt=None):
                raise FofaPoolExhaustedError(
                    [FofaPoolFailure("A", "auth", "invalid key SECRET")], None
                )

        monkeypatch.setattr(collector, "get_engine", lambda name: SimpleNamespace(display_name="FOFA"))
        monkeypatch.setattr(collector, "resolve_engine_config", lambda task: {
            "engine": "fofa", "key": "", "base_url": "https://fofa.info",
            "max_pages": 2, "page_size": 1,
        })
        monkeypatch.setattr(collector, "_llm_for_task", lambda task: None)
        task = SimpleNamespace(fofa_config={"current_query": "host=\"example.com\"", "cursor": 0}, src_type="edusrc", fofa_query="")
        await collector._fofa_collect(
            SimpleNamespace(add=lambda obj: None),
            task,
            set(),
            {},
            lambda phase, text, **payload: _record_progress(progress_events, phase, text, payload),
            fofa_router=TerminalRouter(),
        )
        assert task.fofa_config.get("fofa_pool_blocked") is True
        blocked = next(
            item for item in progress_events
            if item["payload"].get("event_kind") == "fofa_pool_blocked"
        )
        assert blocked["payload"] == {
            "fofa_error": "pool_blocked",
            "cursor": 0,
            "event_kind": "fofa_pool_blocked",
        }
        assert "SECRET" not in repr((task.fofa_config, progress_events))
        assert "key" not in blocked["payload"]
        assert "base_url" not in blocked["payload"]

    asyncio.run(scenario())
