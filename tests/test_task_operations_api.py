from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import findings as findings_api
from app.api import tasks as tasks_api
from app.config import FofaKeyConfig
from app.db.models import Base, Finding, Target, Task, TaskEvent
from app.db.session import get_session
from app.fofa.router import FofaKeyRouter


@pytest.fixture
def operations_api(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'operations.db'}")
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def setup() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(Task(
                id="task-ops",
                name="Operations",
                status="running",
                target_source="fofa",
                engine="fofa",
                fofa_config={
                    "runtime_state": "rate_limited",
                    "failure_kind": "rate_limit",
                    "failure_count": 2,
                    "cooldown_until": "2026-07-17T00:20:00Z",
                },
            ))
            session.add_all([
                Target(
                    id="target-done", task_id="task-ops", url="https://done.example",
                    host="done.example", source="manual", status="done", verdict="found",
                    school="Done University",
                ),
                Target(
                    id="target-dead", task_id="task-ops", url="https://dead.example",
                    host="dead.example", source="fofa", status="dead", verdict="no_vuln",
                    dead_reason="未发现可利用漏洞",
                ),
                Target(
                    id="target-skipped", task_id="task-ops", url="https://skip.example",
                    host="skip.example", source="fofa", status="skipped", verdict="error",
                    dead_reason="低分跳过",
                ),
                Target(
                    id="target-active", task_id="task-ops", url="https://active.example",
                    host="active.example", source="fofa", status="scanning",
                ),
                Target(
                    id="target-queue-high", task_id="task-ops", url="https://high.example",
                    host="high.example", source="fofa", status="queued", priority_score=90,
                ),
                Target(
                    id="target-queue-low", task_id="task-ops", url="https://low.example",
                    host="low.example", source="fofa", status="queued", priority_score=10,
                ),
                Target(
                    id="target-queue-manual", task_id="task-ops", url="https://manual.example",
                    host="manual.example", source="manual", status="queued", priority_score=100,
                ),
            ])
            session.add_all([
                Finding(
                    id="finding-current", task_id="task-ops", target_id="target-done",
                    worker_id="worker-1", vuln_type="idor", title="Current finding",
                    severity_claimed="高危", target_url="https://done.example/api/users",
                    description="description", steps=["step"], poc="curl example",
                    raw_request="GET /api/users HTTP/1.1", raw_response="secret response",
                    evidence={"notes": "evidence"}, status="pending_review",
                ),
                Finding(
                    id="finding-old", task_id="task-ops", target_id="target-done",
                    worker_id="worker-1", vuln_type="idor", title="Superseded finding",
                    severity_claimed="中危", target_url="https://done.example/api/users",
                    description="old", steps=["old"], poc="old",
                    raw_request="old request", raw_response="old response",
                    status="superseded",
                ),
            ])
            await session.commit()

    asyncio.run(setup())

    async def override_session():
        async with session_maker() as session:
            yield session

    app = FastAPI()
    app.include_router(tasks_api.router)
    app.include_router(findings_api.router)
    app.dependency_overrides[get_session] = override_session

    with TestClient(app) as client:
        client._session_maker = session_maker
        yield client

    asyncio.run(engine.dispose())


def test_task_stats_done_counts_every_terminal_target(operations_api: TestClient) -> None:
    response = operations_api.get("/api/tasks/task-ops")

    assert response.status_code == 200
    assert response.json()["stats"]["done"] == 3


def test_task_response_exposes_search_enabled(operations_api: TestClient) -> None:
    response = operations_api.get("/api/tasks/task-ops")

    assert response.status_code == 200
    assert response.json()["search_enabled"] is True


def test_search_stream_marks_stop_and_drain_events_as_important() -> None:
    assert tasks_api._stream_event_visible("search_stopped", "info") is True
    assert tasks_api._stream_event_visible("search_drained", "info") is True


def test_stop_search_is_atomic_for_concurrent_sessions(
    tmp_path,
) -> None:
    async def stop_concurrently():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'atomic.db'}")
        session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with session_maker() as session:
                session.add(Task(id="task-atomic", name="Atomic", status="running"))
                session.add_all([
                    Target(
                        id="target-atomic-high", task_id="task-atomic", url="https://high.example",
                        host="high.example", source="fofa", status="queued", priority_score=90,
                    ),
                    Target(
                        id="target-atomic-low", task_id="task-atomic", url="https://low.example",
                        host="low.example", source="fofa", status="queued", priority_score=10,
                    ),
                ])
                await session.commit()

            get_count = 0
            both_loaded = asyncio.Event()

            async def wait_for_both_tasks() -> None:
                nonlocal get_count
                get_count += 1
                if get_count == 2:
                    both_loaded.set()
                await both_loaded.wait()

            class BarrierSession:
                def __init__(self, session: AsyncSession):
                    self._session = session

                async def get(self, *args, **kwargs):
                    task = await self._session.get(*args, **kwargs)
                    await wait_for_both_tasks()
                    return task

                def __getattr__(self, name):
                    return getattr(self._session, name)

            async with session_maker() as first_session:
                async with session_maker() as second_session:
                    results = await asyncio.gather(
                        tasks_api.stop_search("task-atomic", BarrierSession(first_session)),
                        tasks_api.stop_search("task-atomic", BarrierSession(second_session)),
                    )

            async with session_maker() as session:
                events = (await session.scalars(
                    select(TaskEvent).where(TaskEvent.task_id == "task-atomic")
                )).all()
            return results, events
        finally:
            await engine.dispose()

    results, events = asyncio.run(stop_concurrently())

    assert [result.search_enabled for result in results] == [False, False]
    assert len(events) == 1
    assert events[0].kind == "search_stopped"


def test_stop_search_disables_search_once_and_preserves_queued_targets(
    operations_api: TestClient,
) -> None:
    before = operations_api.get("/api/tasks/task-ops/queue-targets")
    assert before.status_code == 200
    queued_ids = [item["id"] for item in before.json()["items"]]

    first = operations_api.post("/api/tasks/task-ops/stop-search")
    second = operations_api.post("/api/tasks/task-ops/stop-search")

    assert first.status_code == 200
    assert first.json()["search_enabled"] is False
    assert second.status_code == 200
    assert second.json()["search_enabled"] is False

    after = operations_api.get("/api/tasks/task-ops/queue-targets")
    assert [item["id"] for item in after.json()["items"]] == queued_ids

    events = operations_api.get("/api/tasks/task-ops/board").json()["events"]
    stopped_events = [event for event in events if event["kind"] == "search_stopped"]
    assert len(stopped_events) == 1
    assert stopped_events[0]["agent"] == "collector"
    assert stopped_events[0]["level"] == "info"
    assert stopped_events[0]["message"] == "资产搜索已停止，剩余队列将继续处理"


def test_stop_search_returns_404_for_missing_task(operations_api: TestClient) -> None:
    response = operations_api.post("/api/tasks/missing/stop-search")

    assert response.status_code == 404


def test_start_task_reenables_search(
    operations_api: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stopped = operations_api.post("/api/tasks/task-ops/stop-search")
    assert stopped.status_code == 200
    assert stopped.json()["search_enabled"] is False

    async def no_op(_task_id: str) -> None:
        return None

    monkeypatch.setattr(tasks_api.manager, "ensure_running", no_op)
    retry = datetime(2026, 7, 17, 0, 20, tzinfo=timezone.utc)
    global_router = FofaKeyRouter([
        FofaKeyConfig(
            name="Primary",
            key="global-secret",
            runtime_state="rate_limited",
            failure_kind="rate_limit",
            cooldown_until=retry,
        )
    ])
    monkeypatch.setattr(
        tasks_api,
        "fofa_router_for_task",
        lambda _task: global_router,
        raising=False,
    )
    started = operations_api.post("/api/tasks/task-ops/start")

    assert started.status_code == 200
    assert started.json()["search_enabled"] is True
    assert started.json()["fofa_config"]["collector_phase"] == "initializing"
    assert (
        started.json()["fofa_config"]["collector_phase_text"]
        == "正在初始化 FOFA 搜集引擎"
    )
    assert global_router.state_snapshot[0].cooldown_until == retry

    async def persisted_config() -> dict:
        async with operations_api._session_maker() as session:
            task = await session.get(Task, "task-ops")
            return dict(task.fofa_config or {})

    config = asyncio.run(persisted_config())
    assert config["collector_phase_payload"] == {}
    assert "runtime_state" not in config
    assert "cooldown_until" not in config


def test_start_task_initializes_other_auto_engines_but_not_manual_or_site(
    operations_api: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def seed_tasks() -> None:
        async with operations_api._session_maker() as session:
            session.add_all([
                Task(
                    id="task-quake",
                    name="Quake",
                    target_source="both",
                    engine="quake",
                    status="created",
                ),
                Task(
                    id="task-manual",
                    name="Manual",
                    target_source="manual",
                    engine="fofa",
                    status="created",
                ),
                Task(
                    id="task-site",
                    name="Site",
                    target_source="site",
                    engine="fofa",
                    status="created",
                ),
            ])
            await session.commit()

    asyncio.run(seed_tasks())

    async def no_op(_task_id: str) -> None:
        return None

    monkeypatch.setattr(tasks_api.manager, "ensure_running", no_op)
    monkeypatch.setattr(
        tasks_api,
        "fofa_router_for_task",
        lambda _task: (_ for _ in ()).throw(
            AssertionError("非 FOFA 引擎不得访问 FOFA Router")
        ),
        raising=False,
    )

    quake = operations_api.post("/api/tasks/task-quake/start")
    manual = operations_api.post("/api/tasks/task-manual/start")
    site = operations_api.post("/api/tasks/task-site/start")

    assert quake.status_code == 200
    assert quake.json()["fofa_config"]["collector_phase"] == "initializing"
    assert (
        quake.json()["fofa_config"]["collector_phase_text"]
        == "正在初始化 quake 搜集引擎"
    )
    assert manual.status_code == 200
    assert "collector_phase" not in manual.json()["fofa_config"] or not manual.json()[
        "fofa_config"
    ]["collector_phase"]
    assert site.status_code == 200
    assert "collector_phase" not in site.json()["fofa_config"] or not site.json()[
        "fofa_config"
    ]["collector_phase"]


def test_task_response_merges_credential_free_fofa_runtime_summary(
    operations_api: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    router = FofaKeyRouter(
        [
            FofaKeyConfig(name="Primary", key="secret-primary"),
            FofaKeyConfig(name="Disabled", key="secret-disabled", enabled=False),
        ],
        active_name="Primary",
    )
    monkeypatch.setattr(
        tasks_api, "fofa_router_for_task", lambda _task: router, raising=False
    )

    response = operations_api.get("/api/tasks/task-ops")

    assert response.status_code == 200
    config = response.json()["fofa_config"]
    assert config["key_source"] == "global_pool"
    assert config["active_key_name"] == "Primary"
    assert config["pool_available"] == 1
    assert config["pool_total"] == 2
    assert "secret-primary" not in response.text
    assert "secret-disabled" not in response.text


def test_observer_task_response_hides_fofa_names_counts_and_credentials(
    operations_api: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AUTOHUNTER_OBSERVER_TOKEN", "observer-token")

    async def set_runtime_config() -> None:
        async with operations_api._session_maker() as session:
            task = await session.get(Task, "task-ops")
            task.fofa_config = {
                "key": "observer-secret",
                "last_key_name": "Observer Hidden Key",
                "pool_available": 1,
                "pool_total": 2,
                "pool_state": "cooling",
                "collector_phase": "querying",
                "collector_phase_text": "正在使用 Observer Hidden Key",
            }
            await session.commit()

    asyncio.run(set_runtime_config())
    monkeypatch.setattr(
        tasks_api,
        "fofa_router_for_task",
        lambda _task: (_ for _ in ()).throw(
            AssertionError("observer 快照不得访问 FOFA Router")
        ),
        raising=False,
    )

    response = operations_api.get(
        "/api/tasks/task-ops",
        headers={"x-autohunter-token": "observer-token"},
    )

    assert response.status_code == 200
    config = response.json()["fofa_config"]
    assert config["pool_state"] == "cooling"
    assert config["collector_phase"] == "querying"
    assert "active_key_name" not in config
    assert "last_key_name" not in config
    assert "pool_available" not in config
    assert "pool_total" not in config
    assert "observer-secret" not in response.text
    assert "Observer Hidden Key" not in response.text


def test_running_task_rejects_src_type_switch_but_paused_task_allows_it(
    operations_api: TestClient,
) -> None:
    running = operations_api.patch(
        "/api/tasks/task-ops",
        json={"src_type": "enterprise"},
    )
    assert running.status_code == 409
    assert "暂停" in running.json()["detail"]

    async def pause_task() -> None:
        async with operations_api._session_maker() as session:
            task = await session.get(Task, "task-ops")
            task.status = "paused"
            await session.commit()

    asyncio.run(pause_task())
    paused = operations_api.patch(
        "/api/tasks/task-ops",
        json={"src_type": "enterprise"},
    )
    assert paused.status_code == 200
    assert paused.json()["src_type"] == "enterprise"


def test_terminal_targets_are_paginated_and_include_finding_counts(
    operations_api: TestClient,
) -> None:
    response = operations_api.get(
        "/api/tasks/task-ops/targets",
        params={"status": "terminal", "q": "done", "limit": 1, "offset": 0},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["limit"] == 1
    assert payload["offset"] == 0
    assert payload["has_more"] is False
    assert payload["items"][0]["id"] == "target-done"
    assert payload["items"][0]["source"] == "manual"
    assert payload["items"][0]["finding_count"] == 1
    assert payload["items"][0]["updated_at"]


def test_target_detail_includes_related_current_findings(operations_api: TestClient) -> None:
    response = operations_api.get("/api/tasks/task-ops/targets/target-done")

    assert response.status_code == 200
    payload = response.json()
    assert payload["id"] == "target-done"
    assert [item["id"] for item in payload["findings"]] == ["finding-current"]
    assert "raw_response" not in payload["findings"][0]


def test_queued_search_targets_are_listed_in_dispatch_order(operations_api: TestClient) -> None:
    response = operations_api.get("/api/tasks/task-ops/queue-targets")

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert [item["id"] for item in payload["items"]] == [
        "target-queue-high",
        "target-queue-low",
    ]
    assert payload["items"][0]["queue_position"] is None


def test_queue_order_is_persisted_and_requires_a_fresh_complete_snapshot(
    operations_api: TestClient,
) -> None:
    reordered = operations_api.put(
        "/api/tasks/task-ops/queue-targets/order",
        json={"target_ids": ["target-queue-low", "target-queue-high"]},
    )

    assert reordered.status_code == 200
    assert [item["id"] for item in reordered.json()["items"]] == [
        "target-queue-low",
        "target-queue-high",
    ]
    assert [item["queue_position"] for item in reordered.json()["items"]] == [1, 2]

    stale = operations_api.put(
        "/api/tasks/task-ops/queue-targets/order",
        json={"target_ids": ["target-queue-low"]},
    )
    assert stale.status_code == 409


def test_deleting_a_queued_search_target_tombstones_it_and_rejects_claimed_targets(
    operations_api: TestClient,
) -> None:
    deleted = operations_api.delete(
        "/api/tasks/task-ops/queue-targets/target-queue-low"
    )
    assert deleted.status_code == 204

    queue = operations_api.get("/api/tasks/task-ops/queue-targets")
    assert [item["id"] for item in queue.json()["items"]] == ["target-queue-high"]

    removed = operations_api.get(
        "/api/tasks/task-ops/targets", params={"status": "removed", "compact": "true"}
    )
    assert [item["id"] for item in removed.json()["items"]] == ["target-queue-low"]

    claimed = operations_api.delete(
        "/api/tasks/task-ops/queue-targets/target-active"
    )
    assert claimed.status_code == 409


def test_compact_raw_findings_exclude_superseded_and_omit_large_evidence(
    operations_api: TestClient,
) -> None:
    response = operations_api.get(
        "/api/tasks/task-ops/findings",
        params={"compact": "true", "limit": 50, "offset": 0},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["has_more"] is False
    assert [item["id"] for item in payload["items"]] == ["finding-current"]
    assert "raw_request" not in payload["items"][0]
    assert "raw_response" not in payload["items"][0]
    assert "evidence" not in payload["items"][0]
    assert "assistant_messages" not in payload["items"][0]


def test_legacy_raw_findings_also_exclude_superseded(operations_api: TestClient) -> None:
    response = operations_api.get("/api/tasks/task-ops/findings")

    assert response.status_code == 200
    assert [item["id"] for item in response.json()] == ["finding-current"]
