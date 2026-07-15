from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import orchestrator
from app.agents.deepen import apply_deepen
from app.db.models import Base, Finding, Target, Task, TaskEvent
from app.queue_targets import queue_dispatch_order


def _run(coro):
    return asyncio.run(coro)


def _stub_tick_work(monkeypatch, runner) -> None:
    async def no_refill(*_args, **_kwargs):
        return 0

    async def no_work(*_args, **_kwargs):
        return None

    monkeypatch.setattr(orchestrator.collector, "refill", no_refill)
    monkeypatch.setattr(runner, "_reclaim_stale", no_work)
    monkeypatch.setattr(runner, "_pop_queued", no_work)
    monkeypatch.setattr(runner, "_dispatch_reviews", no_work)
    monkeypatch.setattr(runner, "_dispatch_escalation_attempts", no_work)
    monkeypatch.setattr(runner, "_dispatch_killsweep_attempts", no_work)


async def _create_disabled_search_runner(tmp_path, db_name, task_id, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / db_name}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        session.add(Task(
            id=task_id,
            name="Search drain busy",
            status="running",
            search_enabled=False,
        ))
        await session.commit()

    monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
    runner = orchestrator.TaskRunner(task_id)
    _stub_tick_work(monkeypatch, runner)
    return engine, sessions, runner


def test_explicit_queue_position_overrides_automatic_priority(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'queue-order.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-queue-order", name="Queue order", status="running"))
            high = Target(
                id="target-auto-high", task_id="task-queue-order",
                url="https://high.example", host="high.example", source="fofa",
                status="queued", priority_score=100,
            )
            low = Target(
                id="target-manual-first", task_id="task-queue-order",
                url="https://low.example", host="low.example", source="fofa",
                status="queued", priority_score=1,
            )
            low.queue_position = 1
            session.add_all([high, low])
            await session.commit()

        runner = orchestrator.TaskRunner("task-queue-order")
        runner._is_enterprise = True

        async def all_alive(targets):
            return {target.id: {"alive": True, "url": target.url} for target in targets}

        monkeypatch.setattr(runner, "_probe_queued_liveness", all_alive)
        async with sessions() as session:
            selected = await runner._pop_queued(session)
            assert selected is not None
            assert selected.id == "target-manual-first"
        await engine.dispose()

    _run(scenario())


def test_unordered_queue_keeps_existing_priority_dispatch(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'queue-default.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-queue-default", name="Queue default", status="running"))
            session.add_all([
                Target(
                    id="target-default-low", task_id="task-queue-default",
                    url="https://low.example", host="low.example", source="fofa",
                    status="queued", priority_score=1,
                ),
                Target(
                    id="target-default-high", task_id="task-queue-default",
                    url="https://high.example", host="high.example", source="fofa",
                    status="queued", priority_score=100,
                ),
            ])
            await session.commit()

        runner = orchestrator.TaskRunner("task-queue-default")
        runner._is_enterprise = True

        async def all_alive(targets):
            return {target.id: {"alive": True, "url": target.url} for target in targets}

        monkeypatch.setattr(runner, "_probe_queued_liveness", all_alive)
        async with sessions() as session:
            selected = await runner._pop_queued(session)
            assert selected is not None
            assert selected.id == "target-default-high"
        await engine.dispose()

    _run(scenario())


def test_manual_deepen_is_inserted_at_the_front_of_the_persisted_queue(tmp_path) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'deepen-front.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-deepen-front", name="Deepen front", status="paused"))
            session.add_all([
                Target(
                    id="target-manual-first", task_id="task-deepen-front",
                    url="https://manual.example", host="manual.example", source="fofa",
                    status="queued", priority_score=999, queue_position=1,
                ),
                Target(
                    id="target-earlier-deepen", task_id="task-deepen-front",
                    url="https://earlier.example", host="earlier.example", source="fofa",
                    status="queued", priority_score=200, queue_position=-1_000_000,
                ),
            ])
            target = Target(
                id="target-deepen", task_id="task-deepen-front",
                url="https://deep.example", host="deep.example", source="fofa",
                status="done", verdict="found", priority_score=1, queue_position=8,
            )
            finding = Finding(
                id="finding-deepen", task_id="task-deepen-front", target_id=target.id,
                vuln_type="idor", title="Original finding", severity_claimed="高危",
                target_url="https://deep.example/api/users", description="Original evidence summary",
                dedup_key="finding-deepen-key",
            )
            session.add_all([target, finding])
            await session.flush()

            applied, _message = apply_deepen(
                session, finding, target, "Verify the original IDOR with another account", source="user",
            )
            await session.commit()

            queued = list(await session.scalars(
                select(Target)
                .where(Target.task_id == "task-deepen-front", Target.status == "queued")
                .order_by(*queue_dispatch_order())
            ))
            assert applied is True
            assert [item.id for item in queued] == [
                "target-deepen", "target-earlier-deepen", "target-manual-first",
            ]
            assert target.queue_position is not None and target.queue_position < 0
            assert target.deepen_context["directive"] == "Verify the original IDOR with another account"
            assert target.deepen_context["original_title"] == "Original finding"
            assert target.deepen_context["original_summary"] == "Original evidence summary"
        await engine.dispose()

    _run(scenario())


def test_queue_change_during_liveness_probe_aborts_the_stale_claim(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'queue-race.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-queue-race", name="Queue race", status="running"))
            session.add(Target(
                id="target-queue-race", task_id="task-queue-race",
                url="https://race.example", host="race.example", source="fofa",
                status="queued", priority_score=50,
            ))
            await session.commit()

        runner = orchestrator.TaskRunner("task-queue-race")
        runner._is_enterprise = True

        async def invalidate_while_probing(targets):
            runner.invalidate_queue()
            return {target.id: {"alive": True, "url": target.url} for target in targets}

        monkeypatch.setattr(runner, "_probe_queued_liveness", invalidate_while_probing)
        async with sessions() as session:
            selected = await runner._pop_queued(session)
            assert selected is None
        async with sessions() as session:
            target = await session.get(Target, "target-queue-race")
            assert target.status == "queued"
        await engine.dispose()

    _run(scenario())


def test_disabled_search_stops_after_the_queue_drains(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'search-drained.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(
                id="task-search-drained",
                name="Search drained",
                status="running",
                search_enabled=False,
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-search-drained")
        _stub_tick_work(monkeypatch, runner)

        await runner._tick()

        async with sessions() as session:
            task = await session.get(Task, "task-search-drained")
            events = list(await session.scalars(
                select(TaskEvent).where(
                    TaskEvent.task_id == "task-search-drained",
                    TaskEvent.kind == "search_drained",
                )
            ))
            assert task is not None
            assert task.status == "stopped"
            assert runner._stop.is_set()
            assert len(events) == 1
            assert events[0].agent == "orchestrator"
            assert events[0].message == "资产搜索已停止，队列已排空，任务自动停止"
        await engine.dispose()

    _run(scenario())


def test_search_drain_survives_live_event_publish_failure(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine, sessions, runner = await _create_disabled_search_runner(
            tmp_path,
            "search-publish-failure.db",
            "task-search-publish-failure",
            monkeypatch,
        )
        original_commit = AsyncSession.commit
        commit_calls = 0

        async def counted_commit(session):
            nonlocal commit_calls
            commit_calls += 1
            await original_commit(session)

        async def fail_publish(*_args, **_kwargs):
            raise RuntimeError("live event bus unavailable")

        monkeypatch.setattr(AsyncSession, "commit", counted_commit)
        monkeypatch.setattr(orchestrator.bus, "publish", fail_publish)
        try:
            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, "task-search-publish-failure")
                events = list(await session.scalars(
                    select(TaskEvent).where(
                        TaskEvent.task_id == "task-search-publish-failure",
                        TaskEvent.kind == "search_drained",
                    )
                ))
                assert task is not None
                assert task.status == "stopped"
                assert runner._auto_drained is True
                assert runner._stop.is_set()
                assert commit_calls == 1
                assert len(events) == 1
                assert events[0].agent == "orchestrator"
                assert events[0].level == "info"
                assert events[0].message == "资产搜索已停止，队列已排空，任务自动停止"
                assert events[0].payload == {}
        finally:
            await engine.dispose()

    _run(scenario())


def test_restart_search_wins_against_a_stale_drain_snapshot(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        task_id = "task-search-restart-wins"
        engine, sessions, runner = await _create_disabled_search_runner(
            tmp_path,
            "search-restart-wins.db",
            task_id,
            monkeypatch,
        )

        async def restart_during_inflight_count(_session):
            async with sessions() as restart_session:
                await restart_session.execute(
                    update(Task)
                    .where(Task.id == task_id)
                    .values(search_enabled=True, status="running")
                )
                await restart_session.commit()
            return 0

        monkeypatch.setattr(runner, "_count_inflight", restart_during_inflight_count)
        try:
            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, task_id)
                drained_events = list(await session.scalars(
                    select(TaskEvent).where(
                        TaskEvent.task_id == task_id,
                        TaskEvent.kind == "search_drained",
                    )
                ))
                assert task is not None
                assert task.search_enabled is True
                assert task.status == "running"
                assert not runner._stop.is_set()
                assert drained_events == []
        finally:
            await engine.dispose()

    _run(scenario())


def test_start_waits_for_drain_commit_window_before_replacing_runner(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        task_id = "task-search-commit-window"
        engine, sessions, runner = await _create_disabled_search_runner(
            tmp_path,
            "search-commit-window.db",
            task_id,
            monkeypatch,
        )

        async def no_refill(*_args, **_kwargs):
            return 0

        async def no_work(*_args, **_kwargs):
            return None

        commit_finished = asyncio.Event()
        allow_commit_return = asyncio.Event()
        original_commit = AsyncSession.commit

        async def pause_after_drain_commit(session):
            is_drain_commit = any(
                isinstance(item, TaskEvent) and item.kind == "search_drained"
                for item in session.new
            )
            await original_commit(session)
            if is_drain_commit:
                commit_finished.set()
                await allow_commit_return.wait()

        monkeypatch.setattr(AsyncSession, "commit", pause_after_drain_commit)
        monkeypatch.setattr(orchestrator.collector, "refill", no_refill)
        monkeypatch.setattr(runner, "_reclaim_stale", no_work)
        monkeypatch.setattr(runner, "_pop_queued", no_work)
        monkeypatch.setattr(runner, "_dispatch_reviews", no_work)
        monkeypatch.setattr(runner, "_dispatch_escalation_attempts", no_work)
        monkeypatch.setattr(runner, "_dispatch_killsweep_attempts", no_work)

        class FreshRunner:
            def __init__(self, fresh_task_id: str):
                self.task_id = fresh_task_id
                self._stop = asyncio.Event()
                self._auto_drained = False
                self._drain_lifecycle_lock = asyncio.Lock()
                self.release = asyncio.Event()
                self.started = asyncio.Event()

            def resume(self):
                return None

            async def stop(self):
                self._stop.set()

            async def run_forever(self):
                self.started.set()
                await self.release.wait()

        tick_task = asyncio.create_task(runner._tick())
        manager = None
        ensure_task = None
        try:
            await commit_finished.wait()

            async with sessions() as start_session:
                await start_session.execute(
                    update(Task)
                    .where(Task.id == task_id)
                    .values(search_enabled=True, status="running")
                )
                await start_session.commit()

            monkeypatch.setattr(orchestrator, "TaskRunner", FreshRunner)
            manager = orchestrator.OrchestratorManager()
            manager._runners[task_id] = runner
            manager._tasks[task_id] = tick_task
            ensure_task = asyncio.create_task(manager.ensure_running(task_id))
            await asyncio.sleep(0)
            assert not ensure_task.done()
            assert runner._auto_drained is False

            allow_commit_return.set()
            await asyncio.gather(tick_task, return_exceptions=True)
            await ensure_task

            fresh_runner = manager._runners[task_id]
            fresh_task = manager._tasks[task_id]
            assert isinstance(fresh_runner, FreshRunner)
            assert fresh_runner is not runner
            assert fresh_task is not tick_task
            await fresh_runner.started.wait()

            fresh_runner.release.set()
            await fresh_task
        finally:
            allow_commit_return.set()
            tasks = {tick_task}
            if ensure_task is not None:
                tasks.add(ensure_task)
            if manager is not None:
                for managed_runner in manager._runners.values():
                    if isinstance(managed_runner, FreshRunner):
                        managed_runner.release.set()
                tasks.update(manager._tasks.values())
            for pending in tasks:
                if not pending.done():
                    pending.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await engine.dispose()

    _run(scenario())


def test_disabled_search_with_a_queued_target_keeps_running(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'search-queued.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(
                id="task-search-queued",
                name="Search queued",
                status="running",
                search_enabled=False,
            ))
            session.add(Target(
                id="target-search-queued",
                task_id="task-search-queued",
                url="https://queued.example",
                host="queued.example",
                source="manual",
                status="queued",
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-search-queued")
        _stub_tick_work(monkeypatch, runner)

        await runner._tick()

        async with sessions() as session:
            task = await session.get(Task, "task-search-queued")
            assert task is not None
            assert task.status == "running"
            assert not runner._stop.is_set()
        await engine.dispose()

    _run(scenario())


def test_disabled_search_waits_for_the_last_review_task(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'search-review.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(
                id="task-search-review",
                name="Search review",
                status="running",
                search_enabled=False,
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-search-review")
        _stub_tick_work(monkeypatch, runner)
        review_release = asyncio.Event()
        review_task = asyncio.create_task(review_release.wait())
        runner._review_tasks["finding-last"] = review_task

        try:
            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, "task-search-review")
                assert task is not None
                assert task.status == "idle"
                assert not runner._stop.is_set()

            review_release.set()
            await review_task
            runner._review_tasks.clear()

            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, "task-search-review")
                assert task is not None
                assert task.status == "stopped"
                assert runner._stop.is_set()
        finally:
            review_release.set()
            await asyncio.gather(review_task, return_exceptions=True)
            runner._review_tasks.clear()
            await engine.dispose()

    _run(scenario())


def test_disabled_search_waits_for_an_active_worker(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine, sessions, runner = await _create_disabled_search_runner(
            tmp_path,
            "search-active-worker.db",
            "task-search-active-worker",
            monkeypatch,
        )
        worker_release = asyncio.Event()
        worker_task = asyncio.create_task(worker_release.wait())
        runner._active_workers["target-active"] = worker_task

        try:
            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, "task-search-active-worker")
                assert task is not None
                assert task.status == "running"
                assert not runner._stop.is_set()
        finally:
            worker_release.set()
            await worker_task
            runner._active_workers.clear()
            await engine.dispose()

    _run(scenario())


@pytest.mark.parametrize("target_status", ["assigned", "scanning"])
def test_disabled_search_waits_for_database_inflight_target(
    tmp_path,
    monkeypatch,
    target_status,
) -> None:
    async def scenario() -> None:
        task_id = f"task-search-{target_status}"
        engine, sessions, runner = await _create_disabled_search_runner(
            tmp_path,
            f"search-{target_status}.db",
            task_id,
            monkeypatch,
        )
        try:
            async with sessions() as session:
                session.add(Target(
                    id=f"target-search-{target_status}",
                    task_id=task_id,
                    url=f"https://{target_status}.example",
                    host=f"{target_status}.example",
                    source="manual",
                    status=target_status,
                    assigned_worker="worker-inflight",
                ))
                await session.commit()

            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, task_id)
                assert task is not None
                assert task.status == "running"
                assert not runner._stop.is_set()
        finally:
            await engine.dispose()

    _run(scenario())


@pytest.mark.parametrize(
    ("task_map_name", "entry_id"),
    [
        ("_killsweep_tasks", "attempt-killsweep"),
        ("_escalation_tasks", "attempt-escalation"),
    ],
    ids=["killsweep", "escalation"],
)
def test_disabled_search_waits_for_background_analysis_task(
    tmp_path,
    monkeypatch,
    task_map_name,
    entry_id,
) -> None:
    async def scenario() -> None:
        task_id = f"task-search-{entry_id}"
        engine, sessions, runner = await _create_disabled_search_runner(
            tmp_path,
            f"search-{entry_id}.db",
            task_id,
            monkeypatch,
        )
        analysis_release = asyncio.Event()
        analysis_task = asyncio.create_task(analysis_release.wait())
        task_map = getattr(runner, task_map_name)
        task_map[entry_id] = analysis_task

        try:
            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, task_id)
                assert task is not None
                assert task.status == "running"
                assert not runner._stop.is_set()
        finally:
            analysis_release.set()
            await analysis_task
            task_map.clear()
            await engine.dispose()

    _run(scenario())


def test_enabled_search_with_an_empty_queue_keeps_existing_idle_behavior(
    tmp_path,
    monkeypatch,
) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'search-enabled-idle.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(
                id="task-search-enabled-idle",
                name="Search enabled idle",
                status="running",
                search_enabled=True,
            ))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        runner = orchestrator.TaskRunner("task-search-enabled-idle")
        _stub_tick_work(monkeypatch, runner)

        await runner._tick()

        async with sessions() as session:
            task = await session.get(Task, "task-search-enabled-idle")
            drained_events = list(await session.scalars(
                select(TaskEvent).where(
                    TaskEvent.task_id == "task-search-enabled-idle",
                    TaskEvent.kind == "search_drained",
                )
            ))
            assert task is not None
            assert task.status == "idle"
            assert not runner._stop.is_set()
            assert drained_events == []
        await engine.dispose()

    _run(scenario())
