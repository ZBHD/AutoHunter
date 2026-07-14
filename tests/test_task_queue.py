from __future__ import annotations

import asyncio

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import orchestrator
from app.db.models import Base, Target, Task


def _run(coro):
    return asyncio.run(coro)


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
