from __future__ import annotations

import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents import collector
from app.db.models import Base, Target, Task


def _run(coro):
    return asyncio.run(coro)


def test_refill_disabled_search_consumes_manual_target_without_fofa(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'collector-disabled.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        calls = []

        async def fake_fofa_collect(*args, **kwargs):
            calls.append((args, kwargs))
            return 13

        monkeypatch.setattr(collector, "_fofa_collect", fake_fofa_collect)

        async with sessions() as session:
            task = Task(
                id="task-collector-disabled",
                name="Collector disabled",
                status="running",
                target_source="both",
                search_enabled=False,
                manual_targets=["manual.example"],
            )
            session.add(task)
            await session.commit()

            added = await collector.refill(session, task)

            targets = list(await session.scalars(
                select(Target).where(Target.task_id == task.id)
            ))
            assert added == 1
            assert calls == []
            assert task.manual_targets == []
            assert [(target.host, target.source, target.status) for target in targets] == [
                ("manual.example", "manual", "queued"),
            ]

        await engine.dispose()

    _run(scenario())


def test_refill_enabled_search_collects_fofa_after_manual_target(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'collector-enabled.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

        calls = []

        async def fake_fofa_collect(*args, **kwargs):
            calls.append((args, kwargs))
            return 3

        monkeypatch.setattr(collector, "_fofa_collect", fake_fofa_collect)

        async with sessions() as session:
            task = Task(
                id="task-collector-enabled",
                name="Collector enabled",
                status="running",
                target_source="both",
                search_enabled=True,
                manual_targets=["manual.example"],
            )
            session.add(task)
            await session.commit()

            added = await collector.refill(session, task)

            assert added == 4
            assert len(calls) == 1
            assert task.manual_targets == []
            targets = list(await session.scalars(
                select(Target).where(Target.task_id == task.id)
            ))
            assert [(target.host, target.source, target.status) for target in targets] == [
                ("manual.example", "manual", "queued"),
            ]

        await engine.dispose()

    _run(scenario())
