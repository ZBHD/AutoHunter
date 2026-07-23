from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import orchestrator
from app.agents import collector
from app.db.models import Base, GatewayAsset, Target, Task
from app.gateway_hunt.fingerprinter import gateway_target_source, origin_key


def _run(coro):
    return asyncio.run(coro)


async def _db(tmp_path, name: str = "litellm-orchestrator.db"):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / name}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, sessions


def test_litellm_manual_refill_creates_idempotent_target_and_asset(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _db(tmp_path)
        try:
            async with sessions() as session:
                task = Task(
                    id="task-litellm-collector",
                    name="LiteLLM collector",
                    src_type="litellm",
                    target_source="manual",
                    search_enabled=True,
                    manual_targets=["HTTPS://Gateway.TEST:443//proxy///"],
                )
                session.add(task)
                await session.commit()

                assert await collector.refill(session, task) == 1
                task = await session.get(Task, task.id)
                assert task is not None
                assert task.manual_targets == []
                assert await collector.refill(session, task) == 0

            async with sessions() as session:
                targets = list(await session.scalars(select(Target)))
                assets = list(await session.scalars(select(GatewayAsset)))
                assert len(targets) == 1
                assert len(assets) == 1
                canonical = origin_key("https://gateway.test/proxy")
                assert targets[0].source == gateway_target_source(canonical)
                assert targets[0].status == "queued"
                assert assets[0].origin_key == canonical
                assert assets[0].target_id == targets[0].id
        finally:
            await engine.dispose()

    _run(scenario())


def test_due_gateway_assets_are_requeued_atomically(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _db(tmp_path)
        try:
            now = datetime.now(timezone.utc)
            async with sessions() as session:
                task = Task(id="task-litellm-recheck", name="recheck", src_type="litellm", status="running")
                target = Target(
                    id="target-litellm-recheck", task_id=task.id, url="https://gateway.test",
                    host="gateway.test", source="gw:llm:recheck", status="done", verdict="no_vuln",
                )
                asset = GatewayAsset(
                    id="asset-litellm-recheck", task_id=task.id, target_id=target.id,
                    canonical_base_url=target.url, origin_key=target.url,
                    scan_state="scheduled_recheck", scan_epoch=3, next_scan_at=now - timedelta(seconds=1),
                )
                session.add_all([task, target, asset])
                await session.commit()
                runner = orchestrator.TaskRunner(task.id)
                assert await runner._requeue_due_gateway_assets(session, now=now) == 1

            async with sessions() as session:
                target = await session.get(Target, "target-litellm-recheck")
                asset = await session.get(GatewayAsset, "asset-litellm-recheck")
                assert target is not None and target.status == "queued"
                assert target.verdict == ""
                assert asset is not None and asset.scan_state == "discovered"
        finally:
            await engine.dispose()

    _run(scenario())


def test_litellm_dispatch_uses_gateway_scan_and_never_worker(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine, sessions = await _db(tmp_path)
        try:
            async with sessions() as session:
                task = Task(id="task-litellm-dispatch", name="dispatch", src_type="litellm", status="running")
                target = Target(
                    id="target-litellm-dispatch", task_id=task.id, url="https://gateway.test",
                    host="gateway.test", source="gw:llm:dispatch", status="queued",
                )
                asset = GatewayAsset(
                    id="asset-litellm-dispatch", task_id=task.id, target_id=target.id,
                    canonical_base_url=target.url, origin_key=target.url,
                )
                session.add_all([task, target, asset])
                await session.commit()

            runner = orchestrator.TaskRunner(task.id)
            runner._is_enterprise = False
            calls: list[str] = []

            async def fake_scan(*, asset_id, session, client, max_requests=24, now=None):
                calls.append(asset_id)
                return object()

            async def fake_client(*_args, **_kwargs):
                return object()

            monkeypatch.setattr(orchestrator.gateway_service, "scan_asset", fake_scan)
            monkeypatch.setattr(runner, "_gateway_scan_client", fake_client)
            monkeypatch.setattr(runner, "_run_worker", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("worker path")))
            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)

            async with sessions() as session:
                selected = await runner._pop_gateway_queued(session)
                assert selected is not None
                assert selected.id == target.id
                await runner._run_gateway_asset(task.id, selected.id, asset.id)

            assert calls == [asset.id]
        finally:
            await engine.dispose()

    _run(scenario())


def test_litellm_task_without_queued_targets_stays_running(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        engine, sessions = await _db(tmp_path)
        try:
            async with sessions() as session:
                session.add(Task(
                    id="task-litellm-idle", name="idle", src_type="litellm", status="running",
                    search_enabled=True, target_source="manual", manual_targets=[],
                ))
                await session.commit()
            monkeypatch.setattr(orchestrator.collector, "refill", lambda *args, **kwargs: _async_zero())
            runner = orchestrator.TaskRunner("task-litellm-idle")
            monkeypatch.setattr(runner, "_reclaim_stale", _async_none)
            monkeypatch.setattr(runner, "_dispatch_reviews", _async_none)
            monkeypatch.setattr(runner, "_dispatch_escalation_attempts", _async_none)
            monkeypatch.setattr(runner, "_dispatch_killsweep_attempts", _async_none)
            await runner._tick()
            async with sessions() as session:
                task = await session.get(Task, "task-litellm-idle")
                assert task is not None and task.status == "running"
        finally:
            await engine.dispose()

    async def _async_none(*_args, **_kwargs):
        return None

    async def _async_zero(*_args, **_kwargs):
        return 0

    _run(scenario())
