from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import tasks as tasks_api
from app.config import worker_config
from app.db.models import (
    Base,
    Killsweep,
    KillsweepAttempt,
    KillsweepEvent,
    KillsweepReanalysisBatch,
    MissedSignal,
    MissedSignalDraft,
    MissedSignalEvent,
    RawEvidence,
    RawEvidenceChunk,
    Target,
    Task,
)
from app.db.session import get_session
from app.raw_evidence import CaptureCleanupError


def test_task_delete_waits_for_runtime_and_removes_operations_data(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(worker_config, "work_root", str(tmp_path))
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'delete.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    owned_spool = tmp_path / "work" / "owned" / ".captures" / "evidence-delete"
    owned_spool.mkdir(parents=True)
    (owned_spool / "corrupt.bin").write_bytes(b"corrupt-or-partial")
    unrelated_spool = owned_spool.parent / "evidence-other-task"
    unrelated_spool.mkdir()
    (unrelated_spool / "output.bin").write_bytes(b"must-survive")
    legacy_spool = tmp_path / "legacy-target" / ".captures" / "evidence-legacy"
    legacy_spool.mkdir(parents=True)
    (legacy_spool / "output.bin").write_bytes(b"legacy-failed-import")
    legacy_complete_spool = tmp_path / "legacy-complete" / ".captures" / "evidence-legacy-complete"
    legacy_complete_spool.mkdir(parents=True)
    (legacy_complete_spool / "response.bin").write_bytes(b"legacy-complete-capture")

    async def setup():
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-delete", name="Delete", status="stopped"))
            session.add(Target(
                id="target-delete", task_id="task-delete", url="https://delete.test",
                host="delete.test", status="done",
            ))
            signal = MissedSignal(
                id="signal-delete", task_id="task-delete", target_id="target-delete",
                dedup_key="delete-dedup", rule_key="exception_leak",
                endpoint_key="GET https://delete.test/error", status="pending",
            )
            session.add(signal)
            session.add(MissedSignalEvent(
                signal_id=signal.id, task_id="task-delete", kind="created",
                to_status="pending",
            ))
            session.add(MissedSignalDraft(
                id="draft-delete", signal_id=signal.id, task_id="task-delete",
                status="ready", content={}, revision=1,
            ))
            session.add(RawEvidence(
                id="evidence-delete", task_id="task-delete", target_id="target-delete",
                missed_signal_id=signal.id, source_kind="worker_http_request",
                capture_status="complete", metadata_json={"channels": {"response": {}}},
                spool_directory=str(owned_spool.resolve()),
            ))
            session.add(RawEvidenceChunk(
                evidence_id="evidence-delete", channel="response", seq=0, data=b"raw-secret",
            ))
            session.add(RawEvidence(
                id="evidence-legacy-complete", task_id="task-delete", target_id="target-delete",
                source_kind="worker_http_request", capture_status="complete",
                metadata_json={"import_complete": True}, spool_directory=None,
            ))
            session.add(RawEvidence(
                id="evidence-legacy", task_id="task-delete", source_kind="worker_run_shell",
                capture_status="failed", metadata_json={"import_complete": False},
            ))
            batch = KillsweepReanalysisBatch(id="batch-delete", filters={})
            case = Killsweep(
                id="case-delete", task_id="task-delete", origin_finding_id="legacy-source",
                legacy_without_timeline=True, status="failed",
            )
            attempt = KillsweepAttempt(
                id="attempt-delete", case_id=case.id, task_id="task-delete",
                batch_id=batch.id, attempt_no=1, status="failed",
            )
            session.add_all([batch, case, attempt])
            await session.flush()
            session.add(KillsweepEvent(
                case_id=case.id, attempt_id=attempt.id, task_id="task-delete",
                sequence=1, kind="failed",
            ))
            await session.commit()

    asyncio.run(setup())
    stop = AsyncMock()
    monkeypatch.setattr(tasks_api.manager, "stop", stop)

    async def override_session():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(tasks_api.router)
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        response = client.delete("/api/tasks/task-delete")

    assert response.status_code == 204, response.text
    stop.assert_awaited_once_with("task-delete")
    assert not owned_spool.exists()
    assert not legacy_spool.exists()
    assert not legacy_complete_spool.exists()
    assert (unrelated_spool / "output.bin").read_bytes() == b"must-survive"

    async def counts():
        async with sessions() as session:
            models = (
                Task, MissedSignal, MissedSignalEvent, MissedSignalDraft,
                RawEvidence, RawEvidenceChunk, Killsweep, KillsweepAttempt,
                KillsweepEvent, KillsweepReanalysisBatch,
            )
            return {
                model.__name__: await session.scalar(select(func.count()).select_from(model))
                for model in models
            }

    assert set(asyncio.run(counts()).values()) == {0}
    asyncio.run(engine.dispose())


def test_task_delete_keeps_database_ownership_when_spool_cleanup_fails(
    tmp_path, monkeypatch,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'cleanup-failure.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    spool = tmp_path / "work" / ".captures" / "evidence-failure"
    spool.mkdir(parents=True)
    (spool / "output.bin").write_bytes(b"pending")

    async def setup():
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-failure", name="Failure", status="stopped"))
            session.add(RawEvidence(
                id="evidence-failure", task_id="task-failure",
                source_kind="worker_run_shell", capture_status="failed",
                spool_directory=str(spool.resolve()),
            ))
            await session.commit()

    asyncio.run(setup())
    monkeypatch.setattr(tasks_api.manager, "stop", AsyncMock())

    def fail_cleanup(_evidence):
        raise CaptureCleanupError("locked")

    monkeypatch.setattr(tasks_api, "cleanup_evidence_spool", fail_cleanup)

    async def override_session():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(tasks_api.router)
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        response = client.delete("/api/tasks/task-failure")

    assert response.status_code == 409
    assert spool.exists()

    async def ownership_state():
        async with sessions() as session:
            return (
                await session.get(Task, "task-failure"),
                await session.get(RawEvidence, "evidence-failure"),
            )

    task, evidence = asyncio.run(ownership_state())
    assert task is not None
    assert evidence is not None
    assert evidence.spool_directory == str(spool.resolve())
    asyncio.run(engine.dispose())


def test_task_delete_preserves_shared_reanalysis_batch_until_last_task(tmp_path, monkeypatch) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'shared-batch.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def setup():
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add_all([
                Task(id="task-delete", name="Delete", status="stopped"),
                Task(id="task-keep", name="Keep", status="stopped"),
            ])
            batch = KillsweepReanalysisBatch(
                id="batch-shared", filters={"status": "failed"}, actor_role="readonly",
            )
            delete_case = Killsweep(
                id="case-delete", task_id="task-delete", origin_finding_id="legacy-delete",
                legacy_without_timeline=True, status="failed",
            )
            keep_case = Killsweep(
                id="case-keep", task_id="task-keep", origin_finding_id="legacy-keep",
                legacy_without_timeline=True, status="failed",
            )
            session.add_all([batch, delete_case, keep_case])
            await session.flush()
            session.add_all([
                KillsweepAttempt(
                    id="attempt-delete", case_id=delete_case.id, task_id="task-delete",
                    batch_id=batch.id, attempt_no=1, status="failed",
                ),
                KillsweepAttempt(
                    id="attempt-keep", case_id=keep_case.id, task_id="task-keep",
                    batch_id=batch.id, attempt_no=1, status="failed",
                ),
            ])
            await session.commit()

    asyncio.run(setup())
    stop = AsyncMock()
    monkeypatch.setattr(tasks_api.manager, "stop", stop)

    async def override_session():
        async with sessions() as session:
            yield session

    app = FastAPI()
    app.include_router(tasks_api.router)
    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        first = client.delete("/api/tasks/task-delete")
        assert first.status_code == 204, first.text

        async def shared_state():
            async with sessions() as session:
                batch = await session.get(KillsweepReanalysisBatch, "batch-shared")
                attempt = await session.get(KillsweepAttempt, "attempt-keep")
                return batch, attempt

        batch, attempt = asyncio.run(shared_state())
        assert batch is not None
        assert batch.filters == {"status": "failed"}
        assert batch.actor_role == "readonly"
        assert attempt is not None
        assert attempt.batch_id == batch.id

        second = client.delete("/api/tasks/task-keep")
        assert second.status_code == 204, second.text

    async def final_state():
        async with sessions() as session:
            return await session.get(KillsweepReanalysisBatch, "batch-shared")

    assert asyncio.run(final_state()) is None
    assert stop.await_args_list == [
        (("task-delete",), {}),
        (("task-keep",), {}),
    ]
    asyncio.run(engine.dispose())
