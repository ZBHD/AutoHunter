from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents.depth_policy import depth_policy_for
from app.db.models import Base, EscalationAttempt, Finding, Review, Target, Task
from app.escalation_service import (
    claim_attempt,
    finalize_attempt,
    queue_attempt,
    recover_attempts,
)


async def _database(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'escalation.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        session.add(Task(id="task", name="Task", status="running"))
        session.add(Target(
            id="target", task_id="task", url="https://example.test", host="example.test",
            source="manual", status="done",
        ))
        for index in range(3):
            session.add(Finding(
                id=f"finding-{index}", task_id="task", target_id="target",
                vuln_type="idor", title=f"Finding {index}", severity_claimed="高危",
                target_url="https://example.test/api",
            ))
        await session.commit()
    return engine, sessions


def test_queue_attempt_is_persistent_and_idempotent(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                attempt, created = await queue_attempt(
                    session,
                    task_id="task",
                    finding_id="finding-0",
                    orig_severity="高危",
                )
                assert created is True
                assert attempt.status == "queued"
                assert attempt.round_budget == depth_policy_for("高危").escalation_rounds
                attempt_id = attempt.id
                await session.commit()

            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                assert persisted is not None
                duplicate, created = await queue_attempt(
                    session,
                    task_id="task",
                    finding_id="finding-0",
                    orig_severity="高危",
                )
                assert created is False
                assert duplicate.id == attempt_id
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_queue_attempt_records_budget_exhaustion(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import escalation_service

        engine, sessions = await _database(tmp_path)
        monkeypatch.setattr(escalation_service, "MAX_TASK_ATTEMPTS", 1)
        monkeypatch.setattr(escalation_service, "MAX_TASK_ROUNDS", 20)
        try:
            async with sessions() as session:
                first, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="中危"
                )
                second, created = await queue_attempt(
                    session, task_id="task", finding_id="finding-1", orig_severity="中危"
                )
                await session.commit()

                assert first.status == "queued"
                assert created is True
                assert second.status == "skipped"
                assert second.round_budget == 0
                assert second.error_kind == "budget_exhausted"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_completed_non_significant_attempt_still_consumes_task_budget(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import escalation_service

        engine, sessions = await _database(tmp_path)
        monkeypatch.setattr(escalation_service, "MAX_TASK_ATTEMPTS", 1)
        monkeypatch.setattr(escalation_service, "MAX_TASK_ROUNDS", 100)
        try:
            async with sessions() as session:
                first, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="低危"
                )
                await finalize_attempt(
                    session,
                    first.id,
                    status="skipped",
                    result={"escalated": False},
                    error_kind="not_significant",
                )
                second, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-1", orig_severity="低危"
                )

                assert first.round_budget == depth_policy_for("低危").escalation_rounds
                assert second.status == "skipped"
                assert second.round_budget == 0
                assert second.error_kind == "budget_exhausted"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_claim_finalize_and_restart_recovery(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                first, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="低危"
                )
                second, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-1", orig_severity="严重"
                )
                assert await claim_attempt(session, first.id) is True
                assert await claim_attempt(session, first.id) is False
                assert await claim_attempt(session, second.id) is True
                await finalize_attempt(
                    session,
                    first.id,
                    status="succeeded",
                    result={"escalated": True},
                )
                await session.commit()

            async with sessions() as session:
                queued_ids = await recover_attempts(session, task_id="task")
                await session.commit()
                first_row = await session.get(EscalationAttempt, first.id)
                second_row = await session.get(EscalationAttempt, second.id)

                assert first_row.status == "succeeded"
                assert second_row.status == "queued"
                assert second.id in queued_ids
                assert second_row.error_kind == "process_restart"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_claim_rejects_attempt_when_task_is_paused(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="中危"
                )
                task = await session.get(Task, "task")
                task.status = "paused"
                await session.flush()

                assert await claim_attempt(session, attempt.id) is False
                assert attempt.status == "queued"
                assert attempt.started_at is None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_runner_dispatches_persisted_queued_attempts(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator

        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="中危"
                )
                await session.commit()
                task = await session.get(Task, "task")
                runner = orchestrator.TaskRunner("task")
                dispatched: list[tuple[str, str]] = []

                def dispatch(task_id: str, attempt_id: str) -> bool:
                    dispatched.append((task_id, attempt_id))
                    return True

                monkeypatch.setattr(runner, "dispatch_escalation_attempt", dispatch)
                await runner._dispatch_escalation_attempts(session, task)

                assert dispatched == [("task", attempt.id)]
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_runner_finalizes_non_significant_persisted_attempt(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator
        from app.agents import escalate as escalate_module

        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="中危"
                )
                attempt_id = attempt.id
                await session.commit()

            class FakeExecutor:
                def kill_processes(self) -> None:
                    pass

            class FakeHunter:
                def __init__(self, *_args, **kwargs) -> None:
                    assert kwargs["max_rounds"] == depth_policy_for("中危").escalation_rounds
                    self.executor = FakeExecutor()

                def run(self):
                    return SimpleNamespace(
                        model_dump=lambda **_kwargs: {"escalated": False, "reason": "no new impact"}
                    )

            monkeypatch.setattr(escalate_module, "EscalateHunter", FakeHunter)
            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
            monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: asyncio.Semaphore(1))

            runner = orchestrator.TaskRunner("task")
            await runner._run_escalation_inner("task", attempt_id)

            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                assert persisted.status == "skipped"
                assert persisted.result["reason"] == "no new impact"
                assert persisted.finished_at is not None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_stop_waits_for_escalation_hunter_before_requeue(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator
        from app.agents import escalate as escalate_module

        engine, sessions = await _database(tmp_path)
        started = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        stop_task = None
        try:
            async with sessions() as session:
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="高危"
                )
                attempt_id = attempt.id
                await session.commit()

            class BlockingHunter:
                def __init__(self, *_args, **_kwargs) -> None:
                    self.executor = SimpleNamespace(kill_processes=lambda: None)

                def run(self):
                    started.set()
                    release.wait(timeout=5)
                    finished.set()
                    return SimpleNamespace(
                        model_dump=lambda **_kwargs: {"escalated": False, "reason": "cancelled"}
                    )

            monkeypatch.setattr(escalate_module, "EscalateHunter", BlockingHunter)
            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
            monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: asyncio.Semaphore(1))

            runner = orchestrator.TaskRunner("task")
            assert runner.dispatch_escalation_attempt("task", attempt_id) is True
            assert await asyncio.to_thread(started.wait, 2)

            stop_task = asyncio.create_task(runner.stop("stop escalation"))
            await asyncio.sleep(0.05)
            assert stop_task.done() is False

            release.set()
            await asyncio.wait_for(stop_task, timeout=2)
            assert finished.is_set()
            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                assert persisted.status == "queued"
                assert persisted.error_kind == "cancelled"
        finally:
            release.set()
            await asyncio.to_thread(finished.wait, 2)
            if stop_task is not None and not stop_task.done():
                await asyncio.wait_for(stop_task, timeout=2)
            await engine.dispose()

    asyncio.run(scenario())


def test_timeout_waits_for_hunter_and_records_failed_timeout(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator
        from app.agents import escalate as escalate_module

        engine, sessions = await _database(tmp_path)
        started = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        try:
            async with sessions() as session:
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="中危"
                )
                attempt_id = attempt.id
                await session.commit()

            class BlockingHunter:
                def __init__(self, *_args, **_kwargs) -> None:
                    self.executor = SimpleNamespace(kill_processes=lambda: None)

                def run(self):
                    started.set()
                    release.wait(timeout=5)
                    finished.set()
                    return SimpleNamespace(
                        model_dump=lambda **_kwargs: {"escalated": False, "reason": "late result"}
                    )

            monkeypatch.setattr(escalate_module, "EscalateHunter", BlockingHunter)
            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
            monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: asyncio.Semaphore(1))
            monkeypatch.setattr(orchestrator, "ESCALATE_WALL_TIMEOUT", 0.01)
            monkeypatch.setattr(orchestrator, "WORKER_CLEANUP_TIMEOUT", 0.01)

            runner = orchestrator.TaskRunner("task")
            assert runner.dispatch_escalation_attempt("task", attempt_id) is True
            assert await asyncio.to_thread(started.wait, 2)
            await asyncio.sleep(0.08)
            escalation_task = runner._escalation_tasks[attempt_id]
            assert escalation_task.done() is False

            release.set()
            await asyncio.wait_for(escalation_task, timeout=2)
            assert finished.is_set()
            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                assert persisted.status == "failed"
                assert persisted.error_kind == "timeout"
        finally:
            release.set()
            await asyncio.to_thread(finished.wait, 2)
            await engine.dispose()

    asyncio.run(scenario())


def test_runner_requeues_persisted_attempt_when_cancelled(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator

        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="高危"
                )
                attempt_id = attempt.id
                assert await claim_attempt(session, attempt_id) is True
                await session.commit()

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            runner = orchestrator.TaskRunner("task")

            async def cancelled(*_args):
                raise asyncio.CancelledError

            monkeypatch.setattr(runner, "_run_escalation_inner", cancelled)

            with pytest.raises(asyncio.CancelledError):
                await runner._run_escalation("task", attempt_id)

            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                assert persisted.status == "queued"
                assert persisted.error_kind == "cancelled"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_pause_cancels_and_requeues_running_escalation(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator

        engine, sessions = await _database(tmp_path)
        runner = orchestrator.TaskRunner("task")
        attempt_id = ""
        task = None
        try:
            async with sessions() as session:
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="高危"
                )
                attempt_id = attempt.id
                assert await claim_attempt(session, attempt_id) is True
                await session.commit()

            started = asyncio.Event()
            release = asyncio.Event()

            async def wait_until_cancelled(*_args):
                started.set()
                await release.wait()

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(runner, "_run_escalation_inner", wait_until_cancelled)
            task = asyncio.create_task(runner._run_escalation("task", attempt_id))
            runner._escalation_tasks[attempt_id] = task
            runner._escalation_inflight.add(attempt_id)
            await started.wait()

            await runner.pause("pause escalation")

            assert task.done()
            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                assert persisted.status == "queued"
                assert persisted.error_kind == "cancelled"
        finally:
            if task is not None and not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
            await engine.dispose()

    asyncio.run(scenario())


def test_pause_rejects_escalation_dispatched_after_cancel_snapshot() -> None:
    async def scenario() -> None:
        from app import orchestrator

        runner = orchestrator.TaskRunner("task")
        existing_started = asyncio.Event()
        existing_cancelled = asyncio.Event()
        existing_release = asyncio.Event()
        new_started = asyncio.Event()
        new_release = asyncio.Event()

        async def existing_hunt():
            existing_started.set()
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                existing_cancelled.set()
                await existing_release.wait()

        async def new_hunt(*_args):
            new_started.set()
            await new_release.wait()

        existing_task = asyncio.create_task(existing_hunt())
        runner._escalation_tasks["attempt-existing"] = existing_task
        runner._escalation_inflight.add("attempt-existing")
        runner._run_escalation = new_hunt
        new_task = None
        try:
            await existing_started.wait()
            pause_task = asyncio.create_task(runner.pause("pause race"))
            await existing_cancelled.wait()

            dispatched = runner.dispatch_escalation_attempt("task", "attempt-new")
            new_task = runner._escalation_tasks.get("attempt-new")

            existing_release.set()
            await pause_task
            await asyncio.sleep(0)

            assert dispatched is False
            assert new_started.is_set() is False
            assert runner._escalation_tasks == {}
            assert runner._escalation_inflight == set()
        finally:
            existing_release.set()
            new_release.set()
            if new_task is not None and not new_task.done():
                new_task.cancel()
                await asyncio.gather(new_task, return_exceptions=True)
            if not existing_task.done():
                existing_task.cancel()
                await asyncio.gather(existing_task, return_exceptions=True)

    asyncio.run(scenario())


def test_runner_resume_reenables_escalation_dispatch() -> None:
    async def scenario() -> None:
        from app import orchestrator

        runner = orchestrator.TaskRunner("task")
        await runner.pause("paused")
        assert runner.dispatch_escalation_attempt("task", "attempt-paused") is False

        release = asyncio.Event()

        async def fake_hunt(*_args):
            await release.wait()

        runner._run_escalation = fake_hunt
        runner.resume()
        assert runner.dispatch_escalation_attempt("task", "attempt-resumed") is True
        task = runner._escalation_tasks["attempt-resumed"]
        release.set()
        await task

    asyncio.run(scenario())


def test_manager_pause_serializes_resume_with_lifecycle_lock() -> None:
    async def scenario() -> None:
        from app import orchestrator

        pause_entered = asyncio.Event()
        pause_release = asyncio.Event()
        run_release = asyncio.Event()
        resumed = asyncio.Event()

        class FakeRunner:
            async def pause(self):
                pause_entered.set()
                await pause_release.wait()

            def resume(self):
                resumed.set()

        manager = orchestrator.OrchestratorManager()
        runner = FakeRunner()
        run_task = asyncio.create_task(run_release.wait())
        manager._runners["task"] = runner
        manager._tasks["task"] = run_task
        try:
            pause_task = asyncio.create_task(manager.pause("task"))
            await pause_entered.wait()
            resume_task = asyncio.create_task(manager.ensure_running("task"))
            await asyncio.sleep(0.05)

            assert resume_task.done() is False
            assert resumed.is_set() is False

            pause_release.set()
            await pause_task
            await resume_task
            assert resumed.is_set() is True
        finally:
            pause_release.set()
            run_release.set()
            await run_task

    asyncio.run(scenario())


def test_paused_task_does_not_claim_queued_escalation(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator

        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                task = await session.get(Task, "task")
                task.status = "paused"
                attempt, _ = await queue_attempt(
                    session, task_id="task", finding_id="finding-0", orig_severity="中危"
                )
                attempt_id = attempt.id
                await session.commit()

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(
                orchestrator,
                "_llm_for_task",
                lambda _task: pytest.fail("paused escalation reached LLM dispatch"),
            )

            runner = orchestrator.TaskRunner("task")
            await runner._run_escalation_inner("task", attempt_id)

            async with sessions() as session:
                persisted = await session.get(EscalationAttempt, attempt_id)
                assert persisted.status == "queued"
                assert persisted.started_at is None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_stop_during_escalation_query_prevents_late_dispatch() -> None:
    async def scenario() -> None:
        from app import orchestrator

        runner = orchestrator.TaskRunner("task")
        query_entered = asyncio.Event()
        query_release = asyncio.Event()
        hunt_release = asyncio.Event()

        class DelayedScalars:
            def all(self):
                return [SimpleNamespace(id="attempt-late")]

        class DelayedSession:
            async def scalars(self, _query):
                query_entered.set()
                await query_release.wait()
                return DelayedScalars()

        async def fake_hunt(*_args):
            await hunt_release.wait()

        runner._run_escalation = fake_hunt
        dispatch_task = asyncio.create_task(
            runner._dispatch_escalation_attempts(
                DelayedSession(),
                SimpleNamespace(id="task"),
            )
        )
        await query_entered.wait()
        await runner.stop("stop during escalation query")
        query_release.set()
        await dispatch_task
        await asyncio.sleep(0)

        late_tasks = list(runner._escalation_tasks.values())
        for task in late_tasks:
            task.cancel()
        if late_tasks:
            await asyncio.gather(*late_tasks, return_exceptions=True)
        hunt_release.set()

        assert runner._escalation_inflight == set()
        assert runner._escalation_tasks == {}

    asyncio.run(scenario())


def test_dispatch_escalation_refuses_after_runner_stop() -> None:
    async def scenario() -> None:
        from app import orchestrator

        runner = orchestrator.TaskRunner("task")
        release = asyncio.Event()

        async def fake_hunt(*_args):
            await release.wait()

        runner._run_escalation = fake_hunt
        await runner.stop("stopped")
        dispatched = runner.dispatch_escalation_attempt("task", "attempt-after-stop")
        await asyncio.sleep(0)
        late_tasks = list(runner._escalation_tasks.values())
        for task in late_tasks:
            task.cancel()
        if late_tasks:
            await asyncio.gather(*late_tasks, return_exceptions=True)
        release.set()

        assert dispatched is False
        assert runner._escalation_inflight == set()
        assert runner._escalation_tasks == {}

    asyncio.run(scenario())


def test_tick_keeps_task_running_while_escalation_is_active(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator

        engine, sessions = await _database(tmp_path)
        release = asyncio.Event()
        active_task = asyncio.create_task(release.wait())
        try:
            runner = orchestrator.TaskRunner("task")
            runner._escalation_tasks["attempt-running"] = active_task

            async def no_refill(*_args, **_kwargs):
                return 0

            async def no_op(*_args, **_kwargs):
                return None

            async def zero(*_args, **_kwargs):
                return 0

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(orchestrator.collector, "refill", no_refill)
            monkeypatch.setattr(runner, "_reclaim_stale", no_op)
            monkeypatch.setattr(runner, "_pop_queued", no_op)
            monkeypatch.setattr(runner, "_dispatch_reviews", no_op)
            monkeypatch.setattr(runner, "_dispatch_escalation_attempts", no_op)
            monkeypatch.setattr(runner, "_dispatch_killsweep_attempts", no_op)
            monkeypatch.setattr(runner, "_count", zero)
            monkeypatch.setattr(runner, "_count_inflight", zero)

            await runner._tick()

            async with sessions() as session:
                task = await session.get(Task, "task")
                assert task.status == "running"
        finally:
            release.set()
            await active_task
            await engine.dispose()

    asyncio.run(scenario())


def test_accepted_review_commits_persistent_attempt_before_dispatch(tmp_path, monkeypatch) -> None:
    async def scenario() -> None:
        from app import orchestrator

        engine, sessions = await _database(tmp_path)
        try:
            class FakeReviewer:
                def __init__(self, *_args, **_kwargs) -> None:
                    pass

                def review(self, _finding):
                    return SimpleNamespace(model_dump=lambda **_kwargs: {
                        "verdict": "accepted",
                        "confidence": "likely",
                        "severity_final": "高危",
                        "score": 8.0,
                        "in_scope": True,
                        "is_duplicate": False,
                        "ignore_reasons": [],
                        "downgrade_reasons": [],
                        "reproduced": False,
                        "reviewer_notes": "accepted",
                        "deepen_directive": "",
                    })

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(orchestrator, "Reviewer", FakeReviewer)
            monkeypatch.setattr(orchestrator, "_llm_for_task", lambda _task: object())
            monkeypatch.setattr(orchestrator, "agent_semaphore", lambda _kind: asyncio.Semaphore(1))
            runner = orchestrator.TaskRunner("task")
            dispatched: list[tuple[str, str]] = []
            monkeypatch.setattr(
                runner,
                "dispatch_escalation_attempt",
                lambda task_id, attempt_id: dispatched.append((task_id, attempt_id)) or True,
            )

            await runner._run_review_inner("task", "finding-0")

            async with sessions() as session:
                review = await session.scalar(
                    select(Review).where(Review.finding_id == "finding-0")
                )
                attempt = await session.scalar(
                    select(EscalationAttempt).where(
                        EscalationAttempt.finding_id == "finding-0"
                    )
                )
                assert review is not None
                assert review.verdict == "accepted"
                assert attempt is not None
                assert attempt.status == "queued"
                assert dispatched == [("task", attempt.id)]
        finally:
            await engine.dispose()

    asyncio.run(scenario())
