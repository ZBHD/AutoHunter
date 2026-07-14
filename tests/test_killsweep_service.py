from __future__ import annotations

import asyncio
import hashlib
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import (
    Base,
    Finding,
    Killsweep,
    KillsweepAttempt,
    KillsweepEvent,
    KillsweepReanalysisBatch,
    RawEvidence,
    RawEvidenceChunk,
    Target,
    Task,
)
from app.killsweep_service import (
    append_event,
    apply_manual_verdict,
    automatic_verdict_for,
    claim_attempt,
    create_reanalysis_batch,
    finalize_attempt,
    queue_initial_attempt,
    queue_reanalysis,
    recover_attempts,
)

_SOURCE_RAW_REQUEST = "GET /probe?id=source HTTP/1.1\r\nHost: origin.test\r\n\r\n"
_SOURCE_RAW_RESPONSE = (
    'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
    '{"access_token":"source-token-value-123456"}'
)
_CANDIDATE_SIGNAL_BODY = '{"access_token":"candidate-token-value-654321"}'


def _run(coro):
    return asyncio.run(coro)


async def _database(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'killsweep.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    async with sessions() as session:
        session.add(Task(id="task", name="Task", status="running"))
        session.add(Target(
            id="target", task_id="task", url="https://origin.test", host="origin.test",
            source="manual", status="done",
        ))
        session.add(Finding(
            id="finding", task_id="task", target_id="target", vuln_type="info_leak",
            title="Token exposure", severity_claimed="high", target_url="https://origin.test/api",
            raw_request=_SOURCE_RAW_REQUEST,
            raw_response=_SOURCE_RAW_RESPONSE,
        ))
        await session.commit()
    return engine, sessions


def test_human_pass_persists_queued_attempt_in_callers_transaction(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, created = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                assert created is True
                assert case.status == "queued"
                assert attempt.status == "queued"
                assert attempt.attempt_no == 1
                assert case.current_attempt_id == attempt.id
                await session.rollback()

            async with sessions() as session:
                assert await session.scalar(select(func.count(Killsweep.id))) == 0
                assert await session.scalar(select(func.count(KillsweepAttempt.id))) == 0
        finally:
            await engine.dispose()

    _run(scenario())


def test_unverified_positive_stays_pending_validation(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, attempt.id)
                await finalize_attempt(session, attempt.id, result={
                    "product_name": "Example CMS",
                    "is_killsweep": True,
                    "verified": False,
                    "verified_url": "",
                })
                await session.commit()

            async with sessions() as session:
                stored_case = await session.get(Killsweep, case.id)
                stored_attempt = await session.get(KillsweepAttempt, attempt.id)
                assert stored_case.status == "succeeded"
                assert stored_case.is_killsweep is False
                assert stored_case.automatic_verdict == "pending_validation"
                assert stored_attempt.automatic_verdict == "pending_validation"
        finally:
            await engine.dispose()

    _run(scenario())


def test_retry_appends_attempt_without_overwriting_history(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, first, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, first.id)
                await finalize_attempt(
                    session, first.id, error_kind="llm_error", error_message="provider down"
                )
                second = await queue_reanalysis(session, case.id)
                await session.commit()

            async with sessions() as session:
                attempts = (await session.scalars(
                    select(KillsweepAttempt)
                    .where(KillsweepAttempt.case_id == case.id)
                    .order_by(KillsweepAttempt.attempt_no)
                )).all()
                assert [item.attempt_no for item in attempts] == [1, 2]
                assert attempts[0].status == "failed"
                assert attempts[0].error_message == "provider down"
                assert attempts[1].id == second.id
                assert attempts[1].status == "queued"
        finally:
            await engine.dispose()

    _run(scenario())


def test_successful_finalize_requires_a_claimed_running_attempt(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                returned = await finalize_attempt(
                    session, attempt.id, result={"is_killsweep": False}
                )
                await session.flush()
                completed_events = int(await session.scalar(
                    select(func.count(KillsweepEvent.id)).where(
                        KillsweepEvent.attempt_id == attempt.id,
                        KillsweepEvent.kind == "completed",
                    )
                ) or 0)

                assert returned.status == "queued"
                assert case.status == "queued"
                assert case.current_attempt_id == attempt.id
                assert completed_events == 0
        finally:
            await engine.dispose()

    _run(scenario())


def test_stale_finalizer_cannot_overwrite_terminal_attempt_or_case(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as setup:
                case, attempt, _ = await queue_initial_attempt(
                    setup, task_id="task", finding_id="finding"
                )
                await claim_attempt(setup, attempt.id)
                await setup.commit()

            async with sessions() as winner, sessions() as stale:
                stale_attempt = await stale.get(KillsweepAttempt, attempt.id)
                stale_case = await stale.get(Killsweep, case.id)
                assert stale_attempt.status == "running"
                assert stale_case.status == "running"
                # End the read transaction while retaining deliberately stale ORM state.
                await stale.commit()

                await finalize_attempt(
                    winner, attempt.id, result={"is_killsweep": False}
                )
                await winner.commit()

                losing_result = await finalize_attempt(
                    stale,
                    attempt.id,
                    error_kind="late_failure",
                    error_message="陈旧失败不得覆盖成功",
                )
                await stale.commit()
                assert losing_result.status == "succeeded"

            async with sessions() as session:
                stored_attempt = await session.get(KillsweepAttempt, attempt.id)
                stored_case = await session.get(Killsweep, case.id)
                terminal_events = (await session.scalars(
                    select(KillsweepEvent).where(
                        KillsweepEvent.attempt_id == attempt.id,
                        KillsweepEvent.kind.in_(["completed", "failed"]),
                    )
                )).all()
                assert stored_attempt.status == "succeeded"
                assert stored_attempt.error_kind == ""
                assert stored_case.status == "succeeded"
                assert stored_case.failure_kind == ""
                assert [event.kind for event in terminal_events] == ["completed"]
        finally:
            await engine.dispose()

    _run(scenario())


def test_finalize_requires_attempt_to_still_be_current_for_case(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, attempt.id)
                case.current_attempt_id = "newer-attempt"
                await session.commit()

            async with sessions() as session:
                returned = await finalize_attempt(
                    session, attempt.id, result={"is_killsweep": False}
                )
                await session.commit()
                terminal_events = int(await session.scalar(
                    select(func.count(KillsweepEvent.id)).where(
                        KillsweepEvent.attempt_id == attempt.id,
                        KillsweepEvent.kind.in_(["completed", "failed", "cancelled"]),
                    )
                ) or 0)
                stored_case = await session.get(Killsweep, case.id)

                assert returned.status == "running"
                assert stored_case.current_attempt_id == "newer-attempt"
                assert terminal_events == 0
        finally:
            await engine.dispose()

    _run(scenario())


def test_manual_verdict_coexists_and_negative_cancels_only_queued_derived_targets(
    tmp_path, monkeypatch
) -> None:
    proven_result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://verified.test/probe?id=1",
        status=200,
        vuln_type="info_leak",
    )

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, attempt.id)
                await _attach_persisted_verification_evidence(
                    session, case, attempt, proven_result
                )
                await finalize_attempt(session, attempt.id, result=proven_result)
                session.add_all([
                    Target(
                        id="queued-child", task_id="task", url="https://queued.test",
                        host="queued.test", source="killsweep", status="queued",
                        killsweep_case_id=case.id,
                    ),
                    Target(
                        id="running-child", task_id="task", url="https://running.test",
                        host="running.test", source="killsweep", status="scanning",
                        killsweep_case_id=case.id,
                    ),
                ])
                await session.flush()
                cancelled = await apply_manual_verdict(
                    session, case.id, verdict="not_killsweep", reason="误报", actor="full"
                )
                await session.commit()

            async with sessions() as session:
                stored = await session.get(Killsweep, case.id)
                queued = await session.get(Target, "queued-child")
                running = await session.get(Target, "running-child")
                assert stored.automatic_verdict == "killsweep"
                assert stored.manual_verdict == "not_killsweep"
                assert cancelled == 1
                assert queued.status == "skipped"
                assert running.status == "scanning"
        finally:
            await engine.dispose()

    _run(scenario())


def test_batch_selects_oldest_allowed_cases_and_caps_at_40(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        now = datetime.now(timezone.utc)
        try:
            async with sessions() as session:
                for index in range(45):
                    case = Killsweep(
                        id=f"case-{index:02d}", task_id="task",
                        origin_finding_id=f"legacy-{index:02d}", legacy_without_timeline=True,
                        status="failed", failure_kind="llm_error",
                        finished_at=now - timedelta(hours=45 - index),
                    )
                    session.add(case)
                await session.flush()
                batch, attempts = await create_reanalysis_batch(
                    session, filters={"status": "failed"}, actor_role="full"
                )
                await session.commit()

            assert len(attempts) == 40
            assert attempts[0].case_id == "case-00"
            assert attempts[-1].case_id == "case-39"
            assert all(item.batch_id == batch.id for item in attempts)
        finally:
            await engine.dispose()

    _run(scenario())


def test_empty_reanalysis_batch_is_not_persisted(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                batch, attempts = await create_reanalysis_batch(
                    session,
                    filters={"task_id": "task", "status": "failed"},
                    actor_role="full",
                )
                batch_id = batch.id
                assert attempts == []
                await session.commit()

            async with sessions() as session:
                assert await session.get(KillsweepReanalysisBatch, batch_id) is None
        finally:
            await engine.dispose()

    _run(scenario())


def test_service_recomputes_verification_from_database_source_finding(
    tmp_path, monkeypatch
) -> None:
    signed_result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        vuln_type="info_leak",
    )
    assert signed_result.get("_http_verification_proof")

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                finding = await session.get(Finding, "finding")
                finding.raw_response = (
                    "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nhealthy"
                )
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, attempt.id)
                await finalize_attempt(session, attempt.id, result=signed_result)
                await session.commit()

            async with sessions() as session:
                stored = await session.get(Killsweep, case.id)
                assert stored.automatic_verdict == "pending_validation"
                assert stored.verified is False
        finally:
            await engine.dispose()

    _run(scenario())


def test_finalize_accepts_only_capture_persisted_for_current_attempt(
    tmp_path, monkeypatch,
) -> None:
    signed_result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        vuln_type="info_leak",
    )

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, attempt.id)
                await _attach_persisted_verification_evidence(
                    session, case, attempt, signed_result
                )
                await finalize_attempt(session, attempt.id, result=signed_result)
                await session.commit()
                stored = await session.get(Killsweep, case.id)
                assert stored.automatic_verdict == "killsweep"
        finally:
            await engine.dispose()

    _run(scenario())


@pytest.mark.parametrize(
    "corruption",
    [
        "request_bytes",
        "response_bytes",
        "request_sequence",
        "request_size",
        "request_chunk_count",
        "request_tail",
    ],
)
def test_finalize_rejects_verification_when_persisted_chunks_are_inconsistent(
    tmp_path, monkeypatch, corruption: str,
) -> None:
    signed_result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        vuln_type="info_leak",
    )

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, attempt.id)
                await _attach_persisted_verification_evidence(
                    session, case, attempt, signed_result
                )
                capture_id = signed_result["_http_verification_proof"]["capture_id"]
                request_chunk = await session.scalar(
                    select(RawEvidenceChunk).where(
                        RawEvidenceChunk.evidence_id == capture_id,
                        RawEvidenceChunk.channel == "request",
                    )
                )
                response_chunk = await session.scalar(
                    select(RawEvidenceChunk).where(
                        RawEvidenceChunk.evidence_id == capture_id,
                        RawEvidenceChunk.channel == "response",
                    )
                )
                evidence = await session.get(RawEvidence, capture_id)

                if corruption == "request_bytes":
                    request_chunk.data += b"tampered"
                elif corruption == "response_bytes":
                    response_chunk.data += b"tampered"
                elif corruption == "request_sequence":
                    request_chunk.seq = 1
                elif corruption == "request_tail":
                    session.add(RawEvidenceChunk(
                        evidence_id=capture_id,
                        channel="request",
                        seq=1,
                        data=b"unexpected-tail",
                    ))
                else:
                    metadata = dict(evidence.metadata_json)
                    channels = {
                        name: dict(value)
                        for name, value in metadata["channels"].items()
                    }
                    metadata["channels"] = channels
                    if corruption == "request_size":
                        channels["request"]["size"] += 1
                    else:
                        channels["request"]["chunks"] += 1
                    evidence.metadata_json = metadata

                await session.flush()
                await finalize_attempt(session, attempt.id, result=signed_result)
                await session.commit()

                stored = await session.get(Killsweep, case.id)
                assert stored.automatic_verdict == "pending_validation"
                assert stored.verified is False
        finally:
            await engine.dispose()

    _run(scenario())


@pytest.mark.parametrize("needle", ["Related Task", "Related Finding"])
def test_batch_filters_ignore_all_and_search_related_rows(tmp_path, needle) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                task = await session.get(Task, "task")
                finding = await session.get(Finding, "finding")
                task.name = "Related Task"
                finding.title = "Related Finding"
                session.add(Killsweep(
                    id="related-case",
                    task_id="task",
                    origin_finding_id="finding",
                    legacy_without_timeline=True,
                    status="failed",
                    vuln_summary="opaque case text",
                    failure_message="opaque failure",
                ))
                await session.commit()

            async with sessions() as session:
                _batch, attempts = await create_reanalysis_batch(
                    session,
                    filters={
                        "status": "all",
                        "manual_verdict": "all",
                        "q": needle,
                    },
                    actor_role="full",
                )
                assert [attempt.case_id for attempt in attempts] == ["related-case"]
        finally:
            await engine.dispose()

    _run(scenario())


def test_batch_automatic_filter_requires_succeeded_case(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                session.add_all([
                    Killsweep(
                        id="succeeded-not-killsweep",
                        task_id="task",
                        origin_finding_id="legacy-succeeded",
                        legacy_without_timeline=True,
                        status="succeeded",
                        automatic_verdict="not_killsweep",
                    ),
                    Killsweep(
                        id="failed-not-killsweep",
                        task_id="task",
                        origin_finding_id="legacy-failed",
                        legacy_without_timeline=True,
                        status="failed",
                        automatic_verdict="not_killsweep",
                    ),
                ])
                await session.commit()

            async with sessions() as session:
                _batch, attempts = await create_reanalysis_batch(
                    session,
                    filters={"status": "not_killsweep"},
                    actor_role="full",
                )
                assert [attempt.case_id for attempt in attempts] == [
                    "succeeded-not-killsweep"
                ]
        finally:
            await engine.dispose()

    _run(scenario())


def test_restart_fails_running_attempt_and_returns_queued_attempt_ids(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                first_case, first, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, first.id)
                queued_case = Killsweep(
                    id="queued-case", task_id="task", origin_finding_id="legacy",
                    legacy_without_timeline=True, status="queued",
                )
                queued_attempt = KillsweepAttempt(
                    id="queued-attempt", case_id=queued_case.id, task_id="task",
                    attempt_no=1, status="queued",
                )
                queued_case.current_attempt_id = queued_attempt.id
                session.add_all([queued_case, queued_attempt])
                await session.commit()

            async with sessions() as session:
                queued_ids = await recover_attempts(session, task_id="task")
                await session.commit()

            async with sessions() as session:
                failed = await session.get(KillsweepAttempt, first.id)
                case = await session.get(Killsweep, first_case.id)
                event = await session.scalar(select(KillsweepEvent).where(
                    KillsweepEvent.attempt_id == first.id,
                    KillsweepEvent.kind == "process_restart",
                ))
                assert failed.status == "failed"
                assert failed.error_kind == "process_restart"
                assert case.status == "failed"
                assert queued_ids == ["queued-attempt"]
                assert event is not None
        finally:
            await engine.dispose()

    _run(scenario())


def test_concurrent_events_use_global_database_sequence(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                session.add_all([
                    Killsweep(
                        id="event-case-a",
                        task_id="task",
                        origin_finding_id="legacy-event-a",
                        legacy_without_timeline=True,
                        status="failed",
                    ),
                    Killsweep(
                        id="event-case-b",
                        task_id="task",
                        origin_finding_id="legacy-event-b",
                        legacy_without_timeline=True,
                        status="failed",
                    ),
                ])
                await session.commit()

            async def write_event(case_id: str):
                async with sessions() as session:
                    event = await append_event(
                        session,
                        case_id=case_id,
                        attempt_id=None,
                        kind="concurrent",
                        summary=case_id,
                    )
                    await session.commit()
                    return event.id, event.sequence

            written = await asyncio.gather(
                write_event("event-case-a"),
                write_event("event-case-b"),
            )
            assert all(event_id == sequence for event_id, sequence in written)
            assert len({sequence for _event_id, sequence in written}) == 2

            async with sessions() as session:
                stored = (await session.scalars(
                    select(KillsweepEvent)
                    .where(KillsweepEvent.kind == "concurrent")
                    .order_by(KillsweepEvent.sequence, KillsweepEvent.id)
                )).all()
                assert [event.sequence for event in stored] == sorted(
                    event.id for event in stored
                )
        finally:
            await engine.dispose()

    _run(scenario())


def test_negative_manual_verdict_requires_reason(tmp_path) -> None:
    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, _attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                with pytest.raises(ValueError, match="reason"):
                    await apply_manual_verdict(
                        session, case.id, verdict="invalid", reason="", actor="full"
                    )
        finally:
            await engine.dispose()

    _run(scenario())


@pytest.mark.parametrize("verdict", ["not_killsweep", "invalid"])
def test_negative_manual_verdict_permanently_blocks_derived_targets(
    tmp_path, verdict
) -> None:
    from app import orchestrator

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, _attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await apply_manual_verdict(
                    session,
                    case.id,
                    verdict=verdict,
                    reason="人工否定，禁止继续派生",
                    actor="full",
                )
                runner = orchestrator.TaskRunner("task")
                enqueued = await runner._enqueue_killsweep_target(
                    session,
                    "task",
                    case.id,
                    "https://derived.test/probe",
                    "https://origin.test/api",
                )
                await session.flush()

                derived = await session.scalar(
                    select(Target).where(Target.host == "derived.test")
                )
                assert enqueued is False
                assert derived is None
        finally:
            await engine.dispose()

    _run(scenario())


@pytest.mark.parametrize(
    ("fofa_config", "llm_fails", "expected_kind"),
    [
        ({}, False, "missing_fofa"),
        ({"key": "fofa-key"}, True, "missing_llm"),
    ],
)
def test_missing_runtime_configuration_finalizes_attempt(
    tmp_path, monkeypatch, fofa_config, llm_fails, expected_kind
) -> None:
    from app import orchestrator

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                task = await session.get(Task, "task")
                task.fofa_config = fofa_config
                _case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await session.commit()

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            if llm_fails:
                monkeypatch.setattr(
                    orchestrator,
                    "_llm_for_task",
                    lambda _task: (_ for _ in ()).throw(RuntimeError("no provider")),
                )
            runner = orchestrator.TaskRunner("task")
            await runner._run_killsweep_inner("task", attempt.id)

            async with sessions() as session:
                stored = await session.get(KillsweepAttempt, attempt.id)
                case = await session.get(Killsweep, stored.case_id)
                assert stored.status == "failed"
                assert stored.error_kind == expected_kind
                assert case.status == "failed"
        finally:
            await engine.dispose()

    _run(scenario())


def test_stop_waits_for_timed_out_hunter_and_late_events(tmp_path, monkeypatch) -> None:
    from app import orchestrator
    from app.agents import killsweep as killsweep_agent

    started = threading.Event()
    release = threading.Event()
    finished = threading.Event()

    class BlockingHunter:
        def __init__(self, *_args, on_event, cancel_event, **_kwargs):
            self.on_event = on_event
            self.cancel_event = cancel_event
            self.executor = SimpleNamespace(kill_processes=lambda: None)

        def run(self):
            started.set()
            release.wait(timeout=5)
            self.on_event(
                "killsweep_cleanup_finished",
                {"summary": "Hunter 清理完成后写入的事件"},
            )
            finished.set()
            return SimpleNamespace(
                model_dump=lambda mode="json": {"is_killsweep": False}
            )

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        stop_task = None
        try:
            async with sessions() as session:
                task = await session.get(Task, "task")
                task.fofa_config = {"key": "fofa-key"}
                _case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await session.commit()

            monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
            monkeypatch.setattr(
                orchestrator,
                "_llm_for_task",
                lambda _task: SimpleNamespace(enabled_providers=["test"]),
            )
            monkeypatch.setattr(orchestrator, "KILLSWEEP_WALL_TIMEOUT", 0.01)
            monkeypatch.setattr(orchestrator, "WORKER_CLEANUP_TIMEOUT", 0.01)
            monkeypatch.setattr(killsweep_agent, "KillsweepHunter", BlockingHunter)

            runner = orchestrator.TaskRunner("task")
            assert runner.dispatch_killsweep_attempt("task", attempt.id) is True
            assert await asyncio.to_thread(started.wait, 2)

            # Let both the wall timeout and the old bounded cleanup timeout elapse.
            await asyncio.sleep(0.08)
            stop_task = asyncio.create_task(runner.stop("删除任务"))
            await asyncio.sleep(0.03)
            assert stop_task.done() is False

            release.set()
            await asyncio.wait_for(stop_task, timeout=2)
            assert finished.is_set()

            async with sessions() as session:
                stored = await session.get(KillsweepAttempt, attempt.id)
                event = await session.scalar(
                    select(KillsweepEvent).where(
                        KillsweepEvent.attempt_id == attempt.id,
                        KillsweepEvent.kind == "killsweep_cleanup_finished",
                    )
                )
                assert stored.status == "cancelled"
                assert event is not None
        finally:
            release.set()
            await asyncio.to_thread(finished.wait, 2)
            if stop_task is not None and not stop_task.done():
                await asyncio.wait_for(stop_task, timeout=2)
            # The old implementation schedules the late event after stop returns.
            await asyncio.sleep(0.05)
            await engine.dispose()

    _run(scenario())


def test_hunter_emits_post_tool_result_and_detaches_full_capture(monkeypatch) -> None:
    from app.agents.killsweep import KillsweepHunter

    captured = {"id": "capture-id", "channels": []}
    events: list[tuple[str, dict]] = []
    hunter = KillsweepHunter(
        {"target_url": "https://origin.test", "title": "IDOR"},
        "fofa-key",
        llm=object(),
        on_event=lambda kind, data: events.append((kind, data)),
    )
    monkeypatch.setattr(
        hunter.executor,
        "http_request",
        lambda **_kwargs: {
            "ok": True,
            "status_code": 200,
            "body": "preview",
            "_capture": captured,
        },
    )

    result = hunter._dispatch("http_request", {"url": "https://target.test"})

    assert "_capture" not in result
    kind, event = events[-1]
    assert kind == "killsweep_tool_result"
    assert event["tool"] == "http_request"
    assert event["capture"] is captured
    assert event["payload"]["status_code"] == 200


def _verification_capture_bytes(
    *,
    requested: str,
    status: int,
    response_body: str = _CANDIDATE_SIGNAL_BODY,
    method: str = "GET",
) -> tuple[bytes, bytes]:
    request_bytes = (
        f"{method.upper()} {requested} HTTP/1.1\r\nHost: candidate.test\r\n\r\n"
    ).encode()
    response_bytes = (
        f"HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\n\r\n{response_body}"
    ).encode()
    return request_bytes, response_bytes


def _submit_hunter_result(
    monkeypatch,
    *,
    origin: str,
    requested: str,
    status: int,
    source_raw_request: str = _SOURCE_RAW_REQUEST,
    source_raw_response: str = _SOURCE_RAW_RESPONSE,
    response_body: str = _CANDIDATE_SIGNAL_BODY,
    vuln_type: str = "idor",
    method: str = "GET",
    data: str | None = None,
    response_url: str | None = None,
    follow_redirects: bool = False,
):
    from app.agents.killsweep import KillsweepHunter

    request_bytes, response_bytes = _verification_capture_bytes(
        requested=requested,
        status=status,
        response_body=response_body,
        method=method,
    )
    capture = {
        "id": f"capture-{status}-{requested}",
        "tool": "http_request",
        "status": "complete",
        "error": "",
        "meta": {"url": requested, "status_code": status},
        "channels": [
            {
                "name": "request",
                "size": len(request_bytes),
                "sha256": hashlib.sha256(request_bytes).hexdigest(),
            },
            {
                "name": "response",
                "size": len(response_bytes),
                "sha256": hashlib.sha256(response_bytes).hexdigest(),
            },
        ],
    }
    hunter = KillsweepHunter(
        {
            "target_url": origin,
            "id": "finding",
            "title": "IDOR",
            "vuln_type": vuln_type,
            "raw_request": source_raw_request,
            "raw_response": source_raw_response,
        },
        "fofa-key",
        llm=object(),
    )
    monkeypatch.setattr(
        hunter.executor,
        "http_request",
        lambda **_kwargs: {
            "ok": True,
            "status_code": status,
            "url": response_url or requested,
            "body": response_body,
            "_capture": capture,
        },
    )
    hunter._dispatch(
        "http_request", {
            "url": requested,
            "method": method,
            "data": data,
            "follow_redirects": follow_redirects,
        }
    )
    hunter._dispatch(
        "submit_killsweep",
        {
            "is_generic_product": True,
            "product_name": "Example CMS",
            "is_killsweep": True,
            "confidence": "confirmed",
            "verified": True,
            "verified_url": requested,
            "_http_verification_proof": {
                "capture_id": "model-forged",
                "signature": "model-forged",
            },
        },
    )
    return hunter._result


async def _attach_persisted_verification_evidence(
    session: AsyncSession,
    case: Killsweep,
    attempt: KillsweepAttempt,
    result: dict,
) -> None:
    proof = result["_http_verification_proof"]
    request_bytes, response_bytes = _verification_capture_bytes(
        requested=proof["url"],
        status=int(proof["status_code"]),
    )
    event = await append_event(
        session,
        case_id=case.id,
        attempt_id=attempt.id,
        kind="killsweep_tool_result",
        summary="persisted verification capture",
    )
    session.add(RawEvidence(
        id=proof["capture_id"],
        task_id=case.task_id,
        killsweep_event_id=event.id,
        source_kind="killsweep_http_request",
        capture_status="complete",
        metadata_json={
            "import_complete": True,
            "channels": {
                "request": {
                    "size": len(request_bytes),
                    "chunks": 1,
                    "sha256": proof["request_sha256"],
                },
                "response": {
                    "size": len(response_bytes),
                    "chunks": 1,
                    "sha256": proof["response_sha256"],
                },
            },
        },
    ))
    session.add_all([
        RawEvidenceChunk(
            evidence_id=proof["capture_id"], channel="request", seq=0,
            data=request_bytes,
        ),
        RawEvidenceChunk(
            evidence_id=proof["capture_id"], channel="response", seq=0,
            data=response_bytes,
        ),
    ])
    await session.flush()


def test_strict_response_signal_unrelated_to_source_vulnerability_stays_pending(
    monkeypatch,
) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        vuln_type="idor",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result
    assert automatic_verdict_for(
        result,
        source_url="https://origin.test/api",
        source_raw_request=_SOURCE_RAW_REQUEST,
        source_raw_response=_SOURCE_RAW_RESPONSE,
        source_vuln_type="idor",
    ) == "pending_validation"


def test_different_strict_signal_or_request_shape_stays_unverified(monkeypatch) -> None:
    different_signal = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        response_body=(
            'Traceback (most recent call last):\n  File "app.py", line 42, in handler'
        ),
        vuln_type="info_leak",
    )
    different_path = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/other?id=1",
        status=200,
        vuln_type="info_leak",
    )

    assert different_signal["verified"] is False
    assert different_path["verified"] is False


def test_different_post_parameter_names_do_not_match_source_poc(monkeypatch) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/probe",
        requested="https://candidate.test/probe",
        status=200,
        source_raw_request=(
            "POST /probe HTTP/1.1\r\nHost: origin.test\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n\r\nobject_id=1"
        ),
        vuln_type="info_leak",
        method="POST",
        data="user_id=1",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


def test_upload_path_signal_is_not_automatic_file_upload_proof(monkeypatch) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/upload",
        requested="https://candidate.test/upload",
        status=200,
        source_raw_request=(
            "POST /upload HTTP/1.1\r\nHost: origin.test\r\n"
            "Content-Type: application/json\r\n\r\n{}"
        ),
        source_raw_response=(
            'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n'
            '{"file_url":"/uploads/source.jsp"}'
        ),
        response_body='{"file_url":"/uploads/candidate.jsp"}',
        vuln_type="file_upload",
        method="POST",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


def test_generic_2xx_does_not_prove_the_source_vulnerability(monkeypatch) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe",
        status=200,
        source_raw_request="GET /probe HTTP/1.1\r\n\r\n",
        source_raw_response="",
        response_body="ordinary healthy page",
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result
    assert automatic_verdict_for(
        result,
        source_url="https://origin.test/api",
        source_raw_request="GET /probe HTTP/1.1\r\n\r\n",
        source_raw_response="",
        source_vuln_type="info_leak",
    ) == "pending_validation"


def test_hunter_binds_verification_to_non_origin_successful_http_evidence(
    monkeypatch,
) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=204,
        vuln_type="info_leak",
    )

    proof = result.get("_http_verification_proof")
    assert proof["capture_id"].startswith("capture-204-")
    assert proof["status_code"] == 204
    assert proof["host"] == "candidate.test"
    assert proof["request_shape"] == "GET /probe?id"
    assert proof["signal_keys"] == ["token_exposure"]
    assert proof["source_finding_id"] == "finding"
    assert proof["capture_status"] == "complete"
    assert proof["request_sha256"]
    assert proof["response_sha256"]
    assert automatic_verdict_for(
        result,
        source_url="https://origin.test/api",
        source_raw_request=_SOURCE_RAW_REQUEST,
        source_raw_response=_SOURCE_RAW_RESPONSE,
        source_vuln_type="info_leak",
        source_finding_id="finding",
        evidence_verified=True,
    ) == "killsweep"


def test_redirected_response_does_not_prove_source_endpoint(monkeypatch) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        response_url="https://candidate.test/login",
        status=200,
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


def test_follow_redirects_is_never_automatic_verification(monkeypatch) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        vuln_type="info_leak",
        follow_redirects=True,
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


@pytest.mark.parametrize(
    "source_raw_request",
    [
        (
            "GET https://candidate.test/probe?id=source HTTP/1.1\r\n"
            "Host: stale.test\r\n\r\n"
        ),
        "GET /probe?id=source HTTP/1.1\r\nHost: candidate.test\r\n\r\n",
    ],
)
def test_actual_source_request_authority_is_not_a_second_host(
    monkeypatch, source_raw_request: str,
) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        source_raw_request=source_raw_request,
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


def test_proof_binds_and_validates_the_actual_source_request_authority(
    monkeypatch,
) -> None:
    source_raw_request = (
        "GET https://candidate.test/probe?id=source HTTP/1.1\r\n"
        "Host: stale.test\r\n\r\n"
    )
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://second.test/probe?id=1",
        status=200,
        source_raw_request=source_raw_request,
        vuln_type="info_leak",
    )

    assert result["verified"] is True
    assert result["_http_verification_proof"]["origin_host"] == "candidate.test"
    assert automatic_verdict_for(
        result,
        source_url="https://origin.test/api",
        source_raw_request=source_raw_request,
        source_raw_response=_SOURCE_RAW_RESPONSE,
        source_vuln_type="info_leak",
        source_finding_id="finding",
        evidence_verified=True,
    ) == "killsweep"


def test_equivalent_dns_trailing_dot_is_not_a_second_host(monkeypatch) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://origin.test./probe?id=1",
        status=200,
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


@pytest.mark.parametrize(
    ("origin", "requested"),
    [
        ("https://same.test:8443/api", "https://same.test:9443/probe?id=1"),
        ("https://same.test/api", "https://same.test:9443/probe?id=1"),
        ("https://same.test:8443/api", "https://same.test/probe?id=1"),
    ],
)
def test_same_hostname_on_different_ports_is_not_a_second_host(
    monkeypatch, origin: str, requested: str,
) -> None:
    source_base = origin.rsplit("/api", 1)[0]
    result = _submit_hunter_result(
        monkeypatch,
        origin=origin,
        requested=requested,
        status=200,
        source_raw_request=(
            f"GET {source_base}/probe?id=source HTTP/1.1\r\n\r\n"
        ),
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


def test_signed_same_hostname_cross_port_proof_does_not_pass_validation(
) -> None:
    from app.agents.killsweep import _sign_http_verification

    fields = {
        "version": 1,
        "url": "https://same.test:9443/probe?id=1",
        "host": "same.test:9443",
        "origin_host": "same.test:8443",
        "status_code": 200,
        "capture_id": "legacy-cross-port-capture",
        "request_shape": "GET /probe?id",
        "signal_keys": ["token_exposure"],
        "source_vuln_type": "info_leak",
        "source_finding_id": "finding",
        "capture_status": "complete",
        "request_sha256": "request-sha256",
        "response_sha256": "response-sha256",
    }
    result = {
        "is_killsweep": True,
        "verified": True,
        "verified_url": fields["url"],
        "_http_verification_proof": {
            **fields,
            "signature": _sign_http_verification(fields),
        },
    }

    assert automatic_verdict_for(
        result,
        source_url="https://same.test:8443/api",
        source_raw_request=(
            "GET /probe?id=source HTTP/1.1\r\nHost: same.test:8443\r\n\r\n"
        ),
        source_raw_response=_SOURCE_RAW_RESPONSE,
        source_vuln_type="info_leak",
        source_finding_id="finding",
        evidence_verified=True,
    ) == "pending_validation"


def test_ipv6_host_and_url_are_canonicalized() -> None:
    from app.agents.killsweep import _canonical_http_url, _normalize_host

    assert _normalize_host(
        "2001:0db8:0000:0000:0000:0000:0000:0001"
    ) == "2001:db8::1"
    assert _canonical_http_url(
        "https://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443/probe?id=1"
    ) == "https://[2001:db8::1]:8443/probe?id=1"


@pytest.mark.parametrize(
    ("source_raw_request", "requested"),
    [
        (
            "GET https://192.0.2.1/probe?id=source HTTP/1.1\r\n\r\n",
            "https://[::ffff:192.0.2.1]/probe?id=1",
        ),
        (
            "GET https://[::ffff:192.0.2.1]/probe?id=source HTTP/1.1\r\n\r\n",
            "https://192.0.2.1/probe?id=1",
        ),
    ],
)
def test_ipv4_and_ipv4_mapped_ipv6_are_not_different_hosts(
    monkeypatch, source_raw_request: str, requested: str,
) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://fallback.test/api",
        requested=requested,
        status=200,
        source_raw_request=source_raw_request,
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


def test_signed_ipv4_mapped_ipv6_proof_does_not_pass_validation() -> None:
    from app.agents.killsweep import (
        _canonical_http_url,
        _normalize_host,
        _sign_http_verification,
    )

    verified_url = _canonical_http_url(
        "https://[::ffff:192.0.2.1]/probe?id=1"
    )
    fields = {
        "version": 1,
        "url": verified_url,
        "host": _normalize_host(verified_url),
        "origin_host": "192.0.2.1",
        "status_code": 200,
        "capture_id": "mapped-address-capture",
        "request_shape": "GET /probe?id",
        "signal_keys": ["token_exposure"],
        "source_vuln_type": "info_leak",
        "source_finding_id": "finding",
        "capture_status": "complete",
        "request_sha256": "request-sha256",
        "response_sha256": "response-sha256",
    }
    result = {
        "is_killsweep": True,
        "verified": True,
        "verified_url": verified_url,
        "_http_verification_proof": {
            **fields,
            "signature": _sign_http_verification(fields),
        },
    }

    assert automatic_verdict_for(
        result,
        source_url="https://192.0.2.1/api",
        source_raw_request=(
            "GET /probe?id=source HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n"
        ),
        source_raw_response=_SOURCE_RAW_RESPONSE,
        source_vuln_type="info_leak",
        source_finding_id="finding",
        evidence_verified=True,
    ) == "pending_validation"


def test_equivalent_ipv6_hosts_on_different_ports_are_not_a_second_host(
    monkeypatch,
) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin=(
            "https://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443/api"
        ),
        requested="https://[2001:db8::1]:9443/probe?id=1",
        status=200,
        source_raw_request=(
            "GET https://[2001:0db8:0000:0000:0000:0000:0000:0001]:8443/"
            "probe?id=source HTTP/1.1\r\n\r\n"
        ),
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result


def test_different_ipv6_host_can_produce_and_pass_verification(monkeypatch) -> None:
    origin = "https://[2001:db8::1]:8443/api"
    result = _submit_hunter_result(
        monkeypatch,
        origin=origin,
        requested="https://[2001:db8::2]:9443/probe?id=1",
        status=200,
        source_raw_request=(
            f"GET {origin.rsplit('/api', 1)[0]}/probe?id=source HTTP/1.1\r\n\r\n"
        ),
        vuln_type="info_leak",
    )

    assert result["verified"] is True
    assert result["_http_verification_proof"]["host"] == "[2001:db8::2]:9443"
    assert automatic_verdict_for(
        result,
        source_url=origin,
        source_raw_request=(
            f"GET {origin.rsplit('/api', 1)[0]}/probe?id=source HTTP/1.1\r\n\r\n"
        ),
        source_raw_response=_SOURCE_RAW_RESPONSE,
        source_vuln_type="info_leak",
        source_finding_id="finding",
        evidence_verified=True,
    ) == "killsweep"


def test_finalize_requires_matching_persisted_capture_for_automatic_killsweep(
    tmp_path, monkeypatch,
) -> None:
    signed_result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://candidate.test/probe?id=1",
        status=200,
        vuln_type="info_leak",
    )

    async def scenario() -> None:
        engine, sessions = await _database(tmp_path)
        try:
            async with sessions() as session:
                case, attempt, _ = await queue_initial_attempt(
                    session, task_id="task", finding_id="finding"
                )
                await claim_attempt(session, attempt.id)
                await finalize_attempt(session, attempt.id, result=signed_result)
                await session.commit()
                stored = await session.get(Killsweep, case.id)
                assert stored.automatic_verdict == "pending_validation"
        finally:
            await engine.dispose()

    _run(scenario())


def test_hunter_rejects_same_origin_http_as_killsweep_verification(monkeypatch) -> None:
    result = _submit_hunter_result(
        monkeypatch,
        origin="https://origin.test/api",
        requested="https://origin.test/other",
        status=200,
        source_raw_request="GET /other HTTP/1.1\r\n\r\n",
        vuln_type="info_leak",
    )

    assert result["verified"] is False
    assert "_http_verification_proof" not in result
    assert automatic_verdict_for(
        result,
        source_url="https://origin.test/api",
        source_raw_request="GET /other HTTP/1.1\r\n\r\n",
        source_raw_response=_SOURCE_RAW_RESPONSE,
        source_vuln_type="info_leak",
    ) == "pending_validation"


def test_submit_parameters_cannot_forge_http_verification(monkeypatch) -> None:
    from app.agents.killsweep import KillsweepHunter

    hunter = KillsweepHunter(
        {"target_url": "https://origin.test/api", "title": "IDOR"},
        "fofa-key",
        llm=object(),
    )
    hunter._dispatch(
        "submit_killsweep",
        {
            "is_killsweep": True,
            "verified": True,
            "verified_url": "https://candidate.test/probe",
            "_http_verification_proof": {
                "capture_id": "model-forged",
                "status_code": 200,
                "host": "candidate.test",
                "signature": "model-forged",
            },
        },
    )

    assert automatic_verdict_for(
        hunter._result, source_url="https://origin.test/api"
    ) == "pending_validation"
