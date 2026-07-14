"""Persistent lifecycle operations for killsweep cases and attempts.

This module deliberately does not commit ordinary state transitions. API and
review callers own their transaction, which lets a human pass and its initial
queued attempt become visible atomically.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.killsweep import has_valid_http_verification, product_key
from app.db.models import (
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
from app.raw_evidence import import_capture

AUTOMATIC_VERDICTS = {"pending_validation", "killsweep", "not_killsweep"}
MANUAL_VERDICTS = {"confirmed", "not_killsweep", "invalid"}
REANALYSIS_LIMIT = 40
NEGATIVE_MANUAL_VERDICTS = {"not_killsweep", "invalid"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def append_event(
    session: AsyncSession,
    *,
    case_id: str,
    attempt_id: str | None,
    kind: str,
    summary: str = "",
    payload: Mapping[str, Any] | None = None,
    level: str = "info",
) -> KillsweepEvent:
    case = await session.get(Killsweep, case_id)
    if case is None:
        raise LookupError("killsweep case not found")
    event = KillsweepEvent(
        case_id=case.id,
        attempt_id=attempt_id,
        task_id=case.task_id,
        sequence=0,
        kind=str(kind or "event")[:50],
        level=level if level in {"info", "warn", "error"} else "info",
        summary=str(summary or ""),
        payload=dict(payload or {}),
    )
    session.add(event)
    await session.flush()
    event.sequence = int(event.id)
    await session.flush()
    return event


async def persist_tool_event(
    session: AsyncSession,
    *,
    case_id: str,
    attempt_id: str,
    kind: str,
    summary: str,
    payload: Mapping[str, Any] | None = None,
    capture: Mapping[str, Any] | None = None,
    source_kind: str = "killsweep_tool",
) -> KillsweepEvent:
    event = await append_event(
        session,
        case_id=case_id,
        attempt_id=attempt_id,
        kind=kind,
        summary=summary,
        payload=payload,
        level="warn" if payload and payload.get("ok") is False else "info",
    )
    if capture:
        case = await session.get(Killsweep, case_id)
        await import_capture(
            session,
            capture,
            task_id=case.task_id,
            killsweep_event_id=event.id,
            source_kind=source_kind,
            preview=dict(payload or {}),
        )
    return event


async def queue_initial_attempt(
    session: AsyncSession,
    *,
    task_id: str,
    finding_id: str,
) -> tuple[Killsweep, KillsweepAttempt, bool]:
    finding = await session.get(Finding, finding_id)
    if finding is None or finding.task_id != task_id:
        raise LookupError("finding not found")

    existing = await session.scalar(select(Killsweep).where(
        Killsweep.origin_finding_id == finding_id,
        Killsweep.legacy_without_timeline.is_(False),
    ))
    if existing is not None:
        active = await session.scalar(
            select(KillsweepAttempt)
            .where(
                KillsweepAttempt.case_id == existing.id,
                KillsweepAttempt.status.in_(["queued", "running"]),
            )
            .order_by(KillsweepAttempt.attempt_no.desc())
            .limit(1)
        )
        if active is None:
            latest = await session.scalar(
                select(KillsweepAttempt)
                .where(KillsweepAttempt.case_id == existing.id)
                .order_by(KillsweepAttempt.attempt_no.desc())
                .limit(1)
            )
            if latest is None:
                latest = await _new_attempt(session, existing, trigger="initial")
                return existing, latest, True
            return existing, latest, False
        return existing, active, False

    case = Killsweep(
        task_id=task_id,
        origin_finding_id=finding_id,
        vuln_type=finding.vuln_type,
        vuln_summary=finding.title,
        status="queued",
        automatic_verdict="pending_validation",
        is_killsweep=False,
        queued_at=utcnow(),
        attempt_count=0,
        legacy_without_timeline=False,
    )
    session.add(case)
    await session.flush()
    attempt = await _new_attempt(session, case, trigger="initial")
    await append_event(
        session,
        case_id=case.id,
        attempt_id=attempt.id,
        kind="queued",
        summary="人工复审通过，通杀分析已排队",
        payload={"trigger": "initial", "finding_id": finding_id},
    )
    return case, attempt, True


async def _new_attempt(
    session: AsyncSession,
    case: Killsweep,
    *,
    trigger: str,
    batch_id: str | None = None,
) -> KillsweepAttempt:
    next_number = int(await session.scalar(
        select(func.coalesce(func.max(KillsweepAttempt.attempt_no), 0)).where(
            KillsweepAttempt.case_id == case.id
        )
    ) or 0) + 1
    attempt = KillsweepAttempt(
        case_id=case.id,
        task_id=case.task_id,
        batch_id=batch_id,
        attempt_no=next_number,
        trigger=trigger,
        status="queued",
        automatic_verdict="pending_validation",
    )
    session.add(attempt)
    await session.flush()
    case.status = "queued"
    case.current_attempt_id = attempt.id
    case.queued_at = utcnow()
    case.started_at = None
    case.finished_at = None
    case.failure_kind = ""
    case.failure_message = ""
    case.attempt_count = next_number
    await session.flush()
    return attempt


async def claim_attempt(session: AsyncSession, attempt_id: str) -> KillsweepAttempt | None:
    now = utcnow()
    result = await session.execute(
        update(KillsweepAttempt)
        .where(KillsweepAttempt.id == attempt_id, KillsweepAttempt.status == "queued")
        .values(status="running", started_at=now)
    )
    if result.rowcount != 1:
        return None
    attempt = await session.get(KillsweepAttempt, attempt_id)
    case = await session.get(Killsweep, attempt.case_id)
    case.status = "running"
    case.current_attempt_id = attempt.id
    case.started_at = now
    case.finished_at = None
    await append_event(
        session,
        case_id=case.id,
        attempt_id=attempt.id,
        kind="started",
        summary=f"开始第 {attempt.attempt_no} 次通杀分析",
        payload={"attempt_no": attempt.attempt_no, "trigger": attempt.trigger},
    )
    await session.flush()
    return attempt


async def _has_persisted_verification_evidence(
    session: AsyncSession,
    result: Mapping[str, Any],
    *,
    case: Killsweep,
    attempt: KillsweepAttempt,
) -> bool:
    proof = result.get("_http_verification_proof")
    if not isinstance(proof, Mapping):
        return False
    capture_id = str(proof.get("capture_id") or "")
    if not capture_id:
        return False
    row = (
        await session.execute(
            select(RawEvidence, KillsweepEvent)
            .join(KillsweepEvent, RawEvidence.killsweep_event_id == KillsweepEvent.id)
            .where(
                RawEvidence.id == capture_id,
                RawEvidence.task_id == case.task_id,
                KillsweepEvent.case_id == case.id,
                KillsweepEvent.attempt_id == attempt.id,
            )
        )
    ).first()
    if row is None:
        return False
    evidence, _event = row
    metadata = evidence.metadata_json if isinstance(evidence.metadata_json, Mapping) else {}
    channels = metadata.get("channels") if isinstance(metadata.get("channels"), Mapping) else {}
    request_meta = channels.get("request") if isinstance(channels.get("request"), Mapping) else {}
    response_meta = channels.get("response") if isinstance(channels.get("response"), Mapping) else {}
    if (
        evidence.capture_status != "complete"
        or proof.get("capture_status") != "complete"
        or metadata.get("import_complete") is not True
        or str(request_meta.get("sha256") or "") != str(proof.get("request_sha256") or "")
        or str(response_meta.get("sha256") or "") != str(proof.get("response_sha256") or "")
    ):
        return False

    for channel, channel_meta, proof_hash_key in (
        ("request", request_meta, "request_sha256"),
        ("response", response_meta, "response_sha256"),
    ):
        expected_size = channel_meta.get("size")
        expected_chunks = channel_meta.get("chunks")
        if (
            isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
            or isinstance(expected_chunks, bool)
            or not isinstance(expected_chunks, int)
            or expected_chunks < 1
        ):
            return False

        digest = hashlib.sha256()
        actual_size = 0
        actual_chunks = 0
        rows = await session.stream_scalars(
            select(RawEvidenceChunk)
            .where(
                RawEvidenceChunk.evidence_id == capture_id,
                RawEvidenceChunk.channel == channel,
            )
            .order_by(RawEvidenceChunk.seq.asc())
        )
        async for chunk in rows:
            if chunk.seq != actual_chunks:
                return False
            data = bytes(chunk.data)
            digest.update(data)
            actual_size += len(data)
            actual_chunks += 1

        actual_hash = digest.hexdigest()
        if (
            actual_chunks != expected_chunks
            or actual_size != expected_size
            or actual_hash != str(channel_meta.get("sha256") or "")
            or actual_hash != str(proof.get(proof_hash_key) or "")
        ):
            return False
    return True


def automatic_verdict_for(
    result: Mapping[str, Any],
    *,
    source_url: str = "",
    source_raw_request: str = "",
    source_raw_response: str = "",
    source_vuln_type: str = "",
    source_finding_id: str = "",
    evidence_verified: bool = False,
) -> str:
    if bool(result.get("is_killsweep")):
        if (
            bool(result.get("verified"))
            and str(result.get("verified_url") or "").strip()
            and evidence_verified
            and has_valid_http_verification(
                dict(result),
                source_url=source_url,
                source_raw_request=source_raw_request,
                source_raw_response=source_raw_response,
                source_vuln_type=source_vuln_type,
                source_finding_id=source_finding_id,
            )
        ):
            return "killsweep"
        return "pending_validation"
    return "not_killsweep"


async def finalize_attempt(
    session: AsyncSession,
    attempt_id: str,
    *,
    result: Mapping[str, Any] | None = None,
    error_kind: str = "",
    error_message: str = "",
    cancelled: bool = False,
    provider_trace: list | None = None,
) -> KillsweepAttempt:
    attempt = await session.get(KillsweepAttempt, attempt_id)
    if attempt is None:
        raise LookupError("killsweep attempt not found")
    case = await session.get(Killsweep, attempt.case_id)
    if case is None:
        raise LookupError("killsweep case not found")
    if attempt.status in {"succeeded", "failed", "cancelled"}:
        return attempt

    now = utcnow()
    payload = dict(result or {})
    case_is_current = select(Killsweep.id).where(
        Killsweep.id == case.id,
        Killsweep.current_attempt_id == attempt_id,
    ).exists()
    if error_kind or error_message or cancelled:
        final_status = "cancelled" if cancelled else "failed"
        kind = error_kind or ("cancelled" if cancelled else "unexpected_error")
        message = str(error_message or kind)
        stored_kind = kind[:60]
        allowed_statuses = ["queued", "running"] if cancelled else ["running"]
        claimed = await session.execute(
            update(KillsweepAttempt)
            .where(
                KillsweepAttempt.id == attempt_id,
                KillsweepAttempt.status.in_(allowed_statuses),
                case_is_current,
            )
            .values(
                status=final_status,
                error_kind=stored_kind,
                error_message=message,
                result=payload,
                provider_trace=list(provider_trace or []),
                finished_at=now,
            )
            .execution_options(synchronize_session=False)
        )
        if claimed.rowcount != 1:
            await session.refresh(attempt)
            await session.refresh(case)
            return attempt
        case_update = await session.execute(
            update(Killsweep)
            .where(
                Killsweep.id == case.id,
                Killsweep.current_attempt_id == attempt_id,
            )
            .values(
                status=final_status,
                failure_kind=stored_kind,
                failure_message=message,
                finished_at=now,
                current_attempt_id=None,
            )
            .execution_options(synchronize_session=False)
        )
        if case_update.rowcount != 1:
            raise RuntimeError("killsweep case current attempt changed during finalize")
        await append_event(
            session,
            case_id=case.id,
            attempt_id=attempt.id,
            kind="cancelled" if cancelled else "failed",
            level="warn" if cancelled else "error",
            summary=message,
            payload={"error_kind": stored_kind},
        )
        await session.flush()
        await session.refresh(attempt)
        await session.refresh(case)
        return attempt

    source_finding = await session.get(Finding, case.origin_finding_id)
    source_url = source_finding.target_url if source_finding is not None else ""
    evidence_verified = await _has_persisted_verification_evidence(
        session, payload, case=case, attempt=attempt
    )
    verdict = automatic_verdict_for(
        payload,
        source_url=source_url,
        source_raw_request=source_finding.raw_request if source_finding is not None else "",
        source_raw_response=source_finding.raw_response if source_finding is not None else "",
        source_vuln_type=source_finding.vuln_type if source_finding is not None else "",
        source_finding_id=source_finding.id if source_finding is not None else "",
        evidence_verified=evidence_verified,
    )
    trace = list(provider_trace or payload.get("provider_trace") or [])
    claimed = await session.execute(
        update(KillsweepAttempt)
        .where(
            KillsweepAttempt.id == attempt_id,
            KillsweepAttempt.status == "running",
            case_is_current,
        )
        .values(
            status="succeeded",
            automatic_verdict=verdict,
            result=payload,
            provider_trace=trace,
            error_kind="",
            error_message="",
            finished_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    if claimed.rowcount != 1:
        await session.refresh(attempt)
        await session.refresh(case)
        return attempt

    product_name = str(payload.get("product_name") or "")
    fofa_query = str(payload.get("fofa_query") or "")
    fingerprint = str(payload.get("fingerprint") or "")
    asset_count = int(payload.get("asset_count") or 0)
    edu_count = int(payload.get("edu_count") or 0)
    verified = verdict == "killsweep"
    case_update = await session.execute(
        update(Killsweep)
        .where(
            Killsweep.id == case.id,
            Killsweep.current_attempt_id == attempt_id,
        )
        .values(
            status="succeeded",
            automatic_verdict=verdict,
            is_killsweep=verified,
            product_name=product_name,
            fofa_query=fofa_query,
            fingerprint=fingerprint,
            product_key=product_key(product_name, fofa_query, fingerprint),
            asset_count=asset_count,
            edu_count=edu_count,
            confidence=str(payload.get("confidence") or ""),
            verified_url=str(payload.get("verified_url") or ""),
            verified=verified,
            affected_table=list(payload.get("affected_table") or []),
            notes=str(payload.get("notes") or ""),
            failure_kind="",
            failure_message="",
            finished_at=now,
            current_attempt_id=None,
            latest_success_attempt_id=attempt.id,
        )
        .execution_options(synchronize_session=False)
    )
    if case_update.rowcount != 1:
        raise RuntimeError("killsweep case current attempt changed during finalize")
    await append_event(
        session,
        case_id=case.id,
        attempt_id=attempt.id,
        kind="completed",
        summary={
            "killsweep": "验证成功，自动判定可通杀",
            "pending_validation": "自动判断可能通杀，等待验证或人工评判",
            "not_killsweep": "自动判定不可通杀",
        }[verdict],
        payload={
            "automatic_verdict": verdict,
            "asset_count": asset_count,
            "edu_count": edu_count,
            "verified": verified,
        },
    )
    await session.flush()
    await session.refresh(attempt)
    await session.refresh(case)
    return attempt


async def queue_reanalysis(
    session: AsyncSession,
    case_id: str,
    *,
    trigger: str = "manual",
    batch_id: str | None = None,
) -> KillsweepAttempt:
    case = await session.get(Killsweep, case_id)
    if case is None:
        raise LookupError("killsweep case not found")
    active = await session.scalar(select(KillsweepAttempt.id).where(
        KillsweepAttempt.case_id == case_id,
        KillsweepAttempt.status.in_(["queued", "running"]),
    ).limit(1))
    if active:
        raise RuntimeError("killsweep case already has an active attempt")
    if not (
        case.status == "failed"
        or case.automatic_verdict == "not_killsweep"
        or case.manual_verdict == "invalid"
    ):
        raise ValueError("killsweep case is not eligible for reanalysis")
    attempt = await _new_attempt(
        session, case, trigger=trigger[:30] or "manual", batch_id=batch_id
    )
    await append_event(
        session,
        case_id=case.id,
        attempt_id=attempt.id,
        kind="reanalysis_queued",
        summary=f"第 {attempt.attempt_no} 次分析已排队",
        payload={"trigger": attempt.trigger, "batch_id": batch_id},
    )
    return attempt


async def apply_manual_verdict(
    session: AsyncSession,
    case_id: str,
    *,
    verdict: str,
    reason: str,
    actor: str,
) -> int:
    if verdict not in MANUAL_VERDICTS:
        raise ValueError("invalid manual verdict")
    clean_reason = str(reason or "").strip()
    if verdict in NEGATIVE_MANUAL_VERDICTS and not clean_reason:
        raise ValueError("reason is required for a negative verdict")
    case = await session.get(Killsweep, case_id)
    if case is None:
        raise LookupError("killsweep case not found")
    case.manual_verdict = verdict
    case.manual_reason = clean_reason
    case.manual_actor = str(actor or "full")[:40]
    case.manual_reviewed_at = utcnow()
    cancelled = 0
    if verdict in NEGATIVE_MANUAL_VERDICTS:
        result = await session.execute(
            update(Target)
            .where(Target.killsweep_case_id == case_id, Target.status == "queued")
            .values(
                status="skipped",
                verdict="manual_cancelled",
                dead_reason=f"通杀案例被人工判定为{verdict}，取消尚未开始的派生目标"[:300],
            )
        )
        cancelled = int(result.rowcount or 0)
    await append_event(
        session,
        case_id=case.id,
        attempt_id=None,
        kind="manual_review",
        summary=f"人工结论：{verdict}",
        payload={"verdict": verdict, "reason": clean_reason, "cancelled_targets": cancelled},
    )
    await session.flush()
    return cancelled


def apply_case_filters(stmt, filters: Mapping[str, Any]):
    task_id = str(filters.get("task_id") or "").strip()
    if task_id:
        stmt = stmt.where(Killsweep.task_id == task_id)
    status = str(filters.get("status") or "").strip()
    if status and status != "all":
        if status in AUTOMATIC_VERDICTS:
            stmt = stmt.where(
                Killsweep.status == "succeeded",
                Killsweep.automatic_verdict == status,
            )
        elif status == "invalid":
            stmt = stmt.where(Killsweep.manual_verdict == "invalid")
        else:
            stmt = stmt.where(Killsweep.status == status)
    manual = str(filters.get("manual_verdict") or "").strip()
    if manual and manual != "all":
        stmt = stmt.where(Killsweep.manual_verdict == manual)
    needle = str(filters.get("q") or "").strip()
    if needle:
        pattern = f"%{needle}%"
        stmt = stmt.where(or_(
            Killsweep.product_name.ilike(pattern),
            Killsweep.vuln_summary.ilike(pattern),
            Killsweep.vuln_type.ilike(pattern),
            Killsweep.fofa_query.ilike(pattern),
            Killsweep.fingerprint.ilike(pattern),
            Killsweep.failure_message.ilike(pattern),
            Finding.title.ilike(pattern),
            Task.name.ilike(pattern),
        ))
    return stmt


async def create_reanalysis_batch(
    session: AsyncSession,
    *,
    filters: Mapping[str, Any],
    actor_role: str,
) -> tuple[KillsweepReanalysisBatch, list[KillsweepAttempt]]:
    batch = KillsweepReanalysisBatch(
        filters=dict(filters), actor_role=str(actor_role or "full")[:20]
    )
    session.add(batch)
    await session.flush()

    active_cases = select(KillsweepAttempt.case_id).where(
        KillsweepAttempt.status.in_(["queued", "running"])
    )
    stmt = (
        select(Killsweep)
        .outerjoin(Task, Task.id == Killsweep.task_id)
        .outerjoin(Finding, Finding.id == Killsweep.origin_finding_id)
        .where(
            or_(
                Killsweep.status == "failed",
                Killsweep.automatic_verdict == "not_killsweep",
                Killsweep.manual_verdict == "invalid",
            ),
            Killsweep.id.not_in(active_cases),
        )
    )
    stmt = apply_case_filters(stmt, filters)
    stmt = stmt.order_by(
        func.coalesce(Killsweep.finished_at, Killsweep.created_at).asc(),
        Killsweep.id.asc(),
    ).limit(REANALYSIS_LIMIT)
    cases = (await session.scalars(stmt)).all()
    attempts: list[KillsweepAttempt] = []
    for case in cases:
        attempts.append(await queue_reanalysis(
            session,
            case.id,
            trigger="batch",
            batch_id=batch.id,
        ))
    await session.flush()
    if not attempts:
        await session.delete(batch)
        await session.flush()
    return batch, attempts


async def recover_attempts(
    session: AsyncSession,
    *,
    task_id: str | None = None,
) -> list[str]:
    running_stmt = select(KillsweepAttempt).where(KillsweepAttempt.status == "running")
    if task_id:
        running_stmt = running_stmt.where(KillsweepAttempt.task_id == task_id)
    running = (await session.scalars(running_stmt)).all()
    for attempt in running:
        await finalize_attempt(
            session,
            attempt.id,
            error_kind="process_restart",
            error_message="服务进程重启，运行中的通杀分析已终止",
        )
        event = await append_event(
            session,
            case_id=attempt.case_id,
            attempt_id=attempt.id,
            kind="process_restart",
            level="error",
            summary="进程重启导致本次尝试失败",
            payload={"error_kind": "process_restart"},
        )
    queued_stmt = select(KillsweepAttempt.id).where(KillsweepAttempt.status == "queued")
    if task_id:
        queued_stmt = queued_stmt.where(KillsweepAttempt.task_id == task_id)
    queued_stmt = queued_stmt.order_by(KillsweepAttempt.created_at.asc())
    return list((await session.scalars(queued_stmt)).all())


__all__ = [
    "AUTOMATIC_VERDICTS",
    "MANUAL_VERDICTS",
    "REANALYSIS_LIMIT",
    "NEGATIVE_MANUAL_VERDICTS",
    "append_event",
    "apply_case_filters",
    "apply_manual_verdict",
    "automatic_verdict_for",
    "claim_attempt",
    "create_reanalysis_batch",
    "finalize_attempt",
    "persist_tool_event",
    "queue_initial_attempt",
    "queue_reanalysis",
    "recover_attempts",
]
