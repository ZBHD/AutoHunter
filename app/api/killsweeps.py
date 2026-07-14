"""Global killsweep operations APIs."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import case as sql_case
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding,
    Killsweep,
    KillsweepAttempt,
    KillsweepEvent,
    RawEvidence,
    Task,
    to_cst_iso,
)
from app.db.session import get_session
from app.killsweep_service import (
    MANUAL_VERDICTS,
    REANALYSIS_LIMIT,
    apply_case_filters,
    apply_manual_verdict,
    create_reanalysis_batch,
    queue_reanalysis,
)
from app.orchestrator import manager
from app.raw_evidence import stream_evidence_channel
from app.security import resolve_role, token_from_headers

router = APIRouter(prefix="/api/killsweeps", tags=["killsweeps"])


class ManualReviewRequest(BaseModel):
    verdict: str
    reason: str = ""


class ReanalysisBatchRequest(BaseModel):
    filters: dict[str, Any] = Field(default_factory=dict)


def _case_fields(k: Killsweep, task_name: str = "", origin_title: str = "") -> dict:
    return {
        "id": k.id,
        "task_id": k.task_id,
        "task_name": task_name,
        "origin_finding_id": k.origin_finding_id,
        "origin_title": origin_title or k.vuln_summary,
        "product_key": k.product_key,
        "product_name": k.product_name,
        "vuln_type": k.vuln_type,
        "vuln_summary": k.vuln_summary,
        "fofa_query": k.fofa_query,
        "fingerprint": k.fingerprint,
        "asset_count": k.asset_count,
        "edu_count": k.edu_count,
        "is_killsweep": k.is_killsweep,
        "confidence": k.confidence,
        "verified_url": k.verified_url,
        "verified": k.verified,
        "status": k.status,
        "automatic_verdict": k.automatic_verdict,
        "manual_verdict": k.manual_verdict,
        "manual_reason": k.manual_reason,
        "manual_actor": k.manual_actor,
        "manual_reviewed_at": to_cst_iso(k.manual_reviewed_at),
        "failure_kind": k.failure_kind,
        "failure_message": k.failure_message,
        "attempt_count": k.attempt_count,
        "queued_at": to_cst_iso(k.queued_at),
        "started_at": to_cst_iso(k.started_at),
        "finished_at": to_cst_iso(k.finished_at),
        "legacy_without_timeline": k.legacy_without_timeline,
        "created_at": to_cst_iso(k.created_at),
        "updated_at": to_cst_iso(k.updated_at),
    }


def _attempt_fields(attempt: KillsweepAttempt) -> dict:
    return {
        "id": attempt.id,
        "case_id": attempt.case_id,
        "task_id": attempt.task_id,
        "batch_id": attempt.batch_id,
        "attempt_no": attempt.attempt_no,
        "trigger": attempt.trigger,
        "status": attempt.status,
        "automatic_verdict": attempt.automatic_verdict,
        "result": attempt.result or {},
        "provider_trace": attempt.provider_trace or [],
        "error_kind": attempt.error_kind,
        "error_message": attempt.error_message,
        "created_at": to_cst_iso(attempt.created_at),
        "started_at": to_cst_iso(attempt.started_at),
        "finished_at": to_cst_iso(attempt.finished_at),
    }


def _filter_cases(stmt, *, task_id: str | None, status: str | None,
                  manual_verdict: str | None, q: str | None):
    return apply_case_filters(stmt, {
        "task_id": task_id,
        "status": status,
        "manual_verdict": manual_verdict,
        "q": q,
    })


@router.get("/stats")
async def killsweep_stats(
    task_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    base = select(Killsweep)
    if task_id:
        base = base.where(Killsweep.task_id == task_id)
    subquery = base.subquery()

    async def count_where(*conditions) -> int:
        return int(await session.scalar(
            select(func.count()).select_from(subquery).where(*conditions)
        ) or 0)

    return {
        "total": await count_where(),
        "queued": await count_where(subquery.c.status == "queued"),
        "running": await count_where(subquery.c.status == "running"),
        "pending_validation": await count_where(
            subquery.c.status == "succeeded",
            subquery.c.automatic_verdict == "pending_validation",
        ),
        "killsweep": await count_where(
            subquery.c.status == "succeeded",
            subquery.c.automatic_verdict == "killsweep",
        ),
        "not_killsweep": await count_where(
            subquery.c.status == "succeeded",
            subquery.c.automatic_verdict == "not_killsweep",
        ),
        "failed": await count_where(subquery.c.status == "failed"),
        "cancelled": await count_where(subquery.c.status == "cancelled"),
        "invalid": await count_where(subquery.c.manual_verdict == "invalid"),
    }


@router.get("")
async def list_killsweeps(
    task_id: str | None = Query(None),
    status: str | None = Query(None),
    manual_verdict: str | None = Query(None),
    q: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    stmt = (
        select(Killsweep, Task.name, Finding.title)
        .outerjoin(Task, Task.id == Killsweep.task_id)
        .outerjoin(Finding, Finding.id == Killsweep.origin_finding_id)
    )
    stmt = _filter_cases(
        stmt,
        task_id=task_id,
        status=status,
        manual_verdict=manual_verdict,
        q=q,
    )
    total = int(await session.scalar(
        select(func.count()).select_from(stmt.order_by(None).subquery())
    ) or 0)
    priority = sql_case(
        (Killsweep.status == "failed", 0),
        (Killsweep.status == "running", 1),
        (Killsweep.status == "queued", 2),
        else_=3,
    )
    rows = (await session.execute(
        stmt.order_by(
            priority.asc(),
            sql_case(
                (Killsweep.status == "failed", Killsweep.finished_at),
                else_=None,
            ).asc().nulls_last(),
            Killsweep.updated_at.desc(),
        ).offset(offset).limit(limit)
    )).all()
    items = [_case_fields(item, task_name or "", origin_title or "")
             for item, task_name, origin_title in rows]
    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < total,
    }


@router.post("/reanalysis-batches")
async def reanalysis_batch(
    req: ReanalysisBatchRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    role = resolve_role(token_from_headers(request.headers)) or "full"
    try:
        batch, attempts = await create_reanalysis_batch(
            session, filters=req.filters, actor_role=role
        )
    except (ValueError, RuntimeError) as exc:
        await session.rollback()
        raise HTTPException(409, str(exc)) from exc
    await session.commit()
    for attempt in attempts:
        await manager.dispatch_killsweep_attempt(attempt.task_id, attempt.id)
    return {
        "batch_id": batch.id,
        "selected_count": len(attempts),
        "case_ids": [attempt.case_id for attempt in attempts],
        "attempt_ids": [attempt.id for attempt in attempts],
        "max_count": REANALYSIS_LIMIT,
    }


async def _case_row(session: AsyncSession, case_id: str):
    return (await session.execute(
        select(Killsweep, Task.name, Finding.title)
        .outerjoin(Task, Task.id == Killsweep.task_id)
        .outerjoin(Finding, Finding.id == Killsweep.origin_finding_id)
        .where(Killsweep.id == case_id)
    )).first()


@router.get("/{case_id}")
async def get_killsweep(case_id: str, session: AsyncSession = Depends(get_session)):
    row = await _case_row(session, case_id)
    if row is None:
        raise HTTPException(404, "通杀案例不存在")
    item, task_name, origin_title = row
    payload = _case_fields(item, task_name or "", origin_title or "")
    payload["affected_table"] = item.affected_table or []
    payload["notes"] = item.notes
    attempts = (await session.scalars(
        select(KillsweepAttempt)
        .where(KillsweepAttempt.case_id == case_id)
        .order_by(KillsweepAttempt.attempt_no.asc())
    )).all()
    payload["attempts"] = [_attempt_fields(attempt) for attempt in attempts]
    return payload


@router.get("/{case_id}/events")
async def list_killsweep_events(
    case_id: str,
    attempt_id: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
):
    if await session.get(Killsweep, case_id) is None:
        raise HTTPException(404, "通杀案例不存在")
    stmt = select(KillsweepEvent).where(KillsweepEvent.case_id == case_id)
    if attempt_id:
        stmt = stmt.where(KillsweepEvent.attempt_id == attempt_id)
    events = (await session.scalars(stmt.order_by(
        KillsweepEvent.sequence.asc(), KillsweepEvent.id.asc()
    ))).all()
    evidence_rows = []
    if events:
        evidence_rows = (await session.scalars(
            select(RawEvidence)
            .where(RawEvidence.killsweep_event_id.in_([event.id for event in events]))
            .order_by(RawEvidence.created_at.asc())
        )).all()
    by_event: dict[int, list[dict]] = {}
    for evidence in evidence_rows:
        metadata = evidence.metadata_json or {}
        by_event.setdefault(evidence.killsweep_event_id, []).append({
            "id": evidence.id,
            "source_kind": evidence.source_kind,
            "capture_status": evidence.capture_status,
            "preview": evidence.preview or {},
            "metadata_json": metadata,
            "content_hash": evidence.content_hash,
            "channels": list((metadata.get("channels") or {}).keys()),
            "occurred_at": to_cst_iso(evidence.occurred_at),
            "created_at": to_cst_iso(evidence.created_at),
        })
    return {"items": [{
        "id": event.id,
        "case_id": event.case_id,
        "attempt_id": event.attempt_id,
        "sequence": event.sequence,
        "kind": event.kind,
        "level": event.level,
        "summary": event.summary,
        "payload": event.payload or {},
        "created_at": to_cst_iso(event.created_at),
        "evidence": by_event.get(event.id, []),
    } for event in events]}


@router.get("/{case_id}/events/{event_id}/evidence/{evidence_id}/content")
async def get_evidence_content(
    case_id: str,
    event_id: int,
    evidence_id: str,
    channel: str = Query(..., min_length=1, max_length=80),
    session: AsyncSession = Depends(get_session),
):
    event = await session.get(KillsweepEvent, event_id)
    evidence = await session.get(RawEvidence, evidence_id)
    if (
        event is None
        or event.case_id != case_id
        or evidence is None
        or evidence.killsweep_event_id != event_id
    ):
        raise HTTPException(404, "原始证据不存在")
    channels = (evidence.metadata_json or {}).get("channels") or {}
    if channel not in channels:
        raise HTTPException(404, "原始证据频道不存在")
    return StreamingResponse(
        stream_evidence_channel(session, evidence_id, channel),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'inline; filename="{evidence_id}-{channel}.bin"',
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/{case_id}/manual-review")
async def manual_review(
    case_id: str,
    req: ManualReviewRequest,
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    if req.verdict not in MANUAL_VERDICTS:
        raise HTTPException(400, "人工结论非法")
    role = resolve_role(token_from_headers(request.headers)) or "full"
    try:
        cancelled = await apply_manual_verdict(
            session,
            case_id,
            verdict=req.verdict,
            reason=req.reason,
            actor=role,
        )
    except LookupError as exc:
        raise HTTPException(404, "通杀案例不存在") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    await session.commit()
    row = await _case_row(session, case_id)
    item, task_name, origin_title = row
    payload = _case_fields(item, task_name or "", origin_title or "")
    payload["cancelled_targets"] = cancelled
    return payload


@router.post("/{case_id}/reanalyze")
async def reanalyze(case_id: str, session: AsyncSession = Depends(get_session)):
    try:
        attempt = await queue_reanalysis(session, case_id)
    except LookupError as exc:
        raise HTTPException(404, "通杀案例不存在") from exc
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(409, str(exc)) from exc
    await session.commit()
    await manager.dispatch_killsweep_attempt(attempt.task_id, attempt.id)
    return {
        "queued": True,
        "case_id": attempt.case_id,
        "attempt_id": attempt.id,
        "attempt_no": attempt.attempt_no,
    }


__all__ = ["router"]
