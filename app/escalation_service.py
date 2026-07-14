"""Persistent queue and budget accounting for post-review deep hunting."""
from __future__ import annotations

import os
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.depth_policy import depth_policy_for, normalize_severity
from app.db.models import EscalationAttempt, Finding, Task


MAX_TASK_ATTEMPTS = int(os.environ.get("ESCALATE_TASK_MAX_ATTEMPTS", "100"))
MAX_TASK_ROUNDS = int(os.environ.get("ESCALATE_TASK_ROUND_BUDGET", "1000"))


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def round_budget_for(severity: str | None) -> int:
    override = int(os.environ.get("ESCALATE_MAX_ROUNDS", "0"))
    return override if override > 0 else depth_policy_for(severity).escalation_rounds


async def queue_attempt(
    session: AsyncSession,
    *,
    task_id: str,
    finding_id: str,
    orig_severity: str,
) -> tuple[EscalationAttempt, bool]:
    """Create one durable attempt per Finding inside the caller transaction."""
    existing = await session.scalar(
        select(EscalationAttempt).where(EscalationAttempt.finding_id == finding_id)
    )
    if existing is not None:
        return existing, False

    finding = await session.get(Finding, finding_id)
    if finding is None or finding.task_id != task_id:
        raise LookupError("finding not found")

    attempt_count, used_rounds = (
        await session.execute(
            select(func.count(EscalationAttempt.id), func.coalesce(func.sum(EscalationAttempt.round_budget), 0))
            .where(
                EscalationAttempt.task_id == task_id,
                EscalationAttempt.round_budget > 0,
            )
        )
    ).one()
    planned_rounds = round_budget_for(orig_severity)
    exhausted = (
        (MAX_TASK_ATTEMPTS > 0 and int(attempt_count or 0) >= MAX_TASK_ATTEMPTS)
        or (MAX_TASK_ROUNDS > 0 and int(used_rounds or 0) + planned_rounds > MAX_TASK_ROUNDS)
    )
    attempt = EscalationAttempt(
        task_id=task_id,
        finding_id=finding_id,
        orig_severity=normalize_severity(orig_severity),
        round_budget=0 if exhausted else planned_rounds,
        status="skipped" if exhausted else "queued",
        error_kind="budget_exhausted" if exhausted else "",
        error_message=(
            f"任务扩大危害预算已用尽（尝试 {int(attempt_count or 0)}/{MAX_TASK_ATTEMPTS or '不限'}，"
            f"轮数 {int(used_rounds or 0)}/{MAX_TASK_ROUNDS or '不限'}）"
            if exhausted else ""
        ),
        finished_at=_now() if exhausted else None,
    )
    session.add(attempt)
    await session.flush()
    return attempt, True


async def claim_attempt(session: AsyncSession, attempt_id: str) -> bool:
    result = await session.execute(
        update(EscalationAttempt)
        .where(
            EscalationAttempt.id == attempt_id,
            EscalationAttempt.status == "queued",
            EscalationAttempt.task_id.in_(
                select(Task.id).where(Task.status.in_(["running", "idle"]))
            ),
        )
        .values(
            status="running",
            started_at=_now(),
            finished_at=None,
            error_kind="",
            error_message="",
        )
    )
    await session.flush()
    return bool(result.rowcount == 1)


async def finalize_attempt(
    session: AsyncSession,
    attempt_id: str,
    *,
    status: str,
    result: dict | None = None,
    error_kind: str = "",
    error_message: str = "",
) -> EscalationAttempt | None:
    if status not in {"succeeded", "skipped", "failed"}:
        raise ValueError("invalid escalation attempt status")
    attempt = await session.get(EscalationAttempt, attempt_id)
    if attempt is None:
        return None
    attempt.status = status
    attempt.result = dict(result or {})
    attempt.error_kind = error_kind[:60]
    attempt.error_message = error_message[:1000]
    attempt.finished_at = _now()
    await session.flush()
    return attempt


async def requeue_attempt(
    session: AsyncSession,
    attempt_id: str,
    *,
    error_kind: str,
    error_message: str,
) -> EscalationAttempt | None:
    attempt = await session.get(EscalationAttempt, attempt_id)
    if attempt is None or attempt.status not in {"running", "queued"}:
        return attempt
    attempt.status = "queued"
    attempt.started_at = None
    attempt.finished_at = None
    attempt.error_kind = error_kind[:60]
    attempt.error_message = error_message[:1000]
    await session.flush()
    return attempt


async def recover_attempts(
    session: AsyncSession,
    *,
    task_id: str | None = None,
) -> list[str]:
    running_stmt = select(EscalationAttempt).where(EscalationAttempt.status == "running")
    if task_id:
        running_stmt = running_stmt.where(EscalationAttempt.task_id == task_id)
    for attempt in (await session.scalars(running_stmt)).all():
        await requeue_attempt(
            session,
            attempt.id,
            error_kind="process_restart",
            error_message="服务进程重启，扩大危害尝试已重新排队",
        )
    queued_stmt = select(EscalationAttempt.id).where(EscalationAttempt.status == "queued")
    if task_id:
        queued_stmt = queued_stmt.where(EscalationAttempt.task_id == task_id)
    queued_stmt = queued_stmt.order_by(EscalationAttempt.created_at.asc())
    return list((await session.scalars(queued_stmt)).all())


__all__ = [
    "MAX_TASK_ATTEMPTS",
    "MAX_TASK_ROUNDS",
    "claim_attempt",
    "finalize_attempt",
    "queue_attempt",
    "recover_attempts",
    "requeue_attempt",
    "round_budget_for",
]
