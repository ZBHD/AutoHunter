"""Global missed-signal list, evidence, actions, and report drafts."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app import settings_service
from app.db.models import (
    Finding,
    MissedSignal,
    MissedSignalDraft,
    MissedSignalEvent,
    RawEvidence,
    Review,
    Target,
    Task,
    to_cst_iso,
)
from app.db.session import get_session
from app.missed_signal_prompts import (
    build_draft_messages,
    normalize_draft_content,
    parse_draft_response,
)
from app.missed_signals import (
    InvalidSignalTransitionError,
    MissedSignalError,
    SignalNotFoundError,
    SignalValidationError,
    queue_signal_deepening,
    reject_signal,
    restore_signal,
    signal_evidence_filter,
    signal_evidence_query,
)
from app.raw_evidence import stream_evidence_channel
from app.prompt_experiments import recompute_active_prompt_experiment

router = APIRouter(prefix="/api/missed-signals", tags=["missed-signals"])

_STATUS_VALUES = frozenset({"all", "pending", "deepening", "converted", "rejected"})
_TEXT_CHANNELS = frozenset({"request", "response", "stdin", "stdout", "stderr", "command"})
_DRAFT_CHANNEL_LIMIT = 128 * 1024
_DRAFT_TOTAL_LIMIT = 512 * 1024


class RejectRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=10000)

    @field_validator("reason")
    @classmethod
    def reason_not_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("reason cannot be blank")
        return cleaned


class DeepenRequest(BaseModel):
    directive: str = Field(min_length=1, max_length=20000)

    @field_validator("directive")
    @classmethod
    def directive_not_blank(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("directive cannot be blank")
        return cleaned


class DraftPatchRequest(BaseModel):
    revision: int = Field(ge=0)
    content: dict[str, Any]
    missing_evidence: list[str] | None = None


class DraftConfirmRequest(BaseModel):
    revision: int | None = Field(default=None, ge=0)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _raise_domain(exc: MissedSignalError) -> None:
    if isinstance(exc, SignalNotFoundError):
        raise HTTPException(404, str(exc)) from exc
    if isinstance(exc, SignalValidationError):
        raise HTTPException(400, str(exc)) from exc
    if isinstance(exc, InvalidSignalTransitionError):
        raise HTTPException(409, str(exc)) from exc
    raise HTTPException(400, str(exc)) from exc


def _signal_dict(
    signal: MissedSignal,
    *,
    task_name: str = "",
    target_url: str = "",
    target_host: str = "",
) -> dict[str, Any]:
    return {
        "id": signal.id,
        "task_id": signal.task_id,
        "task_name": task_name,
        "target_id": signal.target_id,
        "target_url": target_url,
        "target_host": target_host,
        "source_finding_id": signal.source_finding_id,
        "converted_finding_id": signal.converted_finding_id,
        "rule_key": signal.rule_key,
        "rule_label": signal.rule_label,
        "method": signal.method,
        "endpoint_key": signal.endpoint_key,
        "title": signal.title,
        "summary": signal.summary,
        "risk_level": signal.risk_level,
        "risk_score": signal.risk_score,
        "source_types": signal.source_types or [],
        "status": signal.status,
        "hit_count": signal.hit_count,
        "evidence_count": signal.evidence_count,
        "deepen_count": signal.deepen_count,
        "deepen_phase": signal.deepen_phase,
        "deepen_directive": signal.deepen_directive,
        "deepen_error": signal.deepen_error,
        "last_rejection_reason": signal.last_rejection_reason,
        "rejected_at": to_cst_iso(signal.rejected_at),
        "converted_at": to_cst_iso(signal.converted_at),
        "first_seen_at": to_cst_iso(signal.first_seen_at),
        "last_seen_at": to_cst_iso(signal.last_seen_at),
        "created_at": to_cst_iso(signal.created_at),
        "updated_at": to_cst_iso(signal.updated_at),
    }


def _event_dict(event: MissedSignalEvent) -> dict[str, Any]:
    return {
        "id": event.id,
        "kind": event.kind,
        "actor_role": event.actor_role,
        "from_status": event.from_status,
        "to_status": event.to_status,
        "reason": event.reason,
        "payload": event.payload or {},
        "created_at": to_cst_iso(event.created_at),
    }


def _evidence_dict(evidence: RawEvidence) -> dict[str, Any]:
    metadata = evidence.metadata_json or {}
    channels = metadata.get("channels") if isinstance(metadata, Mapping) else {}
    return {
        "id": evidence.id,
        "task_id": evidence.task_id,
        "target_id": evidence.target_id,
        "source_kind": evidence.source_kind,
        "capture_status": evidence.capture_status,
        "preview": evidence.preview or {},
        "content_hash": evidence.content_hash,
        "occurred_at": to_cst_iso(evidence.occurred_at),
        "created_at": to_cst_iso(evidence.created_at),
        "channels": dict(channels) if isinstance(channels, Mapping) else {},
        "legacy_partial": bool(metadata.get("legacy_partial")) if isinstance(metadata, Mapping) else False,
    }


def _draft_dict(draft: MissedSignalDraft | None) -> dict[str, Any] | None:
    if draft is None:
        return None
    return {
        "id": draft.id,
        "signal_id": draft.signal_id,
        "task_id": draft.task_id,
        "status": draft.status,
        "content": draft.content or {},
        "missing_evidence": draft.missing_evidence or [],
        "provider_trace": draft.provider_trace or [],
        "last_error": draft.last_error,
        "generation_count": draft.generation_count,
        "revision": draft.revision,
        "created_at": to_cst_iso(draft.created_at),
        "updated_at": to_cst_iso(draft.updated_at),
        "confirmed_at": to_cst_iso(draft.confirmed_at),
    }


async def _signal_row(session: AsyncSession, signal_id: str):
    row = (
        await session.execute(
            select(MissedSignal, Task.name, Target.url, Target.host)
            .join(Task, Task.id == MissedSignal.task_id)
            .outerjoin(Target, Target.id == MissedSignal.target_id)
            .where(MissedSignal.id == signal_id)
        )
    ).one_or_none()
    if row is None:
        raise HTTPException(404, "疑似信号不存在")
    return row


async def _signal_response(session: AsyncSession, signal_id: str) -> dict[str, Any]:
    signal, task_name, target_url, target_host = await _signal_row(session, signal_id)
    return _signal_dict(
        signal,
        task_name=task_name or "",
        target_url=target_url or "",
        target_host=target_host or "",
    )


@router.get("/stats")
async def missed_signal_stats(
    task_id: str | None = None,
    session: AsyncSession = Depends(get_session),
):
    query = select(MissedSignal.status, func.count()).group_by(MissedSignal.status)
    if task_id:
        query = query.where(MissedSignal.task_id == task_id)
    counts = {status: int(count) for status, count in (await session.execute(query)).all()}
    return {
        "total": sum(counts.values()),
        "pending": counts.get("pending", 0),
        "deepening": counts.get("deepening", 0),
        "converted": counts.get("converted", 0),
        "rejected": counts.get("rejected", 0),
    }


@router.get("")
async def list_missed_signals(
    status: str = Query("pending"),
    task_id: str | None = None,
    search: str | None = Query(None, alias="q"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    if status not in _STATUS_VALUES:
        raise HTTPException(422, "未知的疑似信号状态")
    filters = []
    if status != "all":
        filters.append(MissedSignal.status == status)
    if task_id:
        filters.append(MissedSignal.task_id == task_id)
    if search and search.strip():
        pattern = f"%{search.strip()}%"
        filters.append(
            or_(
                MissedSignal.title.ilike(pattern),
                MissedSignal.summary.ilike(pattern),
                MissedSignal.endpoint_key.ilike(pattern),
                MissedSignal.rule_label.ilike(pattern),
                Task.name.ilike(pattern),
                Target.url.ilike(pattern),
            )
        )

    base = (
        select(MissedSignal, Task.name, Target.url, Target.host)
        .join(Task, Task.id == MissedSignal.task_id)
        .outerjoin(Target, Target.id == MissedSignal.target_id)
        .where(*filters)
    )
    total = int(await session.scalar(select(func.count()).select_from(base.subquery())) or 0)
    status_order = case(
        (MissedSignal.status == "pending", 0),
        (MissedSignal.status == "deepening", 1),
        (MissedSignal.status == "rejected", 2),
        (MissedSignal.status == "converted", 3),
        else_=4,
    )
    rows = (
        await session.execute(
            base.order_by(
                status_order.asc(),
                MissedSignal.risk_score.desc(),
                MissedSignal.last_seen_at.desc(),
                MissedSignal.id.asc(),
            )
            .offset(offset)
            .limit(limit)
        )
    ).all()
    items = [
        _signal_dict(
            signal,
            task_name=task_name or "",
            target_url=target_url or "",
            target_host=target_host or "",
        )
        for signal, task_name, target_url, target_host in rows
    ]
    return {
        "items": items,
        "total": total,
        "has_more": offset + len(items) < total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/{signal_id}/evidence")
async def list_signal_evidence(
    signal_id: str,
    session: AsyncSession = Depends(get_session),
):
    if await session.get(MissedSignal, signal_id) is None:
        raise HTTPException(404, "疑似信号不存在")
    rows = list(await session.scalars(signal_evidence_query(signal_id)))
    return [_evidence_dict(row) for row in rows]


@router.get("/{signal_id}/evidence/{evidence_id}/content")
async def signal_evidence_content(
    signal_id: str,
    evidence_id: str,
    channel: str = Query(..., min_length=1, max_length=30),
    session: AsyncSession = Depends(get_session),
):
    evidence = (
        await session.scalars(
            select(RawEvidence).where(
                RawEvidence.id == evidence_id,
                signal_evidence_filter(signal_id),
            )
        )
    ).one_or_none()
    if evidence is None:
        raise HTTPException(404, "原始证据不存在")
    channels = (evidence.metadata_json or {}).get("channels") or {}
    if not isinstance(channels, Mapping) or channel not in channels:
        raise HTTPException(404, "原始证据频道不存在")

    async def body():
        async for chunk in stream_evidence_channel(session, evidence_id, channel):
            yield chunk

    media_type = "text/plain; charset=utf-8" if channel in _TEXT_CHANNELS else "application/octet-stream"
    return StreamingResponse(
        body(),
        media_type=media_type,
        headers={"X-Content-Type-Options": "nosniff"},
    )


@router.get("/{signal_id}")
async def missed_signal_detail(
    signal_id: str,
    session: AsyncSession = Depends(get_session),
):
    signal, task_name, target_url, target_host = await _signal_row(session, signal_id)
    events = list(
        await session.scalars(
            select(MissedSignalEvent)
            .where(MissedSignalEvent.signal_id == signal_id)
            .order_by(MissedSignalEvent.created_at.asc(), MissedSignalEvent.id.asc())
        )
    )
    evidence = list(await session.scalars(signal_evidence_query(signal_id)))
    draft = (
        await session.scalars(
            select(MissedSignalDraft).where(MissedSignalDraft.signal_id == signal_id)
        )
    ).one_or_none()
    result = _signal_dict(
        signal,
        task_name=task_name or "",
        target_url=target_url or "",
        target_host=target_host or "",
    )
    result.update(
        {
            "events": [_event_dict(item) for item in events],
            "evidence": [_evidence_dict(item) for item in evidence],
            "draft": _draft_dict(draft),
        }
    )
    return result


@router.post("/{signal_id}/reject")
async def reject_missed_signal(
    signal_id: str,
    request: RejectRequest,
    session: AsyncSession = Depends(get_session),
):
    try:
        await reject_signal(session, signal_id, reason=request.reason, actor_role="full")
        await session.commit()
        await recompute_active_prompt_experiment(session)
    except MissedSignalError as exc:
        await session.rollback()
        _raise_domain(exc)
    return await _signal_response(session, signal_id)


@router.post("/{signal_id}/restore")
async def restore_missed_signal(
    signal_id: str,
    session: AsyncSession = Depends(get_session),
):
    try:
        await restore_signal(session, signal_id, actor_role="full")
        await session.commit()
        await recompute_active_prompt_experiment(session)
    except MissedSignalError as exc:
        await session.rollback()
        _raise_domain(exc)
    return await _signal_response(session, signal_id)


@router.post("/{signal_id}/deepen")
async def deepen_missed_signal(
    signal_id: str,
    request: DeepenRequest,
    session: AsyncSession = Depends(get_session),
):
    try:
        await queue_signal_deepening(
            session,
            signal_id,
            directive=request.directive,
            actor_role="full",
        )
        await session.commit()
    except MissedSignalError as exc:
        await session.rollback()
        _raise_domain(exc)
    return await _signal_response(session, signal_id)


async def _read_channel_for_prompt(
    session: AsyncSession,
    evidence_id: str,
    channel: str,
    remaining: int,
) -> tuple[str, int, bool]:
    kept = bytearray()
    limit = min(_DRAFT_CHANNEL_LIMIT, remaining)
    truncated = False
    async for chunk in stream_evidence_channel(session, evidence_id, channel):
        room = limit - len(kept)
        if room <= 0:
            truncated = True
            break
        kept.extend(chunk[:room])
        if len(chunk) > room:
            truncated = True
            break
    return kept.decode("utf-8", "replace"), len(kept), truncated


async def _draft_evidence_context(
    session: AsyncSession,
    signal: MissedSignal,
) -> list[dict[str, Any]]:
    evidence_rows = list(await session.scalars(signal_evidence_query(signal.id)))
    output: list[dict[str, Any]] = []
    remaining = _DRAFT_TOTAL_LIMIT
    for evidence in evidence_rows:
        item = _evidence_dict(evidence)
        channel_content: dict[str, str] = {}
        truncated_channels: list[str] = []
        for channel in item["channels"]:
            if remaining <= 0:
                truncated_channels.append(channel)
                continue
            text, used, truncated = await _read_channel_for_prompt(
                session, evidence.id, channel, remaining
            )
            remaining -= used
            channel_content[channel] = text
            if truncated:
                truncated_channels.append(channel)
        item["content"] = channel_content
        item["prompt_truncated_channels"] = truncated_channels
        output.append(item)
    return output


def _draft_defaults(signal: MissedSignal, target_url: str) -> dict[str, Any]:
    risk_to_severity = {
        "critical": "严重",
        "high": "高危",
        "medium": "中危",
        "low": "低危",
    }
    endpoint_url = re.sub(r"^[A-Z]+\s+", "", signal.endpoint_key or "")
    return {
        "title": signal.title,
        "vuln_type": signal.rule_key,
        "severity": risk_to_severity.get(signal.risk_level, "中危"),
        "owner": "待确认（现有证据无法确认归属）",
        "target_url": endpoint_url or target_url,
        "description": signal.summary,
        "affected_scope": "待补充",
        "steps": [],
        "poc": "待补充",
        "raw_request": "待补充",
        "raw_response": "待补充",
        "evidence": {},
        "kill_chain": [],
    }


def _draft_llm_for_task(task: Task):
    return settings_service.llm_router_for_task(task)


def _safe_generation_error(exc: Exception, task: Task) -> str:
    text = str(exc or type(exc).__name__)
    try:
        for provider in settings_service.resolve_llm_providers(task):
            if provider.api_key:
                text = text.replace(provider.api_key, "<masked>")
    except Exception:
        pass
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{8,}\b", "sk-<masked>", text)
    return text[:2000]


@router.get("/{signal_id}/draft")
async def get_missed_signal_draft(
    signal_id: str,
    session: AsyncSession = Depends(get_session),
):
    if await session.get(MissedSignal, signal_id) is None:
        raise HTTPException(404, "疑似信号不存在")
    draft = (
        await session.scalars(
            select(MissedSignalDraft).where(MissedSignalDraft.signal_id == signal_id)
        )
    ).one_or_none()
    if draft is None:
        raise HTTPException(404, "报告草稿尚未生成")
    return _draft_dict(draft)


@router.post("/{signal_id}/draft/generate")
async def generate_missed_signal_draft(
    signal_id: str,
    session: AsyncSession = Depends(get_session),
):
    signal, task_name, target_url, target_host = await _signal_row(session, signal_id)
    if signal.status == "converted":
        raise HTTPException(409, "已转报告的信号不能重新生成草稿")
    task = await session.get(Task, signal.task_id)
    assert task is not None
    evidence_context = await _draft_evidence_context(session, signal)
    signal_context = _signal_dict(
        signal,
        task_name=task_name or "",
        target_url=target_url or "",
        target_host=target_host or "",
    )
    draft = (
        await session.scalars(
            select(MissedSignalDraft).where(MissedSignalDraft.signal_id == signal_id)
        )
    ).one_or_none()
    if draft is None:
        draft = MissedSignalDraft(
            signal_id=signal.id,
            task_id=signal.task_id,
            status="generating",
            content={},
            missing_evidence=[],
            provider_trace=[],
            generation_count=0,
            revision=0,
        )
        session.add(draft)
    elif draft.status == "confirmed":
        raise HTTPException(409, "报告草稿已经确认")
    draft.status = "generating"
    draft.generation_count += 1
    draft.last_error = ""
    draft.updated_at = _now()
    await session.commit()

    router_instance = None
    try:
        router_instance = _draft_llm_for_task(task)
        response = await asyncio.to_thread(
            router_instance.chat,
            build_draft_messages(signal_context, evidence_context),
            tools=None,
            tool_choice="none",
            temperature=0.1,
            max_tokens=6000,
        )
        content, missing = parse_draft_response(
            response.content,
            defaults=_draft_defaults(signal, target_url or ""),
        )
    except Exception as exc:
        draft.status = "failed"
        draft.last_error = _safe_generation_error(exc, task)
        draft.provider_trace = list(getattr(router_instance, "enabled_providers", []) or [])
        draft.updated_at = _now()
        await session.commit()
        raise HTTPException(503, "报告草稿生成失败；候选和失败原因已保留，可重试或手工编辑") from exc

    draft.status = "ready"
    draft.content = content
    draft.missing_evidence = missing
    draft.provider_trace = list(getattr(router_instance, "enabled_providers", []) or [])
    draft.last_error = ""
    draft.revision += 1
    draft.updated_at = _now()
    session.add(
        MissedSignalEvent(
            signal_id=signal.id,
            task_id=signal.task_id,
            kind="draft_generated",
            actor_role="system",
            from_status=signal.status,
            to_status=signal.status,
            payload={"revision": draft.revision, "generation_count": draft.generation_count},
        )
    )
    await session.commit()
    return _draft_dict(draft)


@router.patch("/{signal_id}/draft")
async def update_missed_signal_draft(
    signal_id: str,
    request: DraftPatchRequest,
    session: AsyncSession = Depends(get_session),
):
    draft = (
        await session.scalars(
            select(MissedSignalDraft).where(MissedSignalDraft.signal_id == signal_id)
        )
    ).one_or_none()
    if draft is None:
        raise HTTPException(404, "报告草稿尚未生成")
    if draft.status == "confirmed":
        raise HTTPException(409, "已确认的报告草稿不能修改")
    content, inferred_missing = normalize_draft_content(request.content)
    missing = request.missing_evidence if request.missing_evidence is not None else inferred_missing
    result = await session.execute(
        update(MissedSignalDraft)
        .where(
            MissedSignalDraft.id == draft.id,
            MissedSignalDraft.revision == request.revision,
            MissedSignalDraft.status != "confirmed",
        )
        .values(
            content=content,
            missing_evidence=list(dict.fromkeys(str(item).strip() for item in missing if str(item).strip())),
            status="ready",
            revision=MissedSignalDraft.revision + 1,
            updated_at=_now(),
        )
        .execution_options(synchronize_session=False)
    )
    if result.rowcount != 1:
        await session.rollback()
        raise HTTPException(409, "草稿已被其他编辑覆盖，请刷新后重试")
    await session.commit()
    refreshed = (
        await session.scalars(
            select(MissedSignalDraft)
            .where(MissedSignalDraft.id == draft.id)
            .execution_options(populate_existing=True)
        )
    ).one()
    return _draft_dict(refreshed)


def _confirmed_content(content: Mapping[str, Any]) -> dict[str, Any]:
    normalized, missing = normalize_draft_content(content)
    required = ("title", "vuln_type", "owner", "target_url", "description")
    absent = [field for field in required if not normalized.get(field)]
    if absent:
        raise SignalValidationError(f"草稿缺少必要字段: {', '.join(absent)}")
    if not normalized["owner"].strip():
        raise SignalValidationError("owner 不能为空")
    normalized["missing_evidence"] = missing
    return normalized


@router.post("/{signal_id}/draft/confirm")
async def confirm_missed_signal_draft(
    signal_id: str,
    request: DraftConfirmRequest | None = None,
    session: AsyncSession = Depends(get_session),
):
    signal = await session.get(MissedSignal, signal_id)
    if signal is None:
        raise HTTPException(404, "疑似信号不存在")
    draft = (
        await session.scalars(
            select(MissedSignalDraft).where(MissedSignalDraft.signal_id == signal_id)
        )
    ).one_or_none()
    if signal.converted_finding_id or (draft is not None and draft.status == "confirmed"):
        finding_id = signal.converted_finding_id
        if not finding_id and draft is not None:
            finding_id = signal.converted_finding_id
        return {"ok": True, "finding_id": finding_id, "already_confirmed": True}
    if draft is None:
        raise HTTPException(404, "报告草稿尚未生成")
    if draft.status != "ready":
        raise HTTPException(409, "只有已就绪草稿可以确认")
    if request is not None and request.revision is not None and request.revision != draft.revision:
        raise HTTPException(409, "草稿版本已变化，请刷新后确认")
    if not signal.target_id or await session.get(Target, signal.target_id) is None:
        raise HTTPException(409, "该疑似信号没有可关联的目标，暂不能转为报告")
    try:
        content = _confirmed_content(draft.content or {})
    except MissedSignalError as exc:
        _raise_domain(exc)

    severity = content["severity"]
    finding = Finding(
        task_id=signal.task_id,
        target_id=signal.target_id,
        worker_id="missed_signal",
        vuln_type=content["vuln_type"],
        title=content["title"],
        severity_claimed=severity,
        target_url=content["target_url"],
        owner=content["owner"],
        description=content["description"],
        steps=content["steps"],
        poc=content["poc"],
        raw_request=content["raw_request"],
        raw_response=content["raw_response"],
        evidence=content["evidence"],
        affected_scope=content["affected_scope"],
        kill_chain=content["kill_chain"],
        self_check={},
        dedup_key="",
        status="reviewed",
    )
    session.add(finding)
    await session.flush()
    review = Review(
        finding_id=finding.id,
        task_id=signal.task_id,
        verdict="accepted",
        confidence="uncertain",
        severity_final=severity,
        score=max(0.0, min(float(signal.risk_score or 0), 10.0)),
        in_scope=True,
        is_duplicate=False,
        ignore_reasons=[],
        downgrade_reasons=[],
        reproduced=False,
        reviewer_notes="由疑似信号草稿人工确认，进入人工复审队列。",
        deepen_directive="",
        user_status="pending",
        user_severity=None,
        user_notes="",
        user_edits={},
        submitted=False,
    )
    session.add(review)
    previous = signal.status
    now = _now()
    signal.status = "converted"
    signal.converted_finding_id = finding.id
    signal.converted_at = now
    signal.updated_at = now
    draft.status = "confirmed"
    draft.confirmed_at = now
    draft.updated_at = now
    draft.revision += 1
    session.add(
        MissedSignalEvent(
            signal_id=signal.id,
            task_id=signal.task_id,
            kind="converted",
            actor_role="full",
            from_status=previous,
            to_status="converted",
            reason="人工确认报告草稿",
            payload={"finding_id": finding.id, "draft_id": draft.id},
        )
    )
    await session.commit()
    await recompute_active_prompt_experiment(session)
    return {"ok": True, "finding_id": finding.id, "already_confirmed": False}


__all__ = ["router"]
