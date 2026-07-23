"""LiteLLM Gateway 资产、Observation 与 Secret API。"""
from __future__ import annotations

import csv
import io
import json
from collections.abc import AsyncIterator, Iterable
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import GatewayAsset, GatewayObservation, GatewaySecret
from app.db.session import get_session
from app.security import resolve_role, token_from_headers


router = APIRouter()


def _role(request: Request) -> str:
    role = resolve_role(token_from_headers(request.headers))
    if role is None:
        raise HTTPException(status_code=401, detail="需要 AutoHunter 访问令牌")
    return role


def _require_read(role: str = Depends(_role)) -> str:
    if role not in {"full", "readonly"}:
        raise HTTPException(status_code=403, detail="观摩令牌不允许访问网关敏感信息")
    return role


def _require_full(role: str = Depends(_role)) -> str:
    if role != "full":
        raise HTTPException(status_code=403, detail="仅完整权限可执行网关复查")
    return role


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _asset_item(asset: GatewayAsset, *, secret_count: int = 0) -> dict[str, object]:
    return {
        "id": asset.id,
        "task_id": asset.task_id,
        "target_id": asset.target_id,
        "url": asset.canonical_base_url,
        "origin_key": asset.origin_key,
        "profile_id": asset.profile_id,
        "profile_version": asset.profile_version,
        "fingerprint_status": asset.fingerprint_status,
        "fingerprint_confidence": asset.fingerprint_confidence,
        "auth_state": asset.auth_state,
        "model_names": list(asset.model_names or []),
        "model_count": asset.model_count,
        "scan_state": asset.scan_state,
        "scan_epoch": asset.scan_epoch,
        "last_scanned_at": _iso(asset.last_scanned_at),
        "next_scan_at": _iso(asset.next_scan_at),
        "secret_count": secret_count,
    }


def _secret_item(secret: GatewaySecret) -> dict[str, object]:
    return {
        "id": secret.id,
        "gateway_asset_id": secret.gateway_asset_id,
        "secret_type": secret.secret_type,
        "provider": secret.provider,
        "secret_name": secret.secret_name,
        "secret_value": secret.secret_value,
        "secret_sha256": secret.secret_sha256,
        "source_url": secret.source_url,
        "source_location": secret.source_location,
        "source_context": secret.source_context,
        "validation_status": secret.validation_status,
        "validated_models": list(secret.validated_models or []),
        "first_seen_at": _iso(secret.first_seen_at),
        "last_seen_at": _iso(secret.last_seen_at),
        "last_validated_at": _iso(secret.last_validated_at),
    }


async def _task_asset(
    task_id: str,
    asset_id: str,
    session: AsyncSession,
) -> GatewayAsset:
    asset = await session.scalar(
        select(GatewayAsset).where(
            GatewayAsset.id == asset_id,
            GatewayAsset.task_id == task_id,
        )
    )
    if asset is None:
        raise HTTPException(status_code=404, detail="Gateway 资产不存在")
    return asset


@router.get("/api/tasks/{task_id}/gateway/summary")
async def gateway_summary(
    task_id: str,
    _role_name: str = Depends(_require_read),
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    asset_count = await session.scalar(
        select(func.count()).select_from(GatewayAsset).where(GatewayAsset.task_id == task_id)
    )
    confirmed_count = await session.scalar(
        select(func.count()).select_from(GatewayAsset).where(
            GatewayAsset.task_id == task_id,
            GatewayAsset.fingerprint_status == "confirmed",
        )
    )
    secret_count = await session.scalar(
        select(func.count()).select_from(GatewaySecret).where(GatewaySecret.task_id == task_id)
    )
    valid_secret_count = await session.scalar(
        select(func.count()).select_from(GatewaySecret).where(
            GatewaySecret.task_id == task_id,
            GatewaySecret.validation_status == "valid",
        )
    )
    anonymous_inference_count = await session.scalar(
        select(func.count()).select_from(GatewayObservation).where(
            GatewayObservation.task_id == task_id,
            GatewayObservation.result == "anonymous_inference",
        )
    )
    return {
        "task_id": task_id,
        "asset_count": int(asset_count or 0),
        "confirmed_asset_count": int(confirmed_count or 0),
        "secret_count": int(secret_count or 0),
        "valid_secret_count": int(valid_secret_count or 0),
        "anonymous_inference_count": int(anonymous_inference_count or 0),
    }


@router.get("/api/tasks/{task_id}/gateway/assets")
async def gateway_assets(
    task_id: str,
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _role_name: str = Depends(_require_read),
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    query = select(GatewayAsset).where(GatewayAsset.task_id == task_id)
    if q.strip():
        needle = f"%{q.strip()}%"
        query = query.where(
            or_(
                GatewayAsset.canonical_base_url.ilike(needle),
                GatewayAsset.origin_key.ilike(needle),
                GatewayAsset.profile_id.ilike(needle),
                GatewayAsset.auth_state.ilike(needle),
            )
        )
    total = await session.scalar(
        select(func.count()).select_from(query.subquery())
    )
    assets = list(
        await session.scalars(
            query.order_by(GatewayAsset.updated_at.desc()).offset(offset).limit(limit)
        )
    )
    items: list[dict[str, object]] = []
    for asset in assets:
        secret_count = await session.scalar(
            select(func.count()).select_from(GatewaySecret).where(
                GatewaySecret.gateway_asset_id == asset.id
            )
        )
        items.append(_asset_item(asset, secret_count=int(secret_count or 0)))
    return {
        "items": items,
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < int(total or 0),
    }


@router.get("/api/tasks/{task_id}/gateway/secrets")
async def gateway_secrets(
    task_id: str,
    q: str = Query(default="", max_length=200),
    status: str = Query(default="", max_length=30),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _role_name: str = Depends(_require_read),
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    query = select(GatewaySecret).where(GatewaySecret.task_id == task_id)
    if status.strip():
        query = query.where(GatewaySecret.validation_status == status.strip())
    if q.strip():
        needle = f"%{q.strip()}%"
        query = query.where(
            or_(
                GatewaySecret.secret_name.ilike(needle),
                GatewaySecret.provider.ilike(needle),
                GatewaySecret.secret_type.ilike(needle),
                GatewaySecret.source_url.ilike(needle),
            )
        )
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    secrets = list(
        await session.scalars(
            query.order_by(GatewaySecret.last_seen_at.desc()).offset(offset).limit(limit)
        )
    )
    return {
        "items": [_secret_item(secret) for secret in secrets],
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(secrets) < int(total or 0),
    }


async def _export_rows(session: AsyncSession, task_id: str) -> list[dict[str, object]]:
    secrets = list(
        await session.scalars(
            select(GatewaySecret).where(GatewaySecret.task_id == task_id).order_by(
                GatewaySecret.last_seen_at.desc()
            )
        )
    )
    return [_secret_item(secret) for secret in secrets]


@router.get("/api/tasks/{task_id}/gateway/secrets/export")
async def gateway_secrets_export(
    task_id: str,
    format: str = Query(default="json", pattern="^(json|csv)$"),
    _role_name: str = Depends(_require_read),
    session: AsyncSession = Depends(get_session),
) -> StreamingResponse:
    rows = await _export_rows(session, task_id)
    if format == "csv":
        buffer = io.StringIO()
        writer = csv.DictWriter(buffer, fieldnames=list(rows[0]) if rows else ["id"])
        writer.writeheader()
        writer.writerows(rows)
        payload = buffer.getvalue()
        media_type = "text/csv; charset=utf-8"
    else:
        payload = json.dumps(rows, ensure_ascii=False, default=str)
        media_type = "application/json"

    async def stream() -> AsyncIterator[str]:
        yield payload

    return StreamingResponse(
        stream(),
        media_type=media_type,
        headers={"Cache-Control": "no-store"},
    )


@router.get("/api/gateway/assets/{asset_id}")
async def gateway_asset_detail(
    asset_id: str,
    _role_name: str = Depends(_require_read),
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    asset = await session.get(GatewayAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Gateway 资产不存在")
    secret_count = await session.scalar(
        select(func.count()).select_from(GatewaySecret).where(
            GatewaySecret.gateway_asset_id == asset.id
        )
    )
    return _asset_item(asset, secret_count=int(secret_count or 0))


@router.get("/api/gateway/assets/{asset_id}/observations")
async def gateway_asset_observations(
    asset_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _role_name: str = Depends(_require_read),
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    query = select(GatewayObservation).where(
        GatewayObservation.gateway_asset_id == asset_id
    )
    total = await session.scalar(select(func.count()).select_from(query.subquery()))
    rows = list(
        await session.scalars(
            query.order_by(GatewayObservation.observed_at.desc()).offset(offset).limit(limit)
        )
    )
    items = [
        {
            "id": row.id,
            "scan_epoch": row.scan_epoch,
            "stage": row.stage,
            "probe_id": row.probe_id,
            "auth_variant": row.auth_variant,
            "result": row.result,
            "status_code": row.status_code,
            "content_type": row.content_type,
            "evidence_id": row.evidence_id,
            "observed_at": _iso(row.observed_at),
        }
        for row in rows
    ]
    return {
        "items": items,
        "total": int(total or 0),
        "limit": limit,
        "offset": offset,
        "has_more": offset + len(items) < int(total or 0),
    }


@router.post("/api/gateway/assets/{asset_id}/recheck", status_code=202)
async def gateway_asset_recheck(
    asset_id: str,
    _role_name: str = Depends(_require_full),
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    asset = await session.get(GatewayAsset, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Gateway 资产不存在")
    asset.next_scan_at = datetime.now(timezone.utc)
    asset.scan_state = "discovered"
    await session.commit()
    return {"asset_id": asset.id, "scan_state": asset.scan_state, "queued": True}


@router.post("/api/gateway/secrets/{secret_id}/revalidate", status_code=202)
async def gateway_secret_revalidate(
    secret_id: str,
    _role_name: str = Depends(_require_full),
    session: AsyncSession = Depends(get_session),
) -> dict[str, object]:
    secret = await session.get(GatewaySecret, secret_id)
    if secret is None:
        raise HTTPException(status_code=404, detail="Gateway Secret 不存在")
    secret.validation_status = "pending"
    secret.last_validated_at = None
    await session.commit()
    return {"secret_id": secret.id, "validation_status": secret.validation_status}


__all__ = ["router"]
