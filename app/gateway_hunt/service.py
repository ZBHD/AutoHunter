"""LiteLLM 专项扫描状态机与结构化结果持久化。"""
from __future__ import annotations

import inspect
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding,
    GatewayAsset,
    GatewayObservation,
    GatewaySecret,
    RawEvidence,
)
from app.gateway_hunt.classifier import (
    FindingCandidate,
    classify_probe,
    classify_secret,
)
from app.gateway_hunt.schemas import SecretArtifact


SCAN_STAGES = (
    "fingerprinting",
    "auth_baseline",
    "exposure_scanning",
    "secret_extracting",
    "credential_validating",
    "inference_validating",
    "reviewing",
)


@dataclass(frozen=True, slots=True)
class GatewayProbeResult:
    probe_id: str
    stage: str
    auth_variant: str = "none"
    result: str = "inconclusive"
    status_code: int = 0
    content_type: str = ""
    body: str = ""
    evidence_id: str = ""


@dataclass(frozen=True, slots=True)
class GatewayScanInput:
    fingerprint_status: str = "probable"
    fingerprint_confidence: float = 0.0
    auth_state: str = "unknown"
    model_names: tuple[str, ...] = ()
    observations: tuple[GatewayProbeResult, ...] = ()
    secrets: tuple[SecretArtifact, ...] = ()
    request_count: int = 0
    partial: bool = False


@dataclass(frozen=True, slots=True)
class GatewayScanResult:
    asset_id: str
    scan_epoch: int
    secret_count: int
    findings: tuple[FindingCandidate, ...]
    partial: bool
    request_count: int


class GatewayScanClient(Protocol):
    async def scan(
        self,
        asset: GatewayAsset,
        *,
        scan_epoch: int,
        request_budget: int,
    ) -> GatewayScanInput: ...


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def _call_client(
    client: object,
    asset: GatewayAsset,
    *,
    scan_epoch: int,
    request_budget: int,
) -> GatewayScanInput:
    scanner = getattr(client, "scan", None)
    if scanner is None:
        scanner = getattr(client, "scan_asset")
    value = scanner(asset, scan_epoch=scan_epoch, request_budget=request_budget)
    if inspect.isawaitable(value):
        value = await value
    if not isinstance(value, GatewayScanInput):
        raise TypeError("gateway scan client must return GatewayScanInput")
    return value


async def _persist_evidence(
    session: AsyncSession,
    *,
    asset: GatewayAsset,
    probe: GatewayProbeResult,
) -> None:
    if not probe.evidence_id:
        return
    existing = await session.get(RawEvidence, probe.evidence_id)
    if existing is not None:
        return
    body = probe.body or ""
    session.add(
        RawEvidence(
            id=probe.evidence_id,
            task_id=asset.task_id,
            target_id=asset.target_id,
            source_kind="litellm_gateway_probe",
            capture_status="complete",
            metadata_json={
                "probe_id": probe.probe_id,
                "auth_variant": probe.auth_variant,
                "status_code": probe.status_code,
            },
            preview={"response": body[:4000]},
            content_hash="",
        )
    )


async def _persist_observations(
    session: AsyncSession,
    *,
    asset: GatewayAsset,
    epoch: int,
    probes: tuple[GatewayProbeResult, ...],
) -> None:
    for probe in probes:
        existing = await session.scalar(
            select(GatewayObservation).where(
                GatewayObservation.gateway_asset_id == asset.id,
                GatewayObservation.scan_epoch == epoch,
                GatewayObservation.probe_id == probe.probe_id,
                GatewayObservation.auth_variant == probe.auth_variant,
            )
        )
        if existing is not None:
            continue
        await _persist_evidence(session, asset=asset, probe=probe)
        session.add(
            GatewayObservation(
                task_id=asset.task_id,
                gateway_asset_id=asset.id,
                scan_epoch=epoch,
                stage=probe.stage,
                probe_id=probe.probe_id,
                auth_variant=probe.auth_variant,
                result=probe.result,
                status_code=probe.status_code,
                content_type=probe.content_type,
                evidence_id=probe.evidence_id or None,
            )
        )


async def _persist_secrets(
    session: AsyncSession,
    *,
    asset: GatewayAsset,
    secrets: tuple[SecretArtifact, ...],
) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for artifact in secrets:
        status = str(artifact.validation_context.get("validation_status") or "pending")
        statuses[artifact.sha256] = status
        row = await session.scalar(
            select(GatewaySecret).where(
                GatewaySecret.gateway_asset_id == asset.id,
                GatewaySecret.secret_sha256 == artifact.sha256,
            )
        )
        if row is None:
            session.add(
                GatewaySecret(
                    task_id=asset.task_id,
                    gateway_asset_id=asset.id,
                    secret_type=artifact.secret_type,
                    provider=artifact.provider,
                    secret_name=artifact.name,
                    secret_value=artifact.value,
                    secret_sha256=artifact.sha256,
                    source_url=artifact.source_url,
                    source_location=artifact.source_location,
                    source_context=artifact.context,
                    credential_group_id=artifact.credential_group_id,
                    validation_context=artifact.validation_context,
                    validation_status=status,
                    validated_models=list(
                        artifact.validation_context.get("validated_models") or []
                    ),
                )
            )
        else:
            row.last_seen_at = _utc_now()
            row.validation_status = status
    return statuses


async def _persist_finding(
    session: AsyncSession,
    *,
    asset: GatewayAsset,
    candidate: FindingCandidate,
) -> None:
    existing = await session.scalar(
        select(Finding).where(Finding.dedup_key == candidate.dedup_key)
    )
    if existing is not None:
        return
    session.add(
        Finding(
            task_id=asset.task_id,
            target_id=asset.target_id,
            vuln_type=candidate.vuln_type,
            title=candidate.title,
            severity_claimed=candidate.severity,
            target_url=candidate.target_url,
            description=candidate.description,
            steps=[],
            poc="",
            raw_request="",
            raw_response="",
            evidence={"evidence_id": candidate.evidence_id},
            affected_scope=asset.origin_key,
            kill_chain=[],
            dedup_key=candidate.dedup_key,
            status="pending_review",
        )
    )


async def scan_asset(
    *,
    asset_id: str,
    session: AsyncSession,
    client: GatewayScanClient,
    max_requests: int = 24,
    now: datetime | None = None,
) -> GatewayScanResult:
    asset = await session.get(GatewayAsset, asset_id)
    if asset is None:
        raise ValueError(f"gateway asset not found: {asset_id}")
    if max_requests <= 0:
        raise ValueError("max_requests must be positive")
    current_time = now or _utc_now()
    epoch = int(asset.scan_epoch or 0) + 1
    asset.scan_epoch = epoch
    for stage in SCAN_STAGES:
        asset.scan_state = stage
        await session.commit()

    scan = await _call_client(
        client,
        asset,
        scan_epoch=epoch,
        request_budget=max_requests,
    )
    await _persist_observations(
        session,
        asset=asset,
        epoch=epoch,
        probes=scan.observations,
    )
    statuses = await _persist_secrets(session, asset=asset, secrets=scan.secrets)

    candidates: list[FindingCandidate] = []
    for probe in scan.observations:
        candidate = classify_probe(asset, probe)
        if candidate is not None:
            candidates.append(candidate)
    for artifact in scan.secrets:
        candidate = classify_secret(
            asset,
            artifact,
            validation_status=statuses.get(artifact.sha256, "pending"),
        )
        if candidate is not None:
            candidates.append(candidate)
    deduped = tuple({candidate.dedup_key: candidate for candidate in candidates}.values())
    for candidate in deduped:
        await _persist_finding(session, asset=asset, candidate=candidate)

    asset.fingerprint_status = scan.fingerprint_status
    asset.fingerprint_confidence = scan.fingerprint_confidence
    asset.auth_state = scan.auth_state
    asset.model_names = list(scan.model_names)
    asset.model_count = len(scan.model_names)
    asset.last_scanned_at = current_time
    asset.scan_state = "scheduled_recheck"
    partial = bool(scan.partial or scan.request_count >= max_requests)
    asset.last_error_kind = "budget_exhausted" if partial else ""
    asset.last_error = "request budget exhausted" if partial else ""
    asset.next_scan_at = current_time + timedelta(hours=6 if deduped else 24)
    await session.commit()
    return GatewayScanResult(
        asset_id=asset.id,
        scan_epoch=epoch,
        secret_count=len(scan.secrets),
        findings=deduped,
        partial=partial,
        request_count=scan.request_count,
    )


__all__ = [
    "GatewayProbeResult",
    "GatewayScanClient",
    "GatewayScanInput",
    "GatewayScanResult",
    "SCAN_STAGES",
    "scan_asset",
]
