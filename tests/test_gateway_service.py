from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, GatewayAsset, GatewayObservation, GatewaySecret, Task, Target
from app.gateway_hunt.schemas import SecretArtifact
from app.gateway_hunt.service import (
    GatewayProbeResult,
    GatewayScanInput,
    scan_asset,
)


def _secret() -> SecretArtifact:
    value = "sk-proj-real-fixture-key-abcdefghijkl"
    return SecretArtifact(
        name="OPENAI_API_KEY",
        value=value,
        sha256=hashlib.sha256(value.encode()).hexdigest(),
        secret_type="provider_key",
        provider="openai",
        source_url="https://gateway.test/.env",
        source_location="body:1",
        context="OPENAI_API_KEY=<redacted>",
        validation_context={"provider": "openai", "validation_status": "valid"},
    )


@dataclass
class FixtureGatewayClient:
    request_count: int = 4

    async def scan(
        self,
        asset: GatewayAsset,
        *,
        scan_epoch: int,
        request_budget: int,
    ) -> GatewayScanInput:
        return GatewayScanInput(
            fingerprint_status="confirmed",
            fingerprint_confidence=0.99,
            auth_state="anonymous_inference",
            model_names=("gpt-fixture",),
            request_count=self.request_count,
            observations=(
                GatewayProbeResult(
                    probe_id="models",
                    stage="auth_baseline",
                    auth_variant="none",
                    result="anonymous_models",
                    status_code=200,
                    content_type="application/json",
                    body='{"data":[{"id":"gpt-fixture"}]}',
                ),
                GatewayProbeResult(
                    probe_id="chat_completions",
                    stage="inference_validating",
                    auth_variant="none",
                    result="anonymous_inference",
                    status_code=200,
                    content_type="application/json",
                    body='{"choices":[{"message":{"content":"ok"}}]}',
                ),
            ),
            secrets=(_secret(),),
        )


async def _db(tmp_path) -> tuple[object, AsyncSession, GatewayAsset]:
    from tests.test_gateway_models import _asset, _engine, _initialize, _task_target

    engine = _engine(tmp_path, "service.db")
    sessions = await _initialize(engine)
    task, target = _task_target()
    asset = _asset()
    async with sessions() as session:
        session.add_all([task, target, asset])
        await session.commit()
    return engine, sessions, asset


@pytest.mark.asyncio
async def test_scan_asset_persists_checkpoint_secrets_observations_and_findings(tmp_path) -> None:
    engine, sessions, asset = await _db(tmp_path)
    try:
        async with sessions() as session:
            result = await scan_asset(
                asset_id=asset.id,
                session=session,
                client=FixtureGatewayClient(),
            )

        async with sessions() as session:
            stored = await session.get(GatewayAsset, asset.id)
            assert stored is not None
            assert stored.scan_state == "scheduled_recheck"
            assert stored.next_scan_at is not None
            assert result.secret_count == 1
            assert {finding.vuln_type for finding in result.findings} >= {
                "provider_api_key_leak",
                "litellm_unauthenticated_model_list",
                "litellm_unauthenticated_inference",
            }
            assert await session.scalar(
                select(func.count()).select_from(GatewaySecret)
            ) == 1
            assert await session.scalar(
                select(func.count()).select_from(GatewayObservation)
            ) == 2
            assert await session.scalar(select(func.count()).select_from(Finding)) == 3
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_scan_asset_marks_budget_exhaustion_for_next_epoch(tmp_path) -> None:
    engine, sessions, asset = await _db(tmp_path)
    try:
        async with sessions() as session:
            result = await scan_asset(
                asset_id=asset.id,
                session=session,
                client=FixtureGatewayClient(request_count=24),
                max_requests=24,
            )

        async with sessions() as session:
            stored = await session.get(GatewayAsset, asset.id)
            assert stored is not None
            assert result.partial is True
            assert stored.scan_state == "scheduled_recheck"
            assert stored.last_error_kind == "budget_exhausted"
    finally:
        await engine.dispose()
