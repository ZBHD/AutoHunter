from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents import collector
from app.api import gateway_hunt, tasks
from app.db.models import Base, Finding, GatewayAsset, GatewaySecret, Task, TaskEvent
from app.db.session import get_session
from app.gateway_hunt.client import LiteLLMScanClient
from app.gateway_hunt.service import scan_asset
from tests.fixtures.litellm_proxy_fixture import LiteLLMProxyFixture


@pytest.fixture
def litellm_flow_api(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'litellm-flow.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def initialize() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    asyncio.run(initialize())
    monkeypatch.setenv("AUTOHUNTER_API_TOKEN", "full-token")
    monkeypatch.setenv("AUTOHUNTER_READ_TOKEN", "read-token")
    monkeypatch.setenv("AUTOHUNTER_OBSERVER_TOKEN", "observer-token")

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with sessions() as session:
            yield session

    test_app = FastAPI()
    test_app.include_router(tasks.router)
    test_app.include_router(gateway_hunt.router)
    test_app.dependency_overrides[get_session] = override_session
    with TestClient(test_app) as client:
        client._session_maker = sessions
        yield client
    asyncio.run(engine.dispose())


def _create_task(client: TestClient, suffix: str) -> dict:
    response = client.post("/api/tasks", json={
        "name": f"LiteLLM {suffix}",
        "src_type": "litellm",
        "target_source": "manual",
        "manual_targets": [f"https://{suffix}.gateway.test"],
        "mode_config": {"scope_mode": "targeted"},
    })
    assert response.status_code == 200, response.text
    return response.json()


def test_full_litellm_flow_to_finding_and_gateway_api(
    litellm_flow_api: TestClient,
    caplog: pytest.LogCaptureFixture,
) -> None:
    task = _create_task(litellm_flow_api, "open")
    sessions = litellm_flow_api._session_maker

    async def scan() -> None:
        async with sessions() as session:
            stored = await session.get(Task, task["id"])
            assert stored is not None
            assert await collector.refill(session, stored) == 1
            asset = await session.scalar(select(GatewayAsset).where(GatewayAsset.task_id == stored.id))
            assert asset is not None
            fixture = LiteLLMProxyFixture("env_exposure")
            async with httpx.AsyncClient(transport=fixture.transport()) as http_client:
                result = await scan_asset(
                    asset_id=asset.id,
                    session=session,
                    client=LiteLLMScanClient(
                        http_client=http_client,
                        credential_transport=fixture.credential_transport(),
                        validation_base_urls={"openai": "https://provider.fixture"},
                    ),
                    max_requests=24,
                )
            assert {finding.vuln_type for finding in result.findings} >= {
                "litellm_unauthenticated_model_list",
                "litellm_unauthenticated_inference",
                "provider_api_key_leak",
            }
            events = list(
                await session.scalars(select(TaskEvent).where(TaskEvent.task_id == stored.id))
            )
            event_text = json.dumps(
                [{"message": event.message, "payload": event.payload} for event in events],
                ensure_ascii=False,
            )
            assert LiteLLMProxyFixture.PROVIDER_KEY not in event_text

    asyncio.run(scan())

    headers = {"x-autohunter-token": "read-token"}
    summary = litellm_flow_api.get(
        f"/api/tasks/{task['id']}/gateway/summary", headers=headers,
    )
    assert summary.status_code == 200
    assert summary.json()["confirmed_asset_count"] == 1
    assert summary.json()["anonymous_inference_count"] == 1
    assert summary.json()["valid_secret_count"] == 1

    assets = litellm_flow_api.get(
        f"/api/tasks/{task['id']}/gateway/assets", headers=headers,
    )
    assert assets.status_code == 200
    assert assets.json()["items"][0]["fingerprint_status"] == "confirmed"

    secrets = litellm_flow_api.get(
        f"/api/tasks/{task['id']}/gateway/secrets", headers=headers,
    )
    assert secrets.status_code == 200
    assert secrets.json()["items"][0]["secret_value"] == LiteLLMProxyFixture.PROVIDER_KEY
    denied = litellm_flow_api.get(
        f"/api/tasks/{task['id']}/gateway/secrets",
        headers={"x-autohunter-token": "observer-token"},
    )
    assert denied.status_code == 403
    assert LiteLLMProxyFixture.PROVIDER_KEY not in caplog.text


@pytest.mark.parametrize("mode", ["authenticated", "spa_waf"])
def test_protected_and_catch_all_fixtures_do_not_create_findings(
    litellm_flow_api: TestClient,
    mode: str,
) -> None:
    task = _create_task(litellm_flow_api, mode)
    sessions = litellm_flow_api._session_maker

    async def scan() -> tuple[int, str]:
        async with sessions() as session:
            stored = await session.get(Task, task["id"])
            assert stored is not None
            await collector.refill(session, stored)
            asset = await session.scalar(select(GatewayAsset).where(GatewayAsset.task_id == stored.id))
            assert asset is not None
            fixture = LiteLLMProxyFixture(mode)
            async with httpx.AsyncClient(transport=fixture.transport()) as http_client:
                await scan_asset(
                    asset_id=asset.id,
                    session=session,
                    client=LiteLLMScanClient(http_client=http_client),
                )
            count = await session.scalar(
                select(func.count()).select_from(Finding).where(Finding.task_id == stored.id)
            )
            await session.refresh(asset)
            return int(count or 0), asset.fingerprint_status

    count, fingerprint = asyncio.run(scan())
    assert count == 0
    assert fingerprint == ("confirmed" if mode == "authenticated" else "rejected")
