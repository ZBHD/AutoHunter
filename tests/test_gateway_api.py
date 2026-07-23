from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.db.models import Base, GatewayAsset, GatewayObservation, GatewaySecret, Target, Task
from app.db.session import get_session
from app.main import app


def _engine(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'gateway-api.db'}")

    @event.listens_for(engine.sync_engine, "connect")
    def enable_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    return engine


@pytest.fixture
def gateway_api(tmp_path, monkeypatch):
    from app.db.session import _auto_migrate, _ensure_secondary_indexes, _ensure_unique_indexes

    engine = _engine(tmp_path)
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def initialize() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
            await _auto_migrate(connection)
            await _ensure_unique_indexes(connection)
            await _ensure_secondary_indexes(connection)
        async with session_maker() as session:
            task = Task(id="task-gateway", name="Gateway", src_type="litellm")
            target = Target(
                id="target-gateway",
                task_id=task.id,
                url="https://gateway.test/llm",
                host="gateway.test",
                source="gw:llm:fixture",
            )
            asset = GatewayAsset(
                id="asset-gateway",
                task_id=task.id,
                target_id=target.id,
                canonical_base_url=target.url,
                origin_key="https://gateway.test/llm",
                fingerprint_status="confirmed",
                fingerprint_confidence=0.99,
                auth_state="anonymous_models",
                model_names=["gpt-fixture"],
                model_count=1,
                scan_state="scheduled_recheck",
            )
            session.add_all([
                task,
                target,
                asset,
                GatewaySecret(
                    id="secret-gateway",
                    task_id=task.id,
                    gateway_asset_id=asset.id,
                    secret_type="provider_key",
                    provider="openai",
                    secret_name="OPENAI_API_KEY",
                    secret_value="sk-fixture-secret",
                    secret_sha256="a" * 64,
                    source_url="https://gateway.test/llm/.env",
                    source_location="body:1",
                    source_context="OPENAI_API_KEY=<redacted>",
                    validation_status="valid",
                    validated_models=["gpt-fixture"],
                ),
                GatewayObservation(
                    id="observation-gateway",
                    task_id=task.id,
                    gateway_asset_id=asset.id,
                    scan_epoch=1,
                    stage="auth_baseline",
                    probe_id="models",
                    auth_variant="none",
                    result="anonymous_models",
                    status_code=200,
                    content_type="application/json",
                ),
            ])
            await session.commit()

    asyncio.run(initialize())
    monkeypatch.setenv("AUTOHUNTER_API_TOKEN", "full-token")
    monkeypatch.setenv("AUTOHUNTER_READ_TOKEN", "read-token")
    monkeypatch.setenv("AUTOHUNTER_OBSERVER_TOKEN", "observer-token")

    async def override_session() -> AsyncIterator[AsyncSession]:
        async with session_maker() as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        client._session_maker = session_maker
        yield client
    app.dependency_overrides.clear()
    asyncio.run(engine.dispose())


def test_observer_cannot_read_gateway_secrets(gateway_api: TestClient) -> None:
    response = gateway_api.get(
        "/api/tasks/task-gateway/gateway/secrets",
        headers={"x-autohunter-token": "observer-token"},
    )
    assert response.status_code == 403


def test_readonly_can_read_plaintext_secret(gateway_api: TestClient) -> None:
    response = gateway_api.get(
        "/api/tasks/task-gateway/gateway/secrets",
        headers={"x-autohunter-token": "read-token"},
    )
    assert response.status_code == 200
    assert response.json()["items"][0]["secret_value"] == "sk-fixture-secret"


def test_gateway_search_does_not_match_or_echo_secret_value(gateway_api: TestClient) -> None:
    response = gateway_api.get(
        "/api/tasks/task-gateway/gateway/secrets",
        params={"q": "sk-fixture-secret"},
        headers={"x-autohunter-token": "read-token"},
    )
    assert response.status_code == 200
    assert response.json()["items"] == []
    assert "sk-fixture-secret" not in response.text


def test_gateway_export_is_no_store_and_readonly_write_is_forbidden(
    gateway_api: TestClient,
) -> None:
    export = gateway_api.get(
        "/api/tasks/task-gateway/gateway/secrets/export",
        params={"format": "json"},
        headers={"x-autohunter-token": "read-token"},
    )
    assert export.status_code == 200
    assert export.headers["cache-control"] == "no-store"
    assert "sk-fixture-secret" in export.text

    response = gateway_api.post(
        "/api/gateway/assets/asset-gateway/recheck",
        headers={"x-autohunter-token": "read-token"},
    )
    assert response.status_code == 403
