from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from sqlalchemy import delete, func, inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from app.db.models import (
    Base,
    Finding,
    GatewayAsset,
    GatewayObservation,
    GatewaySecret,
    RawEvidence,
    Target,
    Task,
)
from app.db.session import _auto_migrate, _ensure_secondary_indexes, _ensure_unique_indexes


def _engine(tmp_path, name: str):
    return create_async_engine(f"sqlite+aiosqlite:///{tmp_path / name}")


async def _initialize(engine) -> async_sessionmaker[AsyncSession]:
    async with engine.begin() as connection:
        await connection.exec_driver_sql("PRAGMA foreign_keys=ON")
        await connection.run_sync(Base.metadata.create_all)
        await _auto_migrate(connection)
        await _ensure_unique_indexes(connection)
        await _ensure_secondary_indexes(connection)
    return async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


def _task_target(*, task_id: str = "task-1", target_id: str = "target-1") -> tuple[Task, Target]:
    task = Task(id=task_id, name="LiteLLM", src_type="litellm")
    target = Target(
        id=target_id,
        task_id=task_id,
        url="https://gateway.test/llm",
        host="gateway.test",
        source=f"gw:llm:{target_id[-8:]}",
    )
    return task, target


def _asset(
    *,
    asset_id: str = "asset-1",
    task_id: str = "task-1",
    target_id: str = "target-1",
    origin_key: str = "https://gateway.test/llm",
) -> GatewayAsset:
    return GatewayAsset(
        id=asset_id,
        task_id=task_id,
        target_id=target_id,
        profile_id="litellm",
        profile_version="1",
        canonical_base_url="https://gateway.test/llm",
        origin_key=origin_key,
        mount_path="/llm",
        fingerprint_status="confirmed",
        fingerprint_confidence=0.98,
        fingerprint_signals=[{"probe_id": "liveliness"}],
        detected_version="1.72.0",
        auth_state="mixed",
        model_names=["gpt-test"],
        model_count=1,
        scan_state="scheduled_recheck",
        scan_epoch=3,
        last_error_kind="",
        last_error="",
        consecutive_failures=0,
        last_scanned_at=datetime.now(timezone.utc),
        next_scan_at=datetime.now(timezone.utc),
    )


def _secret(
    *,
    secret_id: str = "secret-1",
    asset_id: str = "asset-1",
    secret_hash: str = "a" * 64,
    finding_id: str | None = None,
    evidence_id: str | None = None,
) -> GatewaySecret:
    now = datetime.now(timezone.utc)
    return GatewaySecret(
        id=secret_id,
        task_id="task-1",
        gateway_asset_id=asset_id,
        finding_id=finding_id,
        secret_type="provider_key",
        provider="openai",
        secret_name="OPENAI_API_KEY",
        secret_value="sk-fixture",
        secret_sha256=secret_hash,
        source_url="https://gateway.test/llm/.env",
        source_location="body:1",
        source_context="OPENAI_API_KEY=<redacted>",
        credential_group_id="provider-primary",
        validation_context={"base_url": "https://api.openai.test/v1"},
        validation_status="valid",
        validated_models=["gpt-test"],
        validation_evidence_id=evidence_id,
        first_seen_at=now,
        last_seen_at=now,
        last_validated_at=now,
    )


def _observation(
    *,
    observation_id: str = "observation-1",
    asset_id: str = "asset-1",
    secret_id: str | None = None,
    evidence_id: str | None = None,
    probe_id: str = "models",
    auth_variant: str = "none",
) -> GatewayObservation:
    return GatewayObservation(
        id=observation_id,
        task_id="task-1",
        gateway_asset_id=asset_id,
        gateway_secret_id=secret_id,
        scan_epoch=3,
        stage="auth_baseline",
        probe_id=probe_id,
        auth_variant=auth_variant,
        result="success",
        status_code=200,
        content_type="application/json",
        evidence_id=evidence_id,
        observed_at=datetime.now(timezone.utc),
    )


def test_gateway_schema_and_indexes_are_idempotent(tmp_path) -> None:
    async def scenario() -> None:
        engine = _engine(tmp_path, "schema.db")
        try:
            await _initialize(engine)
            await _initialize(engine)

            async with engine.connect() as connection:
                tables = await connection.run_sync(lambda sync: set(inspect(sync).get_table_names()))
                assert {"gateway_assets", "gateway_secrets", "gateway_observations"} <= tables

                index_names: set[str] = set()
                for table in ("gateway_assets", "gateway_secrets", "gateway_observations"):
                    indexes = await connection.run_sync(lambda sync, table=table: inspect(sync).get_indexes(table))
                    index_names.update(index["name"] for index in indexes)

                assert {
                    "ux_gateway_asset_task_origin",
                    "ux_gateway_observation_probe",
                    "ux_gateway_secret_asset_hash",
                    "ix_gateway_assets_task_id",
                    "ix_gateway_assets_next_scan_at",
                    "ix_gateway_secrets_task_id",
                    "ix_gateway_secrets_validation_status",
                    "ix_gateway_observations_task_id",
                    "ix_gateway_observations_observed_at",
                } <= index_names
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_gateway_models_store_complete_state_and_relationships(tmp_path) -> None:
    async def scenario() -> None:
        engine = _engine(tmp_path, "relationships.db")
        try:
            sessions = await _initialize(engine)
            async with sessions() as session:
                task, target = _task_target()
                asset = _asset()
                secret = _secret()
                observation = _observation(secret_id=secret.id)
                task.gateway_assets.append(asset)
                target.gateway_asset = asset
                asset.secrets.append(secret)
                asset.observations.append(observation)
                session.add_all([task, target])
                await session.commit()

            async with sessions() as session:
                asset = await session.scalar(
                    select(GatewayAsset)
                    .where(GatewayAsset.id == "asset-1")
                    .options(
                        selectinload(GatewayAsset.task),
                        selectinload(GatewayAsset.target).selectinload(Target.gateway_asset),
                        selectinload(GatewayAsset.secrets),
                        selectinload(GatewayAsset.observations),
                    )
                )
                assert asset is not None
                assert asset.task.id == "task-1"
                assert asset.target.gateway_asset.id == asset.id
                assert [secret.secret_value for secret in asset.secrets] == ["sk-fixture"]
                assert [observation.probe_id for observation in asset.observations] == ["models"]
                assert asset.fingerprint_signals == [{"probe_id": "liveliness"}]
                assert asset.model_names == ["gpt-test"]
                assert asset.next_scan_at is not None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_gateway_unique_indexes_do_not_fall_back_to_non_unique_indexes() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.exec_driver_sql(
                    """
                    CREATE TABLE gateway_assets (
                        id VARCHAR(32) PRIMARY KEY,
                        task_id VARCHAR(32) NOT NULL,
                        target_id VARCHAR(32) NOT NULL,
                        origin_key VARCHAR(500) NOT NULL
                    )
                    """
                )
                await connection.exec_driver_sql(
                    "INSERT INTO gateway_assets (id, task_id, target_id, origin_key) VALUES "
                    "('asset-1', 'task-1', 'target-1', 'duplicate'), "
                    "('asset-2', 'task-1', 'target-2', 'duplicate')"
                )

                with pytest.raises(IntegrityError):
                    await _ensure_unique_indexes(connection)

                row = await connection.exec_driver_sql(
                    "SELECT sql FROM sqlite_master WHERE type='index' "
                    "AND name='ux_gateway_asset_task_origin'"
                )
                assert row.first() is None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("duplicate_kind", "expected_index"),
    [
        ("origin", "ux_gateway_asset_task_origin"),
        ("target", "target_id"),
        ("secret", "ux_gateway_secret_asset_hash"),
        ("observation", "ux_gateway_observation_probe"),
    ],
)
def test_gateway_uniqueness_constraints(tmp_path, duplicate_kind: str, expected_index: str) -> None:
    async def scenario() -> None:
        engine = _engine(tmp_path, f"unique-{duplicate_kind}.db")
        try:
            sessions = await _initialize(engine)
            async with sessions() as session:
                task, target = _task_target()
                second_target = Target(
                    id="target-2",
                    task_id=task.id,
                    url="https://gateway.test/other",
                    host="gateway.test",
                    source="gw:llm:00000002",
                )
                asset = _asset()
                session.add_all([task, target, second_target, asset])
                await session.flush()

                if duplicate_kind == "origin":
                    session.add(_asset(asset_id="asset-2", target_id="target-2"))
                elif duplicate_kind == "target":
                    session.add(_asset(
                        asset_id="asset-2",
                        target_id="target-1",
                        origin_key="https://gateway.test/other",
                    ))
                elif duplicate_kind == "secret":
                    session.add_all([_secret(), _secret(secret_id="secret-2")])
                else:
                    session.add_all([
                        _observation(),
                        _observation(observation_id="observation-2"),
                    ])

                with pytest.raises(IntegrityError) as exc_info:
                    await session.commit()
                assert expected_index in str(exc_info.value) or "UNIQUE constraint failed" in str(exc_info.value)
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_nullable_gateway_references_use_set_null(tmp_path) -> None:
    async def scenario() -> None:
        engine = _engine(tmp_path, "set-null.db")
        try:
            sessions = await _initialize(engine)
            async with sessions() as session:
                task, target = _task_target()
                finding = Finding(
                    id="finding-1",
                    task_id=task.id,
                    target_id=target.id,
                    vuln_type="secret_leak",
                    title="Secret leak",
                    severity_claimed="high",
                    target_url="https://gateway.test/llm/.env",
                )
                evidence = RawEvidence(
                    id="evidence-1",
                    task_id=task.id,
                    target_id=target.id,
                    source_kind="gateway_probe",
                )
                asset = _asset()
                secret = _secret(finding_id=finding.id, evidence_id=evidence.id)
                observation = _observation(secret_id=secret.id, evidence_id=evidence.id)
                session.add_all([task, target])
                await session.flush()
                session.add_all([finding, evidence])
                await session.flush()
                session.add_all([asset, secret, observation])
                await session.commit()

                await session.execute(delete(Finding).where(Finding.id == finding.id))
                await session.execute(delete(RawEvidence).where(RawEvidence.id == evidence.id))
                await session.commit()

            async with sessions() as session:
                secret = await session.get(GatewaySecret, "secret-1")
                observation = await session.get(GatewayObservation, "observation-1")
                assert secret is not None
                assert secret.finding_id is None
                assert secret.validation_evidence_id is None
                assert observation is not None
                assert observation.evidence_id is None

                await session.execute(delete(GatewaySecret).where(GatewaySecret.id == secret.id))
                await session.commit()

            async with sessions() as session:
                observation = await session.get(GatewayObservation, "observation-1")
                assert observation is not None
                assert observation.gateway_secret_id is None
                assert observation.evidence_id is None
                assert await session.get(GatewaySecret, "secret-1") is None
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_deleting_task_cascades_gateway_extension_rows(tmp_path) -> None:
    async def scenario() -> None:
        engine = _engine(tmp_path, "cascade.db")
        try:
            sessions = await _initialize(engine)
            async with sessions() as session:
                task, target = _task_target()
                asset = _asset()
                secret = _secret()
                observation = _observation(secret_id=secret.id)
                task.gateway_assets.append(asset)
                target.gateway_asset = asset
                asset.secrets.append(secret)
                asset.observations.append(observation)
                session.add_all([task, target])
                await session.commit()

            async with sessions() as session:
                task = await session.get(Task, "task-1")
                assert task is not None
                await session.delete(task)
                await session.commit()

            async with sessions() as session:
                for model in (GatewayAsset, GatewaySecret, GatewayObservation):
                    assert await session.scalar(select(func.count()).select_from(model)) == 0
        finally:
            await engine.dispose()

    asyncio.run(scenario())
