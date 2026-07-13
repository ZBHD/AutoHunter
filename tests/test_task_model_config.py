from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.dto import ModelConfigDTO, PartialModelConfigDTO
from app.db.models import Base, Task
from app.db.session import get_session


def test_new_task_model_config_defaults_to_global_pool() -> None:
    config = ModelConfigDTO()

    assert config.use_global_pool is True
    assert config.protocol == "openai_chat"
    assert config.temperature == 0.3


def test_task_model_config_accepts_supported_dedicated_protocol() -> None:
    config = ModelConfigDTO(
        use_global_pool=False,
        base_url="https://anthropic.example/v1",
        api_key="task-secret",
        model="claude-test",
        protocol="anthropic_messages",
        temperature=0.7,
    )

    assert config.use_global_pool is False
    assert config.protocol == "anthropic_messages"
    assert config.temperature == 0.7


@pytest.mark.parametrize(
    "payload",
    [
        {"protocol": "invalid"},
        {"temperature": -0.1},
        {"temperature": 2.1},
        {"base_url": "https://user:password@llm.example/v1"},
        {"base_url": "https://llm.example/v1?api_key=secret"},
    ],
)
def test_task_model_config_rejects_invalid_provider_fields(payload) -> None:
    with pytest.raises(ValidationError):
        ModelConfigDTO(use_global_pool=False, **payload)


def test_partial_task_model_config_supports_pool_switch() -> None:
    patch = PartialModelConfigDTO(use_global_pool=True, prompt_version="modern")

    assert patch.model_dump(exclude_unset=True) == {
        "use_global_pool": True,
        "prompt_version": "modern",
    }


@pytest.fixture
def task_api(tmp_path, monkeypatch):
    from app import settings_service
    from app.api import tasks as tasks_api

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'tasks.db'}")
    session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async def setup() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    asyncio.run(setup())

    async def override_session():
        async with session_maker() as session:
            yield session

    monkeypatch.setattr(
        settings_service,
        "_cache",
        {
            "llm": {
                "base_url": "https://global.example/v1",
                "api_key": "global-secret",
                "model": "global-model",
                "protocol": "openai_responses",
                "temperature": 0.4,
            },
            "llm_providers": [],
            "fofa": {},
            "engines": {},
            "defaults": {"worker_prompt_version": "current"},
        },
    )
    monkeypatch.setenv("AUTOHUNTER_OBSERVER_TOKEN", "observer-token")

    app = FastAPI()
    app.include_router(tasks_api.router)
    app.dependency_overrides[get_session] = override_session

    with TestClient(app) as client:
        yield client, session_maker

    asyncio.run(engine.dispose())


async def _stored_model_config(session_maker, task_id: str) -> dict:
    async with session_maker() as session:
        task = await session.get(Task, task_id)
        assert task is not None
        return dict(task.model_config_json or {})


async def _insert_task(session_maker, task_id: str, model_config: dict) -> None:
    async with session_maker() as session:
        session.add(
            Task(
                id=task_id,
                name=f"Task {task_id}",
                src_type="edusrc",
                vuln_types=[],
                src_rules="",
                target_source="manual",
                fofa_query="",
                manual_targets=[],
                model_config_json=model_config,
                fofa_config={},
                engine="",
                concurrency=1,
                status="created",
            )
        )
        await session.commit()


def test_create_task_persists_and_returns_global_pool_default(task_api) -> None:
    client, session_maker = task_api

    response = client.post("/api/tasks", json={"name": "Global task"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model_config_data"]["use_global_pool"] is True
    assert asyncio.run(_stored_model_config(session_maker, body["id"])) == {
        "use_global_pool": True
    }


def test_create_dedicated_task_returns_protocol_temperature_without_key(task_api) -> None:
    client, _session_maker = task_api

    response = client.post(
        "/api/tasks",
        json={
            "name": "Dedicated task",
            "model_config_data": {
                "use_global_pool": False,
                "base_url": "https://anthropic.example/v1",
                "api_key": "task-secret",
                "model": "claude-test",
                "protocol": "anthropic_messages",
                "temperature": 0.7,
            },
        },
    )

    assert response.status_code == 200, response.text
    config = response.json()["model_config_data"]
    assert config == {
        "use_global_pool": False,
        "base_url": "https://anthropic.example/v1",
        "model": "claude-test",
        "protocol": "anthropic_messages",
        "temperature": 0.7,
        "api_key_set": True,
        "prompt_version": "current",
    }
    assert "api_key" not in config
    assert "task-secret" not in response.text


def test_patch_global_pool_clears_override_fields_but_keeps_prompt_version(task_api) -> None:
    client, session_maker = task_api
    asyncio.run(
        _insert_task(
            session_maker,
            "switch-global",
            {
                "use_global_pool": False,
                "base_url": "https://old.example/v1",
                "api_key": "old-secret",
                "model": "old-model",
                "protocol": "anthropic_messages",
                "temperature": 1.2,
                "prompt_version": "legacy",
            },
        )
    )

    response = client.patch(
        "/api/tasks/switch-global",
        json={"model_config_data": {"use_global_pool": True}},
    )

    assert response.status_code == 200, response.text
    assert asyncio.run(_stored_model_config(session_maker, "switch-global")) == {
        "use_global_pool": True,
        "prompt_version": "legacy",
    }
    config = response.json()["model_config_data"]
    assert config["use_global_pool"] is True
    assert config["model"] == "global-model"
    assert config["prompt_version"] == "legacy"
    assert "old-secret" not in response.text


@pytest.mark.parametrize("replacement", ["", "********"])
def test_patch_dedicated_task_preserves_key_for_empty_or_masked_value(
    task_api, replacement
) -> None:
    client, session_maker = task_api
    asyncio.run(
        _insert_task(
            session_maker,
            "keep-key",
            {
                "use_global_pool": False,
                "base_url": "https://task.example/v1",
                "api_key": "keep-this-secret",
                "model": "task-model",
                "protocol": "openai_chat",
                "temperature": 0.3,
            },
        )
    )

    response = client.patch(
        "/api/tasks/keep-key",
        json={
            "model_config_data": {
                "use_global_pool": False,
                "api_key": replacement,
                "protocol": "openai_responses",
            }
        },
    )

    assert response.status_code == 200, response.text
    stored = asyncio.run(_stored_model_config(session_maker, "keep-key"))
    assert stored["api_key"] == "keep-this-secret"
    assert stored["protocol"] == "openai_responses"
    assert response.json()["model_config_data"]["api_key_set"] is True
    assert "keep-this-secret" not in response.text


def test_legacy_task_with_provider_fields_is_reported_as_dedicated(task_api) -> None:
    client, session_maker = task_api
    asyncio.run(
        _insert_task(
            session_maker,
            "legacy-provider",
            {
                "base_url": "https://legacy.example/v1",
                "api_key": "legacy-secret",
                "model": "legacy-model",
                "protocol": "openai_chat",
                "temperature": 0.6,
            },
        )
    )

    response = client.get("/api/tasks/legacy-provider")

    assert response.status_code == 200, response.text
    config = response.json()["model_config_data"]
    assert config["use_global_pool"] is False
    assert config["model"] == "legacy-model"
    assert config["api_key_set"] is True
    assert "legacy-secret" not in response.text


def test_legacy_prompt_only_task_is_reported_as_global_pool(task_api) -> None:
    client, session_maker = task_api
    asyncio.run(
        _insert_task(
            session_maker,
            "prompt-only",
            {"prompt_version": "legacy"},
        )
    )

    response = client.get("/api/tasks/prompt-only")

    assert response.status_code == 200, response.text
    config = response.json()["model_config_data"]
    assert config["use_global_pool"] is True
    assert config["model"] == "global-model"
    assert config["prompt_version"] == "legacy"


def test_observer_task_response_hides_dedicated_provider_details(task_api) -> None:
    client, session_maker = task_api
    asyncio.run(
        _insert_task(
            session_maker,
            "observer-hidden",
            {
                "use_global_pool": False,
                "base_url": "https://private-provider.example/v1",
                "api_key": "observer-must-not-see",
                "model": "private-model",
                "protocol": "anthropic_messages",
                "temperature": 1.7,
            },
        )
    )

    response = client.get(
        "/api/tasks/observer-hidden",
        headers={"x-autohunter-token": "observer-token"},
    )

    assert response.status_code == 200, response.text
    config = response.json()["model_config_data"]
    assert config["base_url"] == ""
    assert config["model"] == "hidden"
    assert config["api_key_set"] is False
    assert "api_key" not in config
    assert config.get("protocol") != "anthropic_messages"
    assert config.get("temperature") != 1.7
    assert "private-provider" not in response.text
    assert "private-model" not in response.text
    assert "observer-must-not-see" not in response.text
