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


async def _stored_hunt_direction(session_maker, task_id: str) -> str:
    async with session_maker() as session:
        task = await session.get(Task, task_id)
        assert task is not None
        return task.hunt_direction


async def _stored_fofa_config(session_maker, task_id: str) -> dict:
    async with session_maker() as session:
        task = await session.get(Task, task_id)
        assert task is not None
        return dict(task.fofa_config or {})


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


async def _insert_site_task_with_fofa_config(
    session_maker, task_id: str, fofa_config: dict
) -> None:
    async with session_maker() as session:
        session.add(
            Task(
                id=task_id,
                name=f"Task {task_id}",
                src_type="edusrc",
                vuln_types=[],
                src_rules="",
                target_source="site",
                fofa_query="",
                manual_targets=[],
                model_config_json={"use_global_pool": True},
                fofa_config=fofa_config,
                engine="",
                concurrency=1,
                status="created",
            )
        )
        await session.commit()


def test_site_recon_mode_persists_on_create_and_patch_preserves_runtime_cursor(task_api) -> None:
    client, session_maker = task_api

    created = client.post(
        "/api/tasks",
        json={
            "name": "Light site task",
            "target_source": "site",
            "fofa_config": {"site_recon_mode": "light"},
        },
    )

    assert created.status_code == 200, created.text
    task_id = created.json()["id"]
    assert created.json()["fofa_config"]["site_recon_mode"] == "light"
    assert asyncio.run(_stored_fofa_config(session_maker, task_id)) == {
        "site_recon_mode": "light"
    }

    async def add_cursor() -> None:
        async with session_maker() as session:
            task = await session.get(Task, task_id)
            assert task is not None
            task.fofa_config = {
                **(task.fofa_config or {}),
                "cursor": 7,
                "skip_site_recon": True,
            }
            await session.commit()

    asyncio.run(add_cursor())
    patched = client.patch(
        f"/api/tasks/{task_id}",
        json={"fofa_config": {"site_recon_mode": "full"}},
    )

    assert patched.status_code == 200, patched.text
    assert patched.json()["fofa_config"]["site_recon_mode"] == "full"
    assert asyncio.run(_stored_fofa_config(session_maker, task_id)) == {
        "site_recon_mode": "full",
        "cursor": 7,
    }


def test_legacy_skip_site_recon_is_publicly_reported_as_light(task_api) -> None:
    client, session_maker = task_api
    asyncio.run(
        _insert_site_task_with_fofa_config(
            session_maker, "legacy-site-mode", {"skip_site_recon": True}
        )
    )

    response = client.get("/api/tasks/legacy-site-mode")

    assert response.status_code == 200, response.text
    assert response.json()["fofa_config"]["site_recon_mode"] == "light"


def test_switching_to_site_defaults_recon_mode_to_full(task_api) -> None:
    client, session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={
            "name": "Switch to site",
            "target_source": "manual",
            "fofa_config": {"site_recon_mode": "light"},
        },
    ).json()

    response = client.patch(
        f"/api/tasks/{created['id']}",
        json={"target_source": "site"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["fofa_config"]["site_recon_mode"] == "full"
    assert asyncio.run(_stored_fofa_config(session_maker, created["id"])) == {
        "site_recon_mode": "full"
    }


def test_switching_to_site_honors_explicit_recon_mode(task_api) -> None:
    client, session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={"name": "Explicit site mode", "target_source": "manual"},
    ).json()

    response = client.patch(
        f"/api/tasks/{created['id']}",
        json={
            "target_source": "site",
            "fofa_config": {"site_recon_mode": "light"},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["fofa_config"]["site_recon_mode"] == "light"
    assert asyncio.run(_stored_fofa_config(session_maker, created["id"])) == {
        "site_recon_mode": "light"
    }


def test_switching_to_site_defaults_null_recon_mode_to_full(task_api) -> None:
    client, session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={
            "name": "Null site mode",
            "target_source": "manual",
            "fofa_config": {"site_recon_mode": "light"},
        },
    ).json()

    response = client.patch(
        f"/api/tasks/{created['id']}",
        json={
            "target_source": "site",
            "fofa_config": {"site_recon_mode": None},
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["fofa_config"]["site_recon_mode"] == "full"
    assert asyncio.run(_stored_fofa_config(session_maker, created["id"])) == {
        "site_recon_mode": "full"
    }


def test_create_rejects_unknown_site_recon_mode(task_api) -> None:
    client, _session_maker = task_api

    response = client.post(
        "/api/tasks",
        json={
            "name": "Invalid site mode",
            "target_source": "site",
            "fofa_config": {"site_recon_mode": "auto"},
        },
    )

    assert response.status_code == 422, response.text


def test_create_task_persists_and_returns_global_pool_default(task_api) -> None:
    client, session_maker = task_api

    response = client.post("/api/tasks", json={"name": "Global task"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["model_config_data"]["use_global_pool"] is True
    assert asyncio.run(_stored_model_config(session_maker, body["id"])) == {
        "use_global_pool": True
    }


def test_create_task_trims_and_persists_hunt_direction(task_api) -> None:
    client, session_maker = task_api

    response = client.post(
        "/api/tasks",
        json={
            "name": "Directional task",
            "hunt_direction": "  优先检查后台对象越权  ",
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["hunt_direction"] == "优先检查后台对象越权"
    assert asyncio.run(_stored_hunt_direction(session_maker, body["id"])) == "优先检查后台对象越权"


def test_create_task_defaults_hunt_direction_to_empty(task_api) -> None:
    client, session_maker = task_api

    response = client.post("/api/tasks", json={"name": "Default direction"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["hunt_direction"] == ""
    assert asyncio.run(_stored_hunt_direction(session_maker, body["id"])) == ""


def test_patch_can_modify_and_explicitly_clear_hunt_direction(task_api) -> None:
    client, session_maker = task_api
    created = client.post("/api/tasks", json={"name": "Patch direction"}).json()

    updated = client.patch(
        f"/api/tasks/{created['id']}",
        json={"hunt_direction": "  检查批量导出接口  "},
    )

    assert updated.status_code == 200, updated.text
    assert updated.json()["hunt_direction"] == "检查批量导出接口"

    cleared = client.patch(
        f"/api/tasks/{created['id']}",
        json={"hunt_direction": ""},
    )

    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["hunt_direction"] == ""
    assert asyncio.run(_stored_hunt_direction(session_maker, created["id"])) == ""


@pytest.mark.parametrize("method", ["post", "patch"])
def test_hunt_direction_rejects_more_than_2000_characters(task_api, method) -> None:
    client, _session_maker = task_api
    if method == "post":
        response = client.post(
            "/api/tasks",
            json={"name": "Too long", "hunt_direction": "x" * 2001},
        )
    else:
        created = client.post("/api/tasks", json={"name": "Patch too long"}).json()
        response = client.patch(
            f"/api/tasks/{created['id']}",
            json={"hunt_direction": "x" * 2001},
        )

    assert response.status_code == 422, response.text


def test_observer_task_list_and_detail_hide_hunt_direction(task_api) -> None:
    client, _session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={
            "name": "Private direction",
            "hunt_direction": "敏感挖掘方向",
            "fofa_config": {"site_recon_mode": "light"},
        },
    ).json()
    headers = {"x-autohunter-token": "observer-token"}

    listed = client.get("/api/tasks", headers=headers)
    detailed = client.get(f"/api/tasks/{created['id']}", headers=headers)

    assert listed.status_code == 200, listed.text
    assert detailed.status_code == 200, detailed.text
    item = next(task for task in listed.json() if task["id"] == created["id"])
    assert item["hunt_direction"] == ""
    assert detailed.json()["hunt_direction"] == ""
    assert item["fofa_config"]["site_recon_mode"] == "full"
    assert detailed.json()["fofa_config"]["site_recon_mode"] == "full"
    assert "敏感挖掘方向" not in listed.text
    assert "敏感挖掘方向" not in detailed.text


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


def test_patch_fofa_key_null_clears_task_override(task_api) -> None:
    client, session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={"name": "Clear FOFA key", "fofa_config": {"key": "task-fofa-secret"}},
    ).json()

    response = client.patch(
        f"/api/tasks/{created['id']}",
        json={"fofa_config": {"key": None}},
    )

    assert response.status_code == 200, response.text
    assert "key" not in asyncio.run(_stored_fofa_config(session_maker, created["id"]))


def test_patch_fofa_key_omitted_preserves_task_override(task_api) -> None:
    client, session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={"name": "Keep omitted FOFA key", "fofa_config": {"key": "task-fofa-secret"}},
    ).json()

    response = client.patch(
        f"/api/tasks/{created['id']}",
        json={"fofa_config": {"intent_mode": "intent"}},
    )

    assert response.status_code == 200, response.text
    stored = asyncio.run(_stored_fofa_config(session_maker, created["id"]))
    assert stored["key"] == "task-fofa-secret"


def test_patch_fofa_key_blank_preserves_task_override(task_api) -> None:
    client, session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={"name": "Keep blank FOFA key", "fofa_config": {"key": "task-fofa-secret"}},
    ).json()

    response = client.patch(
        f"/api/tasks/{created['id']}",
        json={"fofa_config": {"key": ""}},
    )

    assert response.status_code == 200, response.text
    stored = asyncio.run(_stored_fofa_config(session_maker, created["id"]))
    assert stored["key"] == "task-fofa-secret"


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
