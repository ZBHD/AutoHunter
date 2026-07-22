from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.agents.prompts import is_enterprise_src, is_litellm_src, normalize_src_type
from app.api.dto import CreateTaskRequest, LiteLlmModeConfigDTO
from app.api import tasks as tasks_api
from app.db.models import Base, Task
from app.db.session import get_session


def test_normalize_src_type_keeps_litellm() -> None:
    assert normalize_src_type("litellm") == "litellm"
    assert is_litellm_src("litellm") is True
    assert is_enterprise_src("litellm") is False


def test_global_mode_defaults_to_full_checks() -> None:
    req = CreateTaskRequest(
        name="lite",
        src_type="litellm",
        target_source="fofa",
        mode_config={"scope_mode": "global"},
    )

    assert req.mode_config is not None
    assert req.mode_config.validation.level == "full"
    assert req.mode_config.checks.anonymous_inference is True


def test_targeted_mode_requires_anchor_or_manual_target() -> None:
    with pytest.raises(ValidationError):
        CreateTaskRequest(
            name="lite",
            src_type="litellm",
            target_source="manual",
            mode_config={"scope_mode": "targeted", "scope_anchors": []},
        )


def test_litellm_mode_rejects_unknown_fields_and_profiles() -> None:
    with pytest.raises(ValidationError):
        LiteLlmModeConfigDTO(unknown=True)


@pytest.fixture
def task_api(tmp_path, monkeypatch):
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

    app = FastAPI()
    app.include_router(tasks_api.router)
    app.dependency_overrides[get_session] = override_session
    monkeypatch.setenv("AUTOHUNTER_OBSERVER_TOKEN", "observer-token")

    with TestClient(app) as client:
        yield client, session_maker

    asyncio.run(engine.dispose())


def test_create_litellm_task_uses_fixed_specialized_vuln_types(task_api) -> None:
    client, session_maker = task_api
    response = client.post(
        "/api/tasks",
        json={
            "name": "LiteLLM fixture",
            "src_type": "litellm",
            "target_source": "manual",
            "manual_targets": ["https://gateway.example"],
            "vuln_types": ["sqli", "xss"],
            "mode_config": {"scope_mode": "targeted"},
        },
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert "sqli" not in body["vuln_types"]
    assert "xss" not in body["vuln_types"]
    assert "litellm_unauthenticated_inference" in body["vuln_types"]
    assert body["mode_config"]["enabled_profiles"] == ["litellm"]

    async def stored() -> tuple[dict, str]:
        async with session_maker() as session:
            task = await session.get(Task, body["id"])
            assert task is not None
            return dict(task.mode_config_json or {}), task.src_type

    config, src_type = asyncio.run(stored())
    assert config["scope_mode"] == "targeted"
    assert src_type == "litellm"


def test_patch_litellm_checks_recomputes_specialized_vuln_types(task_api) -> None:
    client, _session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={
            "name": "LiteLLM patch fixture",
            "src_type": "litellm",
            "target_source": "fofa",
            "mode_config": {"scope_mode": "global"},
        },
    )
    assert created.status_code == 200, created.text

    response = client.patch(
        f"/api/tasks/{created.json()['id']}",
        json={
            "vuln_types": ["sqli", "xss"],
            "mode_config": {
                "scope_mode": "global",
                "checks": {
                    "key_leak": False,
                    "env_leak": False,
                    "management_exposure": False,
                    "anonymous_models": True,
                    "anonymous_inference": False,
                },
            },
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["vuln_types"] == [
        "litellm_unauthenticated_model_list"
    ]
    assert response.json()["mode_config"]["checks"]["anonymous_models"] is True


def test_observer_task_detail_hides_litellm_mode_config(task_api) -> None:
    client, _session_maker = task_api
    created = client.post(
        "/api/tasks",
        json={
            "name": "Private LiteLLM scope",
            "src_type": "litellm",
            "target_source": "fofa",
            "mode_config": {
                "scope_mode": "targeted",
                "scope_anchors": ["private.example"],
            },
        },
    )
    assert created.status_code == 200, created.text

    response = client.get(
        f"/api/tasks/{created.json()['id']}",
        headers={"x-autohunter-token": "observer-token"},
    )

    assert response.status_code == 200, response.text
    assert response.json()["mode_config"] == {}
    assert "private.example" not in response.text


@pytest.mark.parametrize(
    "mode_config",
    [
        {"scope_mode": "global", "enabled_profiles": ["unknown"]},
        {"scope_mode": "global", "validation": {"max_requests_per_asset_epoch": 1001}},
    ],
)
def test_litellm_rejects_unknown_profile_and_budget_with_400(task_api, mode_config) -> None:
    client, _session_maker = task_api
    response = client.post(
        "/api/tasks",
        json={
            "name": "Invalid LiteLLM",
            "src_type": "litellm",
            "target_source": "fofa",
            "mode_config": mode_config,
        },
    )

    assert response.status_code == 400, response.text


def test_litellm_rejects_site_source_with_400(task_api) -> None:
    client, _session_maker = task_api
    response = client.post(
        "/api/tasks",
        json={
            "name": "Invalid source",
            "src_type": "litellm",
            "target_source": "site",
            "mode_config": {"scope_mode": "targeted", "scope_anchors": ["example.com"]},
        },
    )

    assert response.status_code == 400, response.text


def test_litellm_illegal_source_is_400_before_scope_validation(task_api) -> None:
    client, _session_maker = task_api
    response = client.post(
        "/api/tasks",
        json={
            "name": "Invalid source without scope",
            "src_type": "litellm",
            "target_source": "site",
            "mode_config": {"scope_mode": "targeted"},
        },
    )

    assert response.status_code == 400, response.text


def test_legacy_task_mode_config_defaults_to_empty_object(task_api) -> None:
    client, session_maker = task_api

    async def insert() -> str:
        async with session_maker() as session:
            task = Task(
                name="Legacy task",
                src_type="edusrc",
                vuln_types=[],
                src_rules="",
                target_source="manual",
                fofa_query="",
                manual_targets=[],
                model_config_json={"use_global_pool": True},
                fofa_config={},
                concurrency=1,
                status="created",
            )
            session.add(task)
            await session.commit()
            return task.id

    task_id = asyncio.run(insert())
    response = client.get(f"/api/tasks/{task_id}")
    assert response.status_code == 200, response.text
    assert response.json()["mode_config"] == {}
