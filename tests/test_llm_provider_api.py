from __future__ import annotations

import asyncio
import logging
import threading
from urllib.parse import quote

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import settings as settings_api
from app.config import LLMProviderConfig
from app.db.models import Base, SystemSettings
from app.db.session import get_session
from app import settings_service


@pytest.fixture
def provider_api(tmp_path, monkeypatch):
    db_path = tmp_path / "providers.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    session_maker = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def setup() -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    asyncio.run(setup())

    async def override_session():
        async with session_maker() as session:
            yield session

    app = FastAPI()
    app.include_router(settings_api.router)
    app.dependency_overrides[get_session] = override_session

    monkeypatch.setattr(settings_service, "SessionLocal", session_maker)
    settings_service._cache = {
        "llm": {}, "llm_providers": [], "fofa": {}, "engines": {}, "defaults": {}
    }

    with TestClient(app) as client:
        yield client, session_maker

    asyncio.run(engine.dispose())


def provider_payload(name: str, key: str, **overrides):
    payload = {
        "name": name,
        "base_url": f"https://{name.lower()}.example/v1",
        "api_key": key,
        "model": f"model-{name.lower()}",
        "temperature": 0.3,
        "weight": 5,
        "protocol": "openai_chat",
        "enabled": True,
    }
    payload.update(overrides)
    return payload


async def raw_providers(session_maker) -> list[dict]:
    async with session_maker() as session:
        row = await session.get(SystemSettings, "global")
        return list(row.llm_providers or []) if row else []


async def raw_fofa_settings(session_maker) -> dict:
    async with session_maker() as session:
        row = await session.get(SystemSettings, "global")
        return dict(row.fofa or {}) if row else {}


def create_provider(client: TestClient, name: str, key: str, **overrides):
    response = client.post(
        "/api/settings/llm-providers",
        json=provider_payload(name, key, **overrides),
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_provider_crud_never_returns_plaintext_keys(provider_api) -> None:
    client, session_maker = provider_api
    secret = "opaque-provider-token-VERYSECRET"

    created = create_provider(client, "Primary", secret)
    listed = client.get("/api/settings/llm-providers")

    assert listed.status_code == 200
    assert created["providers"][0]["api_key"] == settings_service._MASK_PLACEHOLDER
    assert listed.json()[0]["api_key_set"] is True
    assert secret not in created.__repr__()
    assert secret not in listed.text
    assert asyncio.run(raw_providers(session_maker))[0]["api_key"] == secret

    updated = client.put(
        "/api/settings/llm-providers/Primary",
        json={"model": "new-model", "api_key": settings_service._MASK_PLACEHOLDER},
    )
    assert updated.status_code == 200, updated.text
    raw = asyncio.run(raw_providers(session_maker))[0]
    assert raw["api_key"] == secret
    assert raw["model"] == "new-model"

    disabled = client.put(
        "/api/settings/llm-providers/Primary",
        json={"enabled": False, "api_key": ""},
    )
    assert disabled.status_code == 200
    assert disabled.json()["providers"][0]["enabled"] is False

    deleted = client.delete("/api/settings/llm-providers/Primary")
    assert deleted.status_code == 200
    assert deleted.json()["providers"] == []


def test_duplicate_names_are_case_insensitive(provider_api) -> None:
    client, _session_maker = provider_api
    create_provider(client, "Primary", "secret-a")

    duplicate = client.post(
        "/api/settings/llm-providers",
        json=provider_payload(" primary ", "secret-b"),
    )

    assert duplicate.status_code == 409


def test_enabled_provider_requires_key_but_disabled_draft_does_not(provider_api) -> None:
    client, _session_maker = provider_api

    rejected = client.post(
        "/api/settings/llm-providers",
        json=provider_payload("NoKey", ""),
    )
    draft = client.post(
        "/api/settings/llm-providers",
        json=provider_payload("Draft", "", enabled=False),
    )

    assert rejected.status_code == 422
    assert draft.status_code == 200


def test_order_route_preserves_secrets_and_rejects_non_permutations(provider_api) -> None:
    client, session_maker = provider_api
    create_provider(client, "A", "secret-a")
    create_provider(client, "B", "secret-b")

    ordered = client.put(
        "/api/settings/llm-providers/order",
        json={"names": ["B", "A"]},
    )

    assert ordered.status_code == 200, ordered.text
    assert [item["name"] for item in ordered.json()["providers"]] == ["B", "A"]
    raw = asyncio.run(raw_providers(session_maker))
    assert [(item["name"], item["api_key"]) for item in raw] == [
        ("B", "secret-b"),
        ("A", "secret-a"),
    ]

    missing = client.put(
        "/api/settings/llm-providers/order",
        json={"names": ["A"]},
    )
    duplicate = client.put(
        "/api/settings/llm-providers/order",
        json={"names": ["A", "A"]},
    )
    assert missing.status_code == 400
    assert duplicate.status_code == 400


def test_connectivity_probe_uses_saved_provider_and_returns_safe_result(provider_api, monkeypatch) -> None:
    client, _session_maker = provider_api
    secret = "probe-secret-VERYSECRET"
    create_provider(client, "Probe", secret, protocol="anthropic_messages")
    seen: dict = {}

    async def fake_probe(provider):
        seen.update(provider.model_dump())
        return {
            "ok": True,
            "latency_ms": 12,
            "model": provider.model,
            "protocol": provider.protocol,
            "error": "",
        }

    monkeypatch.setattr(settings_api, "probe_llm_provider", fake_probe, raising=False)

    response = client.post("/api/settings/llm-providers/Probe/test")

    assert response.status_code == 200, response.text
    assert response.json()["protocol"] == "anthropic_messages"
    assert seen["api_key"] == secret
    assert secret not in response.text


def test_models_probe_uses_saved_provider_key(provider_api, monkeypatch) -> None:
    client, _session_maker = provider_api
    secret = "saved-model-list-secret"
    create_provider(
        client,
        "Models",
        secret,
        base_url="https://api.anthropic.com",
        protocol="anthropic_messages",
    )
    seen: dict = {}

    async def fake_list_models(*, base_url=None, api_key=None, protocol="openai_chat"):
        seen.update(
            base_url=base_url,
            api_key=api_key,
            protocol=protocol,
        )
        return {"ok": True, "error": "", "models": ["claude-test"]}

    monkeypatch.setattr(settings_api, "list_available_models", fake_list_models)

    response = client.post(
        "/api/settings/models",
        json={
            "provider_name": "Models",
            "base_url": "https://api.anthropic.com",
            "api_key": "",
            "protocol": "anthropic_messages",
        },
    )

    assert response.status_code == 200, response.text
    assert response.json()["models"] == ["claude-test"]
    assert seen == {
        "base_url": "https://api.anthropic.com",
        "api_key": secret,
        "protocol": "anthropic_messages",
    }
    assert secret not in response.text


def test_models_probe_does_not_send_saved_key_to_changed_url(
    provider_api, monkeypatch
) -> None:
    client, _session_maker = provider_api
    secret = "saved-model-list-secret"
    create_provider(client, "Models", secret)
    seen: dict = {}

    async def fake_list_models(*, base_url=None, api_key=None, protocol="openai_chat"):
        seen.update(
            base_url=base_url,
            api_key=api_key,
            protocol=protocol,
        )
        return {"ok": False, "error": "missing key", "models": []}

    monkeypatch.setattr(settings_api, "list_available_models", fake_list_models)

    response = client.post(
        "/api/settings/models",
        json={
            "provider_name": "Models",
            "base_url": "https://attacker.example/v1",
            "api_key": "",
            "protocol": "openai_chat",
        },
    )

    assert response.status_code == 200, response.text
    assert seen["base_url"] == "https://attacker.example/v1"
    assert seen["api_key"] is None
    assert secret not in response.text


def test_model_list_does_not_fallback_global_key_for_explicit_url(monkeypatch) -> None:
    global_secret = "global-key-must-not-leak"
    settings_service._cache = {
        "llm": {
            "base_url": "https://global.example/v1",
            "api_key": global_secret,
            "model": "global-model",
        },
        "llm_providers": [],
        "fofa": {},
        "engines": {},
        "defaults": {},
    }

    class UnexpectedClient:
        def __init__(self, *args, **kwargs):
            raise AssertionError("missing task key must stop before any outbound request")

    monkeypatch.setattr(httpx, "AsyncClient", UnexpectedClient)

    result = asyncio.run(
        settings_service.list_available_models(
            base_url="https://task-provider.example/v1",
            api_key=None,
            protocol="openai_chat",
        )
    )

    assert result == {
        "ok": False,
        "error": "未配置 API Key，无法拉取模型列表",
        "models": [],
    }


def test_anthropic_model_list_uses_protocol_headers_and_v1_url(monkeypatch) -> None:
    secret = "anthropic-model-secret"
    seen: dict = {}

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"data": [{"id": "claude-z"}, {"id": "claude-a"}]}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, headers):
            seen.update(url=url, headers=headers)
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url", lambda _url: None
    )

    result = asyncio.run(
        settings_service.list_available_models(
            base_url="https://api.anthropic.com",
            api_key=secret,
            protocol="anthropic_messages",
        )
    )

    assert result == {
        "ok": True,
        "error": "",
        "models": ["claude-a", "claude-z"],
    }
    assert seen["url"] == "https://api.anthropic.com/v1/models"
    assert seen["headers"]["x-api-key"] == secret
    assert seen["headers"]["anthropic-version"] == "2023-06-01"
    assert "Authorization" not in seen["headers"]


def test_fofa_probe_uses_account_info_endpoint(monkeypatch) -> None:
    secret = "fofa-probe-secret-VERYSECRET"
    seen: dict = {}

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"error": False, "username": "tester", "fcoin": 10}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, url, params):
            seen.update(url=url, params=params)
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url", lambda url, **_kwargs: seen.update(safe_url=url)
    )

    result = asyncio.run(
        settings_service.probe_fofa_key(
            key=secret,
            base_url="https://fofa.info",
        )
    )

    assert result["ok"] is True
    assert result["error"] == ""
    assert result["latency_ms"] >= 0
    assert seen["url"] == "https://fofa.info/api/v1/info/my"
    assert seen["safe_url"] == seen["url"]
    assert seen["params"] == {"key": secret}
    assert secret not in repr(result)


def test_fofa_probe_failure_never_echoes_key(monkeypatch) -> None:
    secret = "fofa/probe+secret-VERYSECRET"
    encoded_secret = quote(secret, safe="")

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return {"error": True, "errmsg": f"invalid key {encoded_secret}"}

    class Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        async def get(self, _url, params):
            assert params == {"key": secret}
            return Response()

    monkeypatch.setattr(httpx, "AsyncClient", lambda **_kwargs: Client())
    monkeypatch.setattr(
        "app.tools.netguard.assert_safe_outbound_url", lambda _url, **_kwargs: None
    )

    result = asyncio.run(
        settings_service.probe_fofa_key(
            key=secret,
            base_url="https://fofa.info",
        )
    )

    assert result["ok"] is False
    assert secret not in repr(result)
    assert encoded_secret not in repr(result)


def test_saving_replacement_fofa_key_reenables_global_fofa(provider_api) -> None:
    client, session_maker = provider_api

    async def seed_disabled_fofa() -> None:
        async with session_maker() as session:
            row = SystemSettings(
                id="global",
                fofa={
                    "key": "old-fofa-secret",
                    "base_url": "https://fofa.info",
                    "enabled": False,
                },
            )
            session.add(row)
            await session.commit()

    asyncio.run(seed_disabled_fofa())

    response = client.put(
        "/api/settings",
        json={"fofa": {"key": "replacement-fofa-secret"}},
    )

    assert response.status_code == 200, response.text
    assert response.json()["fofa"]["enabled"] is True
    stored = asyncio.run(raw_fofa_settings(session_maker))
    assert stored["enabled"] is True
    assert stored["key"] == "replacement-fofa-secret"
    assert "replacement-fofa-secret" not in response.text


def test_settings_health_check_tests_all_and_disables_failures_atomically(
    provider_api, monkeypatch
) -> None:
    client, session_maker = provider_api
    secrets = {
        "A": "health-secret-a",
        "B": "health/secret+b",
        "C": "health-secret-c",
    }
    fofa_secret = "health/fofa+secret"
    create_provider(client, "A", secrets["A"])
    create_provider(client, "B", secrets["B"])
    create_provider(client, "C", secrets["C"], enabled=False)
    saved_fofa = client.put(
        "/api/settings",
        json={
            "fofa": {
                "key": fofa_secret,
                "base_url": "https://fofa.info",
            }
        },
    )
    assert saved_fofa.status_code == 200, saved_fofa.text
    checked: list[str] = []

    async def fake_provider_probe(provider):
        checked.append(provider.name)
        if provider.name == "B":
            return {
                "ok": False,
                "latency_ms": 21,
                "model": provider.model,
                "protocol": provider.protocol,
                "error": f"rejected {quote(provider.api_key, safe='')}",
            }
        return {
            "ok": True,
            "latency_ms": 12,
            "model": provider.model,
            "protocol": provider.protocol,
            "error": "",
        }

    async def fake_fofa_probe(key, base_url):
        assert key == fofa_secret
        assert base_url == "https://fofa.info"
        return {
            "ok": False,
            "latency_ms": 8,
            "error": f"invalid {quote(key, safe='')}",
        }

    monkeypatch.setattr(settings_service, "probe_llm_provider", fake_provider_probe)
    monkeypatch.setattr(settings_service, "probe_fofa_key", fake_fofa_probe)

    response = client.post("/api/settings/health-check")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert checked == ["A", "B", "C"]
    assert [item["name"] for item in payload["provider_results"]] == ["A", "B", "C"]
    assert payload["provider_results"] == [
        {
            "name": "A",
            "ok": True,
            "latency_ms": 12,
            "model": "model-a",
            "protocol": "openai_chat",
            "error": "",
            "enabled": True,
            "auto_disabled": False,
            "stale": False,
        },
        {
            "name": "B",
            "ok": False,
            "latency_ms": 21,
            "model": "model-b",
            "protocol": "openai_chat",
            "error": "rejected <masked>",
            "enabled": False,
            "auto_disabled": True,
            "stale": False,
        },
        {
            "name": "C",
            "ok": True,
            "latency_ms": 12,
            "model": "model-c",
            "protocol": "openai_chat",
            "error": "",
            "enabled": False,
            "auto_disabled": False,
            "stale": False,
        },
    ]
    assert payload["fofa_result"] == {
        "name": "FOFA",
        "ok": False,
        "latency_ms": 8,
        "error": "invalid <masked>",
        "enabled": False,
        "auto_disabled": True,
        "stale": False,
    }
    assert [item["enabled"] for item in payload["providers"]] == [True, False, False]
    stored = asyncio.run(raw_providers(session_maker))
    assert [item["enabled"] for item in stored] == [True, False, False]
    stored_fofa = asyncio.run(raw_fofa_settings(session_maker))
    assert stored_fofa["enabled"] is False
    assert stored_fofa["key"] == fofa_secret
    for secret in [*secrets.values(), fofa_secret]:
        assert secret not in response.text
        assert quote(secret, safe="") not in response.text


def test_settings_health_check_does_not_disable_rotated_provider(
    provider_api, monkeypatch
) -> None:
    client, session_maker = provider_api
    create_provider(client, "Rotating", "old-health-key")
    client.put(
        "/api/settings",
        json={"fofa": {"key": "fofa-health-key", "base_url": "https://fofa.info"}},
    )

    async def rotate_then_fail(provider):
        async with session_maker() as session:
            row = await session.get(SystemSettings, "global")
            updated = [dict(item) for item in row.llm_providers]
            updated[0]["api_key"] = "rotated-health-key"
            row.llm_providers = updated
            await session.commit()
        return {
            "ok": False,
            "latency_ms": 5,
            "model": provider.model,
            "protocol": provider.protocol,
            "error": "old request failed",
        }

    async def successful_fofa(_key, _base_url):
        return {"ok": True, "latency_ms": 2, "error": ""}

    monkeypatch.setattr(settings_service, "probe_llm_provider", rotate_then_fail)
    monkeypatch.setattr(settings_service, "probe_fofa_key", successful_fofa)

    response = client.post("/api/settings/health-check")

    assert response.status_code == 200, response.text
    result = response.json()["provider_results"][0]
    assert result["ok"] is False
    assert result["stale"] is True
    assert result["auto_disabled"] is False
    assert result["enabled"] is True
    stored = asyncio.run(raw_providers(session_maker))[0]
    assert stored["api_key"] == "rotated-health-key"
    assert stored["enabled"] is True
    assert "rotated-health-key" not in response.text


def test_settings_health_check_uses_fofa_engine_key_fallback(
    provider_api, monkeypatch
) -> None:
    client, _session_maker = provider_api
    secret = "engine-only-fofa-secret"
    saved = client.put(
        "/api/settings",
        json={"engines": {"fofa": {"key": secret}}},
    )
    assert saved.status_code == 200, saved.text
    seen: dict[str, str] = {}

    async def successful_provider(provider):
        return {
            "ok": True,
            "latency_ms": 1,
            "model": provider.model,
            "protocol": provider.protocol,
            "error": "",
        }

    async def probe_engine_key(key, base_url):
        seen.update(key=key, base_url=base_url)
        return {
            "ok": key == secret,
            "latency_ms": 2,
            "error": "" if key == secret else "missing key",
        }

    monkeypatch.setattr(settings_service, "probe_llm_provider", successful_provider)
    monkeypatch.setattr(settings_service, "probe_fofa_key", probe_engine_key)

    response = client.post("/api/settings/health-check")

    assert response.status_code == 200, response.text
    assert seen == {"key": secret, "base_url": "https://fofa.info"}
    assert response.json()["fofa_result"]["ok"] is True
    assert response.json()["fofa_result"]["enabled"] is True
    assert secret not in response.text


def test_provider_dto_rejects_invalid_protocol_and_weight(provider_api) -> None:
    client, _session_maker = provider_api

    invalid_protocol = client.post(
        "/api/settings/llm-providers",
        json=provider_payload("BadProtocol", "secret", protocol="invalid"),
    )
    invalid_weight = client.post(
        "/api/settings/llm-providers",
        json=provider_payload("BadWeight", "secret", weight=0),
    )

    assert invalid_protocol.status_code == 422
    assert invalid_weight.status_code == 422


@pytest.mark.parametrize("name", ["order", "ORDER", "OpenAI/Azure", r"OpenAI\Azure"])
def test_provider_name_rejects_reserved_or_unaddressable_values(
    provider_api, name
) -> None:
    client, _session_maker = provider_api

    response = client.post(
        "/api/settings/llm-providers",
        json=provider_payload(name, "secret"),
    )

    assert response.status_code == 422


def test_update_rejects_rename_and_cannot_enable_keyless_draft(provider_api) -> None:
    client, _session_maker = provider_api
    create_provider(client, "Draft", "", enabled=False)

    renamed = client.put(
        "/api/settings/llm-providers/Draft",
        json={"name": "Renamed"},
    )
    enabled = client.put(
        "/api/settings/llm-providers/Draft",
        json={"enabled": True},
    )

    assert renamed.status_code == 422
    assert enabled.status_code == 422


def test_unknown_provider_operations_return_404(provider_api) -> None:
    client, _session_maker = provider_api

    assert client.put(
        "/api/settings/llm-providers/Missing",
        json={"enabled": False},
    ).status_code == 404
    assert client.delete("/api/settings/llm-providers/Missing").status_code == 404
    assert client.post("/api/settings/llm-providers/Missing/test").status_code == 404


def test_get_marks_legacy_fallback_read_only(provider_api, monkeypatch) -> None:
    client, _session_maker = provider_api
    secret = "legacy-token-VERYSECRET"
    monkeypatch.setenv("LLM_API_KEY", secret)

    response = client.get("/api/settings/llm-providers")

    assert response.status_code == 200
    assert response.json() == [{
        "name": "Legacy default",
        "base_url": "https://api.deepseek.com/v1",
        "api_key": settings_service._MASK_PLACEHOLDER,
        "api_key_set": True,
        "model": "deepseek-chat",
        "temperature": 0.3,
        "weight": 1,
        "protocol": "openai_chat",
        "enabled": True,
        "read_only": True,
        "source": "legacy",
    }]
    assert secret not in response.text


def test_order_rejects_unknown_and_case_insensitive_duplicates(provider_api) -> None:
    client, _session_maker = provider_api
    create_provider(client, "A", "secret-a")
    create_provider(client, "B", "secret-b")

    unknown = client.put(
        "/api/settings/llm-providers/order",
        json={"names": ["A", "Missing"]},
    )
    duplicate = client.put(
        "/api/settings/llm-providers/order",
        json={"names": ["A", "a"]},
    )

    assert unknown.status_code == 400
    assert duplicate.status_code == 400


def test_probe_sanitizes_arbitrary_saved_key_and_runs_chat_off_loop(monkeypatch, caplog) -> None:
    secret = "opaque/probe+token-VERYSECRET"
    encoded_secret = quote(secret, safe="")
    provider = LLMProviderConfig(**provider_payload("Probe", secret))
    caller_thread = threading.get_ident()
    seen: dict[str, object] = {}

    class FailingClient:
        def __init__(self, config):
            seen["config"] = config

        def chat(self, *args, **kwargs):
            seen["thread"] = threading.get_ident()
            raise RuntimeError(f"upstream rejected token {encoded_secret}")

    monkeypatch.setattr(settings_service, "LLMClient", FailingClient, raising=False)

    with caplog.at_level(logging.ERROR):
        result = asyncio.run(settings_service.probe_llm_provider(provider))

    assert result["ok"] is False
    assert result["model"] == provider.model
    assert result["protocol"] == provider.protocol
    assert seen["config"].api_key == secret
    assert seen["thread"] != caller_thread
    assert secret not in repr(result)
    assert encoded_secret not in repr(result)
    assert secret not in caplog.text


def test_invalid_stored_pool_returns_safe_recovery_error(provider_api) -> None:
    client, session_maker = provider_api
    secret = "corrupt-provider-secret-VERYSECRET"

    async def seed_invalid_provider() -> None:
        async with session_maker() as session:
            row = SystemSettings(
                id="global",
                llm_providers=[provider_payload("Broken", secret, protocol="invalid")],
            )
            session.add(row)
            await session.commit()

    asyncio.run(seed_invalid_provider())

    response = client.get("/api/settings/llm-providers")

    assert response.status_code == 422
    assert secret not in response.text
