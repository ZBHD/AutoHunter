from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, quote_plus

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import settings_service
from app.api import settings as settings_api
from app.api.dto import FofaKeyDTO
from app.db.models import Base, SystemSettings
from app.db.session import get_session
from app.fofa.router import FofaKeyStateChange, fofa_credential_fingerprint


@pytest.fixture
def fofa_key_api(tmp_path, monkeypatch):
    previous_cache = settings_service._cache
    previous_router_cache = settings_service._fofa_router_cache.copy()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'fofa-keys.db'}")
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
    app.include_router(settings_api.router)
    app.dependency_overrides[get_session] = override_session
    monkeypatch.setattr(settings_service, "SessionLocal", session_maker)
    monkeypatch.setattr(settings_service, "_cache", {
        "llm": {},
        "llm_providers": [],
        "fofa": {},
        "fofa_keys": [],
        "engines": {},
        "defaults": {},
    })
    settings_service._fofa_router_cache.clear()

    try:
        with TestClient(app) as client:
            yield client, session_maker
    finally:
        settings_service._fofa_router_cache.clear()
        settings_service._fofa_router_cache.update(previous_router_cache)
        settings_service._cache = previous_cache
        asyncio.run(engine.dispose())


async def _raw_row(session_maker) -> SystemSettings | None:
    async with session_maker() as session:
        return await session.get(SystemSettings, "global")


async def _raw_keys(session_maker) -> list[dict]:
    row = await _raw_row(session_maker)
    return list(row.fofa_keys or []) if row else []


async def _raw_fofa(session_maker) -> dict:
    row = await _raw_row(session_maker)
    return dict(row.fofa or {}) if row else {}


async def _seed(
    session_maker, *, keys: list[dict], fofa: dict | None = None
) -> None:
    async with session_maker() as session:
        row = await session.get(SystemSettings, "global")
        if row is None:
            row = SystemSettings(id="global")
            session.add(row)
        row.fofa_keys = keys
        if fofa is not None:
            row.fofa = fofa
        await session.commit()


def _key(name: str, key: str, **overrides) -> dict:
    value = {
        "name": name,
        "key": key,
        "base_url": "https://fofa.info",
        "enabled": True,
        "runtime_state": "ready",
        "failure_kind": "",
        "failure_count": 0,
        "cooldown_until": None,
    }
    value.update(overrides)
    return value


def _create(client: TestClient, name: str, key: str, **overrides) -> dict:
    body = {"name": name, "key": key, **overrides}
    response = client.post("/api/settings/fofa-keys", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _probe_result(*, category: str = "ok", error: str = "", **overrides) -> dict:
    value = {
        "ok": category == "ok",
        "latency_ms": 7,
        "error": error,
        "category": category,
        "resolved_url": "https://fofa.info/api/v1/info/my",
        "endpoint_mode": "root",
        "http_status": 200 if category == "ok" else 401,
    }
    value.update(overrides)
    return value


def test_fofa_key_crud_and_public_settings_never_return_plaintext(
    fofa_key_api,
) -> None:
    client, session_maker = fofa_key_api
    secret = "fofa/secret+VERYSECRET"

    created = _create(client, "Primary", secret)
    listed = client.get("/api/settings/fofa-keys")
    public = client.get("/api/settings")

    assert created["fofa_keys"][0]["key"] == settings_service._MASK_PLACEHOLDER
    assert created["fofa_keys"][0]["key_set"] is True
    assert listed.status_code == 200
    assert listed.json() == {"fofa_keys": created["fofa_keys"]}
    assert public.json()["fofa_keys"] == created["fofa_keys"]
    for response in (listed, public):
        assert secret not in response.text
        assert quote(secret, safe="") not in response.text
        assert quote_plus(secret, safe="") not in response.text
    assert asyncio.run(_raw_keys(session_maker))[0]["key"] == secret

    deleted = client.delete("/api/settings/fofa-keys/Primary")
    assert deleted.status_code == 200
    assert deleted.json() == {"fofa_keys": []}


@pytest.mark.parametrize(
    "body",
    [
        {"name": "order", "key": "secret"},
        {"name": "bad/name", "key": "secret"},
        {"name": "bad\\name", "key": "secret"},
        {"name": "bad?name", "key": "secret"},
        {"name": "bad#name", "key": "secret"},
        {"name": "bad\x01name", "key": "secret"},
        {"name": "Bad URL", "key": "secret", "base_url": "ftp://fofa.info"},
        {"name": "Query", "key": "secret", "base_url": "https://fofa.info/?x=1"},
        {"name": "Creds", "key": "secret", "base_url": "https://u:p@fofa.info"},
        {"name": "Port", "key": "secret", "base_url": "https://fofa.info:bad"},
        {"name": "Keyless", "enabled": True},
        {"name": "Masked", "key": settings_service._MASK_PLACEHOLDER},
    ],
)
def test_create_rejects_invalid_fofa_key_values(fofa_key_api, body) -> None:
    client, _session_maker = fofa_key_api
    assert client.post("/api/settings/fofa-keys", json=body).status_code == 422


def test_fofa_key_dto_rejects_invalid_port() -> None:
    with pytest.raises(ValueError):
        FofaKeyDTO(
            name="Port", key="secret", base_url="https://fofa.info:bad"
        )


def test_duplicate_names_are_case_insensitive_and_update_cannot_rename(
    fofa_key_api,
) -> None:
    client, _session_maker = fofa_key_api
    _create(client, " Primary ", "secret-a")

    duplicate = client.post(
        "/api/settings/fofa-keys", json={"name": "PRIMARY", "key": "secret-b"}
    )
    renamed = client.put(
        "/api/settings/fofa-keys/Primary", json={"name": "Renamed"}
    )

    assert duplicate.status_code == 409
    assert renamed.status_code == 422


def test_masked_update_preserves_key_and_replacement_resets_runtime_state(
    fofa_key_api,
) -> None:
    client, session_maker = fofa_key_api
    old_secret = "old-secret"
    asyncio.run(
        _seed(
            session_maker,
            keys=[
                _key(
                    "Primary",
                    old_secret,
                    runtime_state="rate_limited",
                    failure_kind="rate_limit",
                    failure_count=4,
                    cooldown_until="2026-07-17T00:00:00Z",
                )
            ],
            fofa={"active_key_name": "Primary"},
        )
    )

    masked = client.put(
        "/api/settings/fofa-keys/Primary",
        json={"key": settings_service._MASK_PLACEHOLDER, "enabled": False},
    )
    assert masked.status_code == 200, masked.text
    assert asyncio.run(_raw_keys(session_maker))[0]["key"] == old_secret

    replacement = client.put(
        "/api/settings/fofa-keys/Primary",
        json={"key": "replacement-secret", "base_url": "https://mirror.example/api.php"},
    )
    assert replacement.status_code == 200, replacement.text
    item = replacement.json()["fofa_keys"][0]
    assert item["enabled"] is False
    assert item["runtime_state"] == "ready"
    assert item["failure_kind"] == ""
    assert item["failure_count"] == 0
    assert item["cooldown_until"] is None


def test_active_key_moves_on_disable_and_delete_but_survives_reorder(
    fofa_key_api,
) -> None:
    client, session_maker = fofa_key_api
    _create(client, "A", "secret-a")
    _create(client, "B", "secret-b")
    _create(client, "C", "secret-c")
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "A"

    disabled = client.put("/api/settings/fofa-keys/A", json={"enabled": False})
    assert disabled.status_code == 200
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "B"

    ordered = client.put(
        "/api/settings/fofa-keys/order", json={"names": ["C", "B", "A"]}
    )
    assert [item["name"] for item in ordered.json()["fofa_keys"]] == ["C", "B", "A"]
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "B"

    deleted = client.delete("/api/settings/fofa-keys/B")
    assert deleted.status_code == 200
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "C"
    assert [item["is_active"] for item in deleted.json()["fofa_keys"]] == [True, False]

    bad_order = client.put(
        "/api/settings/fofa-keys/order", json={"names": ["C", "c"]}
    )
    assert bad_order.status_code == 400


def test_legacy_key_is_read_only_and_unknown_names_return_404(
    fofa_key_api, monkeypatch
) -> None:
    client, _session_maker = fofa_key_api
    secret = "legacy-fofa-secret"
    monkeypatch.setenv("FOFA_KEY", secret)

    listed = client.get("/api/settings/fofa-keys")
    item = listed.json()["fofa_keys"][0]

    assert item["name"] == "Legacy Key"
    assert item["read_only"] is True
    assert item["source"] == "legacy"
    assert item["key"] == settings_service._MASK_PLACEHOLDER
    assert secret not in listed.text
    assert client.put(
        "/api/settings/fofa-keys/Legacy%20Key", json={"enabled": False}
    ).status_code == 400
    assert client.delete("/api/settings/fofa-keys/Legacy%20Key").status_code == 400
    assert client.post("/api/settings/fofa-keys/Legacy%20Key/test").status_code == 400
    assert client.put(
        "/api/settings/fofa-keys/Missing", json={"enabled": False}
    ).status_code == 404


def test_legacy_key_can_be_adopted_then_managed_without_returning_after_delete(
    fofa_key_api, monkeypatch
) -> None:
    client, session_maker = fofa_key_api
    secret = "legacy-adopt-secret"
    monkeypatch.setenv("FOFA_KEY", secret)
    monkeypatch.setenv("FOFA_BASE_URL", "http://legacy.example/api.php")

    adopted = client.post("/api/settings/fofa-keys/legacy/adopt")
    assert adopted.status_code == 200, adopted.text
    item = adopted.json()["fofa_keys"][0]
    assert item["name"] == "Legacy Key"
    assert item["source"] == "database"
    assert item["read_only"] is False
    assert item["base_url"] == "http://legacy.example/api.php"
    assert secret not in adopted.text

    edited = client.put(
        "/api/settings/fofa-keys/Legacy%20Key",
        json={"base_url": "https://managed.example/api.php"},
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["fofa_keys"][0]["base_url"] == "https://managed.example/api.php"

    deleted = client.delete("/api/settings/fofa-keys/Legacy%20Key")
    assert deleted.status_code == 200, deleted.text
    assert deleted.json() == {"fofa_keys": []}
    assert client.get("/api/settings/fofa-keys").json() == {"fofa_keys": []}
    assert client.get("/api/settings").json()["fofa_keys"] == []
    assert asyncio.run(_raw_keys(session_maker)) == []

    async def healthy_provider(_provider):
        return {
            "ok": True,
            "latency_ms": 1,
            "model": "test",
            "protocol": "openai_chat",
            "error": "",
        }

    monkeypatch.setattr(settings_service, "probe_llm_provider", healthy_provider)
    health = client.post("/api/settings/health-check")
    assert health.status_code == 200, health.text
    assert "fofa_result" not in health.json()
    assert health.json()["fofa_results"] == []


def test_malformed_stored_pool_rejects_reads_and_mutations_without_data_loss(
    fofa_key_api,
) -> None:
    client, session_maker = fofa_key_api
    secret = "corrupt-fofa-secret-VERYSECRET"
    original = [{"name": "Broken", "key": secret, "base_url": "not-a-url"}]
    asyncio.run(_seed(session_maker, keys=original))

    listed = client.get("/api/settings/fofa-keys")
    changed = client.post(
        "/api/settings/fofa-keys", json={"name": "Good", "key": "good-secret"}
    )

    assert listed.status_code == 422
    assert changed.status_code == 422
    assert secret not in listed.text + changed.text
    assert asyncio.run(_raw_keys(session_maker)) == original


def test_successful_single_probe_clears_block_but_preserves_manual_disable(
    fofa_key_api, monkeypatch
) -> None:
    client, session_maker = fofa_key_api
    asyncio.run(
        _seed(
            session_maker,
            keys=[
                _key(
                    "Paused",
                    "paused-secret",
                    enabled=False,
                    runtime_state="auth_invalid",
                    failure_kind="auth",
                    failure_count=2,
                )
            ],
        )
    )

    async def successful_probe(_key, _base_url):
        return _probe_result()

    monkeypatch.setattr(settings_service, "probe_fofa_key", successful_probe)
    response = client.post("/api/settings/fofa-keys/Paused/test")

    assert response.status_code == 200, response.text
    item = response.json()["fofa_key"]
    assert item["enabled"] is False
    assert item["runtime_state"] == "ready"
    assert item["failure_count"] == 0
    assert item["stale"] is False
    assert item["resolved_url"].endswith("/api/v1/info/my")


def test_single_probe_uses_compatible_placeholder_for_url_encoded_key(
    fofa_key_api, monkeypatch
) -> None:
    client, _session_maker = fofa_key_api
    secret = "Opaque/Probe+VERY SECRET"
    _create(client, "Probe", secret)
    variants = (
        secret,
        quote(secret, safe="").lower(),
        quote_plus(secret, safe="").lower(),
    )

    async def failed(_key, _base_url):
        return _probe_result(
            category="transient", error="rejected " + " ".join(variants)
        )

    monkeypatch.setattr(settings_service, "probe_fofa_key", failed)
    response = client.post("/api/settings/fofa-keys/Probe/test")

    assert response.status_code == 200
    for variant in variants:
        assert variant.casefold() not in response.text.casefold()
    assert response.json()["fofa_key"]["error"] == (
        "rejected <masked> <masked> <masked>"
    )


def test_probe_failure_categories_update_runtime_state_without_manual_disable(
    fofa_key_api, monkeypatch
) -> None:
    client, _session_maker = fofa_key_api
    _create(client, "Probe", "probe-secret")
    category = "auth"

    async def probe(_key, _base_url):
        return _probe_result(category=category, error=f"{category} rejected")

    monkeypatch.setattr(settings_service, "probe_fofa_key", probe)

    item = client.post("/api/settings/fofa-keys/Probe/test").json()["fofa_key"]
    assert item["enabled"] is True
    assert item["runtime_state"] == "auth_invalid"
    assert item["failure_kind"] == "auth"

    category = "rate_limit"
    delays = []
    for _ in range(6):
        item = client.post("/api/settings/fofa-keys/Probe/test").json()["fofa_key"]
        until = datetime.fromisoformat(item["cooldown_until"].replace("Z", "+00:00"))
        delays.append(round((until - datetime.now(timezone.utc)).total_seconds(), -1))
    assert item["runtime_state"] == "rate_limited"
    assert item["failure_count"] == 6
    assert delays == [60, 120, 240, 480, 600, 600]

    category = "daily_limit"
    for _ in range(11):
        item = client.post("/api/settings/fofa-keys/Probe/test").json()["fofa_key"]
    assert item["runtime_state"] == "daily_cooldown"
    item = client.post("/api/settings/fofa-keys/Probe/test").json()["fofa_key"]
    assert item["runtime_state"] == "daily_suspended"
    assert item["failure_count"] == 12


@pytest.mark.parametrize("category", ["endpoint", "transient"])
def test_endpoint_and_transient_probe_failures_preserve_ready_state(
    fofa_key_api, monkeypatch, category
) -> None:
    client, _session_maker = fofa_key_api
    _create(client, "Probe", "probe-secret")

    async def failed(_key, _base_url):
        return _probe_result(
            category=category,
            error="temporary failure",
            http_status=404 if category == "endpoint" else 503,
        )

    monkeypatch.setattr(settings_service, "probe_fofa_key", failed)
    item = client.post("/api/settings/fofa-keys/Probe/test").json()["fofa_key"]

    assert item["runtime_state"] == "ready"
    assert item["failure_kind"] == "transient"
    assert item["failure_count"] == 1
    assert item["auto_blocked"] is False


def test_probe_uses_shared_endpoint_transport_and_returns_metadata(monkeypatch) -> None:
    seen: list[dict] = []

    class Response:
        status_code = 200
        headers = {}

        @staticmethod
        def json():
            return {"error": False, "results": []}

    class Result:
        response = Response()
        resolved_url = "https://mirror.example/api.php"
        endpoint_mode = "exact"
        http_status = 200
        category = "ok"
        error = None

    async def request_async(key, base_url, **kwargs):
        seen.append({"key": key, "base_url": base_url, **kwargs})
        return Result()

    monkeypatch.setattr(settings_service.fofa_endpoints, "request_async", request_async)
    result = asyncio.run(
        settings_service.probe_fofa_key("probe-secret", "https://mirror.example/api.php")
    )

    assert seen[0]["purpose"] == "search"
    assert seen[0]["params"]["size"] == "1"
    assert result == {
        "ok": True,
        "latency_ms": result["latency_ms"],
        "error": "",
        "category": "ok",
        "resolved_url": "https://mirror.example/api.php",
        "endpoint_mode": "exact",
        "http_status": 200,
    }


@pytest.mark.parametrize("category,status", [("auth", 401), ("rate_limit", 429)])
def test_probe_preserves_transport_category_for_non_json_errors(
    monkeypatch, category, status
) -> None:
    class Response:
        status_code = status
        headers = {}
        text = "upstream error"

        @staticmethod
        def json():
            raise ValueError("not json")

    class Result:
        response = Response()
        resolved_url = "https://fofa.info/api/v1/info/my"
        endpoint_mode = "root"
        http_status = status
        error = None

    Result.category = category

    async def request_async(*_args, **_kwargs):
        return Result()

    monkeypatch.setattr(settings_service.fofa_endpoints, "request_async", request_async)
    result = asyncio.run(
        settings_service.probe_fofa_key("probe-secret", "https://fofa.info")
    )

    assert result["category"] == category


def test_one_click_health_checks_every_pool_key_in_order_with_limit_three(
    fofa_key_api, monkeypatch
) -> None:
    client, session_maker = fofa_key_api
    keys = [
        _key("A", "secret-a"),
        _key("B", "secret-b", runtime_state="auth_invalid", failure_kind="auth"),
        _key("C", "secret-c", enabled=False),
        _key("D", "secret-d", runtime_state="daily_cooldown", failure_kind="daily_limit"),
    ]
    asyncio.run(_seed(session_maker, keys=keys, fofa={"active_key_name": "A"}))
    active = 0
    peak = 0

    async def probe(key, base_url):
        nonlocal active, peak
        assert base_url == "https://fofa.info"
        active += 1
        peak = max(peak, active)
        await asyncio.sleep(0.02)
        active -= 1
        return _probe_result(
            resolved_url=f"https://fofa.info/api/v1/info/my?probe={key[-1]}"
        )

    async def provider_probe(provider):
        return {
            "ok": True,
            "latency_ms": 1,
            "model": provider.model,
            "protocol": provider.protocol,
            "error": "",
        }

    monkeypatch.setattr(settings_service, "probe_fofa_key", probe)
    monkeypatch.setattr(settings_service, "probe_llm_provider", provider_probe)
    response = client.post("/api/settings/health-check")

    assert response.status_code == 200, response.text
    results = response.json()["fofa_results"]
    assert [item["name"] for item in results] == ["A", "B", "C", "D"]
    assert peak == 3
    assert all(item["runtime_state"] == "ready" for item in results)
    assert results[2]["enabled"] is False
    assert all(item["stale"] is False for item in results)
    assert [item["resolved_url"][-1] for item in results] == ["a", "b", "c", "d"]
    assert "fofa_result" not in response.json()


def test_one_click_stale_probe_does_not_overwrite_replaced_key_or_leak_error(
    fofa_key_api, monkeypatch
) -> None:
    client, session_maker = fofa_key_api
    old_secret = "old/secret+VERYSECRET"
    replacement = "replacement-secret"
    asyncio.run(_seed(session_maker, keys=[_key("Rotating", old_secret)]))

    async def rotate_then_fail(key, _base_url):
        assert key == old_secret
        await _seed(session_maker, keys=[_key("Rotating", replacement)])
        return _probe_result(
            category="auth",
            error=f"rejected {key} {quote(key, safe='')} {quote_plus(key, safe='')}",
        )

    async def provider_probe(provider):
        return {
            "ok": True,
            "latency_ms": 1,
            "model": provider.model,
            "protocol": provider.protocol,
            "error": "",
        }

    monkeypatch.setattr(settings_service, "probe_fofa_key", rotate_then_fail)
    monkeypatch.setattr(settings_service, "probe_llm_provider", provider_probe)
    response = client.post("/api/settings/health-check")

    result = response.json()["fofa_results"][0]
    assert result["stale"] is True
    assert result["runtime_state"] == "ready"
    stored = asyncio.run(_raw_keys(session_maker))[0]
    assert stored["key"] == replacement
    assert stored["runtime_state"] == "ready"
    assert old_secret not in response.text
    assert quote(old_secret, safe="") not in response.text
    assert quote_plus(old_secret, safe="") not in response.text
    assert replacement not in response.text


def test_one_click_health_redacts_case_varied_encoded_key_variants(
    fofa_key_api, monkeypatch
) -> None:
    client, session_maker = fofa_key_api
    secret = "Health/Probe+VERY SECRET"
    variants = (
        secret,
        quote(secret, safe="").lower(),
        quote_plus(secret, safe="").lower(),
    )
    asyncio.run(_seed(session_maker, keys=[_key("Health", secret)]))

    async def failed_probe(_key, _base_url):
        return _probe_result(
            category="transient", error="failed " + " ".join(variants)
        )

    async def successful_provider(provider):
        return {
            "ok": True,
            "latency_ms": 1,
            "model": provider.model,
            "protocol": provider.protocol,
            "error": "",
        }

    monkeypatch.setattr(settings_service, "probe_fofa_key", failed_probe)
    monkeypatch.setattr(settings_service, "probe_llm_provider", successful_provider)
    response = client.post("/api/settings/health-check")

    assert response.status_code == 200
    for variant in variants:
        assert variant.casefold() not in response.text.casefold()
    assert response.json()["fofa_results"][0]["error"] == (
        "failed <masked> <masked> <masked>"
    )


def test_persist_fofa_key_state_updates_runtime_and_valid_active_only(
    fofa_key_api,
) -> None:
    _client, session_maker = fofa_key_api
    secret = "state-secret-a"
    base_url = "https://a.example/api.php"
    cooldown = datetime(2026, 7, 16, 8, 0, tzinfo=timezone.utc)
    asyncio.run(
        _seed(
            session_maker,
            keys=[
                _key("A", secret, base_url=base_url),
                _key("B", "state-secret-b"),
            ],
            fofa={"active_key_name": "A"},
        )
    )
    change = FofaKeyStateChange(
        name="A",
        base_url=base_url,
        runtime_state="rate_limited",
        failure_kind="rate_limit",
        failure_count=3,
        cooldown_until=cooldown,
        active_key_name="B",
        credential_fingerprint=fofa_credential_fingerprint(
            "A", secret, base_url
        ),
        revision=4,
    )

    asyncio.run(settings_service._persist_fofa_key_state(change))

    stored = asyncio.run(_raw_keys(session_maker))
    assert stored[0] == {
        "name": "A",
        "key": secret,
        "base_url": base_url,
        "enabled": True,
        "runtime_state": "rate_limited",
        "failure_kind": "rate_limit",
        "failure_count": 3,
        "cooldown_until": "2026-07-16T08:00:00Z",
    }
    assert stored[1] == _key("B", "state-secret-b")
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "B"
    assert secret not in repr(settings_service.public_settings_view())

    invalid_active = FofaKeyStateChange(
        **{**change.__dict__, "active_key_name": "Missing", "revision": 5}
    )
    asyncio.run(settings_service._persist_fofa_key_state(invalid_active))
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "B"


def test_persist_fofa_key_state_ignores_stale_credential_fingerprint(
    fofa_key_api,
) -> None:
    _client, session_maker = fofa_key_api
    old_secret = "old-state-secret"
    replacement = "replacement-state-secret"
    base_url = "https://fofa.info"
    asyncio.run(
        _seed(
            session_maker,
            keys=[_key("A", replacement)],
            fofa={"active_key_name": "A"},
        )
    )
    change = FofaKeyStateChange(
        name="A",
        base_url=base_url,
        runtime_state="auth_invalid",
        failure_kind="auth",
        failure_count=1,
        cooldown_until=None,
        active_key_name="A",
        credential_fingerprint=fofa_credential_fingerprint(
            "A", old_secret, base_url
        ),
    )

    asyncio.run(settings_service._persist_fofa_key_state(change))

    assert asyncio.run(_raw_keys(session_maker)) == [_key("A", replacement)]
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "A"


def test_fofa_state_callback_schedules_persistence_on_captured_loop(
    monkeypatch,
) -> None:
    change = FofaKeyStateChange(
        name="A",
        base_url="https://fofa.info",
        runtime_state="auth_invalid",
        failure_kind="auth",
        failure_count=1,
        cooldown_until=None,
        active_key_name="B",
        credential_fingerprint="fingerprint",
    )
    persisted: list[FofaKeyStateChange] = []

    async def scenario() -> None:
        completed = asyncio.Event()
        loop = asyncio.get_running_loop()

        async def fake_persist(value: FofaKeyStateChange) -> None:
            assert asyncio.get_running_loop() is loop
            persisted.append(value)
            completed.set()

        monkeypatch.setattr(
            settings_service, "_persist_fofa_key_state", fake_persist
        )
        callback = settings_service._fofa_state_callback(loop)
        await asyncio.to_thread(callback, change)
        await asyncio.wait_for(completed.wait(), timeout=1)

    asyncio.run(scenario())
    assert persisted == [change]


def test_fofa_state_callback_ignores_closed_loop_without_leaking(
    monkeypatch, caplog
) -> None:
    secret = "callback-secret-VERYSECRET"
    called = False

    async def fake_persist(_change: FofaKeyStateChange) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(settings_service, "_persist_fofa_key_state", fake_persist)
    loop = asyncio.new_event_loop()
    loop.close()
    callback = settings_service._fofa_state_callback(loop)
    change = FofaKeyStateChange(
        name="A",
        base_url=f"https://fofa.info/{secret}",
        runtime_state="ready",
        failure_kind="",
        failure_count=0,
        cooldown_until=None,
        active_key_name="A",
        credential_fingerprint="fingerprint",
    )

    with caplog.at_level("WARNING"):
        callback(change)

    assert called is False
    assert secret not in caplog.text


def test_fofa_state_callback_drops_older_revision_after_newer_persisted(
    fofa_key_api, monkeypatch
) -> None:
    _client, session_maker = fofa_key_api
    secret = "revision-secret-a"
    base_url = "https://fofa.info"
    asyncio.run(
        _seed(
            session_maker,
            keys=[_key("A", secret), _key("B", "revision-secret-b")],
            fofa={"active_key_name": "A"},
        )
    )
    fingerprint = fofa_credential_fingerprint("A", secret, base_url)
    newer = FofaKeyStateChange(
        name="A",
        base_url=base_url,
        runtime_state="auth_invalid",
        failure_kind="auth",
        failure_count=2,
        cooldown_until=None,
        active_key_name="B",
        credential_fingerprint=fingerprint,
        revision=2,
    )
    older = FofaKeyStateChange(
        name="A",
        base_url=base_url,
        runtime_state="ready",
        failure_kind="",
        failure_count=0,
        cooldown_until=None,
        active_key_name="A",
        credential_fingerprint=fingerprint,
        revision=1,
    )
    original_persist = settings_service._persist_fofa_key_state

    async def scenario() -> None:
        completed = asyncio.Event()
        persisted_revisions: list[int] = []

        async def observed(change: FofaKeyStateChange):
            result = await original_persist(change)
            persisted_revisions.append(change.revision)
            completed.set()
            return result

        monkeypatch.setattr(
            settings_service, "_persist_fofa_key_state", observed
        )
        callback = settings_service._fofa_state_callback(asyncio.get_running_loop())
        await asyncio.to_thread(callback, newer)
        await asyncio.wait_for(completed.wait(), timeout=1)
        await asyncio.to_thread(callback, older)
        await asyncio.sleep(0.05)
        assert persisted_revisions == [2]

    asyncio.run(scenario())
    stored = asyncio.run(_raw_keys(session_maker))
    assert stored[0]["runtime_state"] == "auth_invalid"
    assert stored[0]["failure_count"] == 2
    assert asyncio.run(_raw_fofa(session_maker))["active_key_name"] == "B"


def test_public_active_skips_runtime_blocked_and_future_cooldown_keys(
    fofa_key_api,
) -> None:
    client, session_maker = fofa_key_api
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    asyncio.run(
        _seed(
            session_maker,
            keys=[
                _key(
                    "Auth",
                    "secret-auth",
                    runtime_state="auth_invalid",
                    failure_kind="auth",
                    failure_count=1,
                ),
                _key(
                    "Daily",
                    "secret-daily",
                    runtime_state="daily_suspended",
                    failure_kind="daily_limit",
                    failure_count=12,
                ),
                _key(
                    "Cooling",
                    "secret-cooling",
                    runtime_state="rate_limited",
                    failure_kind="rate_limit",
                    failure_count=1,
                    cooldown_until=future.isoformat(),
                ),
                _key("Ready", "secret-ready"),
            ],
            fofa={"active_key_name": "Auth"},
        )
    )

    listed = client.get("/api/settings/fofa-keys").json()["fofa_keys"]
    public = client.get("/api/settings").json()["fofa_keys"]

    assert [item["name"] for item in listed if item["is_active"]] == ["Ready"]
    assert [item["name"] for item in public if item["is_active"]] == ["Ready"]


def test_expired_cooldown_can_be_active_and_all_blocked_has_no_active(
    fofa_key_api,
) -> None:
    client, session_maker = fofa_key_api
    past = datetime.now(timezone.utc) - timedelta(minutes=1)
    asyncio.run(
        _seed(
            session_maker,
            keys=[
                _key(
                    "Expired",
                    "secret-expired",
                    runtime_state="rate_limited",
                    failure_kind="rate_limit",
                    failure_count=1,
                    cooldown_until=past.isoformat(),
                ),
                _key("Ready", "secret-ready"),
            ],
            fofa={"active_key_name": "Expired"},
        )
    )

    listed = client.get("/api/settings/fofa-keys").json()["fofa_keys"]
    assert [item["name"] for item in listed if item["is_active"]] == ["Expired"]

    asyncio.run(
        _seed(
            session_maker,
            keys=[
                _key(
                    "Auth",
                    "secret-auth",
                    runtime_state="auth_invalid",
                    failure_kind="auth",
                ),
                _key("Disabled", "secret-disabled", enabled=False),
            ],
            fofa={"active_key_name": "Auth"},
        )
    )
    blocked = client.get("/api/settings/fofa-keys").json()["fofa_keys"]
    public_blocked = client.get("/api/settings").json()["fofa_keys"]
    assert not any(item["is_active"] for item in blocked)
    assert not any(item["is_active"] for item in public_blocked)
