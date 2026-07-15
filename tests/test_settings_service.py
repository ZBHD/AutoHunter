from __future__ import annotations

import asyncio
import copy

import pytest
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import LLMProviderConfig
from app.db.models import Base, SystemSettings, Task
from app import settings_service


@pytest.fixture(autouse=True)
def restore_settings_cache():
    original = copy.deepcopy(settings_service._cache)
    yield
    settings_service._cache = original


def set_cache(*, providers=None, legacy=None, fofa=None, engines=None, fofa_keys=None) -> None:
    settings_service._cache = {
        "llm": legacy or {},
        "llm_providers": providers if providers is not None else [],
        "fofa": fofa or {},
        "fofa_keys": fofa_keys if fofa_keys is not None else [],
        "engines": engines or {},
        "defaults": {},
        "updated_at": None,
    }


def provider_dict(name: str, **overrides):
    data = {
        "name": name,
        "base_url": f"https://{name.lower()}.example/v1",
        "api_key": f"sk-{name.lower()}-secret-123456",
        "model": f"model-{name.lower()}",
        "temperature": 0.3,
        "weight": 5,
        "protocol": "openai_chat",
        "enabled": True,
    }
    data.update(overrides)
    return data


def fofa_key_dict(name: str, key: str, **overrides):
    data = {
        "name": name,
        "key": key,
        "enabled": True,
        "runtime_state": "ready",
        "failure_kind": "",
        "failure_count": 0,
        "cooldown_until": None,
    }
    data.update(overrides)
    return data


@pytest.mark.parametrize(
    ("patch", "message"),
    [
        ({"name": "  "}, "name"),
        ({"base_url": "file:///tmp/model"}, "base_url"),
        ({"base_url": "https://user:password@llm.example/v1"}, "base_url"),
        ({"base_url": "https://llm.example/v1?api_key=secret"}, "base_url"),
        ({"base_url": "https://llm.example:bad/v1"}, "base_url"),
        ({"base_url": "https://llm.example:99999/v1"}, "base_url"),
        ({"model": ""}, "model"),
        ({"protocol": "made_up"}, "protocol"),
        ({"temperature": 2.1}, "temperature"),
        ({"weight": 0}, "weight"),
    ],
)
def test_provider_configuration_is_validated(patch, message) -> None:
    data = provider_dict("Primary")
    data.update(patch)

    with pytest.raises(ValidationError) as exc_info:
        LLMProviderConfig(**data)

    assert message in str(exc_info.value)


def test_global_pool_wins_over_legacy_environment(monkeypatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "sk-env-secret-123456")
    set_cache(providers=[provider_dict("Pool")])

    providers = settings_service.resolve_llm_providers()

    assert [item.name for item in providers] == ["Pool"]
    assert providers[0].api_key == "sk-pool-secret-123456"


def test_empty_pool_falls_back_to_legacy_environment(monkeypatch) -> None:
    monkeypatch.setenv("LLM_BASE_URL", "https://legacy.example/v1")
    monkeypatch.setenv("LLM_API_KEY", "sk-legacy-secret-123456")
    monkeypatch.setenv("LLM_MODEL", "legacy-model")
    monkeypatch.setenv("LLM_PROTOCOL", "openai_responses")
    set_cache()

    providers = settings_service.resolve_llm_providers()

    assert len(providers) == 1
    assert providers[0].name == "Legacy default"
    assert providers[0].protocol == "openai_responses"
    assert providers[0].api_key == "sk-legacy-secret-123456"


def test_nonempty_disabled_pool_does_not_fall_back(monkeypatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "sk-env-secret-123456")
    set_cache(providers=[provider_dict("Disabled", enabled=False)])

    providers = settings_service.resolve_llm_providers()

    assert len(providers) == 1
    assert providers[0].name == "Disabled"
    assert providers[0].enabled is False
    assert settings_service.llm_router_for_task_optional() is None


def test_saved_fofa_settings_drive_runtime_resolution(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "env-fofa-key")
    set_cache(
        fofa={
            "key": "saved-fofa-key",
            "base_url": "https://saved-fofa.example",
            "enabled": True,
            "max_pages": 7,
            "page_size": 25,
            "default_intent_mode": "syntax",
        },
        engines={
            "fofa": {
                "key": "engine-fofa-key",
                "base_url": "https://engine-fofa.example",
            }
        },
    )

    assert settings_service.resolve_fofa_key() == "saved-fofa-key"
    assert settings_service.resolve_fofa_base_url() == "https://saved-fofa.example"
    assert settings_service.resolve_fofa_defaults() == {
        "engine": "fofa",
        "key": "saved-fofa-key",
        "base_url": "https://saved-fofa.example",
        "max_pages": 7,
        "page_size": 25,
        "intent_mode": "syntax",
    }


def test_empty_fofa_pool_uses_legacy_key(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "legacy-secret")
    set_cache(fofa_keys=[], fofa={})

    keys = settings_service.resolve_fofa_keys()

    assert [(item.name, item.key) for item in keys] == [("Legacy Key", "legacy-secret")]


def test_fofa_pool_preserves_per_key_base_urls() -> None:
    set_cache(
        fofa_keys=[
            fofa_key_dict("Primary", "pool-secret", base_url="https://a.example/api"),
            fofa_key_dict("Secondary", "pool-secret-2", base_url="http://b.example:8080"),
        ]
    )

    keys = settings_service.resolve_fofa_keys()

    assert [(item.name, item.base_url) for item in keys] == [
        ("Primary", "https://a.example/api"),
        ("Secondary", "http://b.example:8080"),
    ]


def test_task_override_uses_task_base_url() -> None:
    set_cache(
        fofa={"base_url": "https://global.example"},
        fofa_keys=[fofa_key_dict("Primary", "pool-secret")],
    )
    task = make_task({})
    task.fofa_config = {
        "key": "task-secret",
        "base_url": "http://task.example:8080/private/api",
    }

    keys = settings_service.resolve_fofa_keys(task)

    assert [(item.name, item.key, item.base_url) for item in keys] == [
        ("Task override", "task-secret", "http://task.example:8080/private/api")
    ]


def test_task_override_base_url_falls_back_to_legacy_base_url() -> None:
    set_cache(
        fofa={"base_url": "https://global.example"},
        fofa_keys=[fofa_key_dict("Primary", "pool-secret")],
    )
    task = make_task({})
    task.fofa_config = {"key": "task-secret"}

    keys = settings_service.resolve_fofa_keys(task)

    assert [(item.name, item.key, item.base_url) for item in keys] == [
        ("Task override", "task-secret", "https://global.example")
    ]


def test_legacy_fofa_base_url_precedence(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_BASE_URL", "https://env.example/api")
    set_cache(
        fofa={"key": "legacy-secret", "base_url": "https://saved.example"},
        engines={"fofa": {"base_url": "https://engine.example/api"}},
    )

    assert settings_service.resolve_fofa_keys()[0].base_url == "https://saved.example"

    set_cache(fofa={"key": "legacy-secret"})
    assert settings_service.resolve_fofa_keys()[0].base_url == "https://env.example/api"

    monkeypatch.delenv("FOFA_BASE_URL", raising=False)
    assert settings_service.resolve_fofa_keys()[0].base_url == "https://fofa.info"


def test_legacy_fofa_base_url_environment_wins_old_engine_fallback(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_BASE_URL", "https://env.example/api")
    set_cache(
        fofa={"key": "legacy-secret"},
        engines={"fofa": {"base_url": "https://engine.example/api"}},
    )

    assert settings_service.resolve_fofa_keys()[0].base_url == "https://env.example/api"


def test_legacy_fofa_base_url_keeps_old_engine_compatibility_fallback(monkeypatch) -> None:
    monkeypatch.delenv("FOFA_BASE_URL", raising=False)
    set_cache(
        fofa={"key": "legacy-secret"},
        engines={"fofa": {"base_url": "https://engine.example/api"}},
    )

    assert settings_service.resolve_fofa_keys()[0].base_url == "https://engine.example/api"


def test_fofa_legacy_resolution_prefers_saved_fofa_then_engine_then_environment(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "env-secret")
    set_cache(
        fofa={"key": "saved-fofa-secret"},
        engines={"fofa": {"key": "engine-secret"}},
    )

    keys = settings_service.resolve_fofa_keys()

    assert [(item.name, item.key) for item in keys] == [("Legacy Key", "saved-fofa-secret")]

    set_cache(fofa={}, engines={"fofa": {"key": "engine-secret"}})
    assert settings_service.resolve_fofa_keys()[0].key == "engine-secret"


def test_nonempty_fofa_pool_wins_over_legacy_key(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "legacy-secret")
    set_cache(fofa_keys=[fofa_key_dict("Primary", "pool-secret")])

    keys = settings_service.resolve_fofa_keys()

    assert [(item.name, item.key) for item in keys] == [("Primary", "pool-secret")]
    assert keys[0].base_url == "https://fofa.info"


def test_nonempty_disabled_fofa_pool_does_not_fallback(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "legacy-secret")
    set_cache(fofa_keys=[fofa_key_dict("Disabled", "pool-secret", enabled=False)])

    keys = settings_service.resolve_fofa_keys()

    assert [(item.name, item.key) for item in keys] == [("Disabled", "pool-secret")]
    assert keys[0].enabled is False


def test_task_fofa_key_override_wins_over_global_pool() -> None:
    set_cache(fofa_keys=[fofa_key_dict("Primary", "pool-secret")])
    task = make_task({})
    task.fofa_config = {"key": "task-secret"}

    keys = settings_service.resolve_fofa_keys(task)

    assert [(item.name, item.key) for item in keys] == [("Task override", "task-secret")]


def test_fofa_key_cache_and_effective_settings_do_not_share_mutable_lists() -> None:
    stored = [fofa_key_dict("Primary", "pool-secret", base_url="https://primary.example/api")]
    set_cache(fofa_keys=stored)

    effective = settings_service.effective_settings()
    effective["fofa_keys"][0]["name"] = "Changed"
    effective["fofa_keys"][0]["base_url"] = "https://changed.example"

    assert settings_service._cache["fofa_keys"][0]["name"] == "Primary"
    assert settings_service._cache["fofa_keys"][0]["base_url"] == "https://primary.example/api"


def test_publish_settings_cache_deep_copies_fofa_key_pool() -> None:
    stored = [fofa_key_dict("Primary", "pool-secret", base_url="https://primary.example/api")]
    row = SystemSettings(id="global", fofa_keys=stored)

    settings_service._publish_settings_cache(row)
    stored[0]["name"] = "Changed"
    row.fofa_keys[0]["key"] = "changed-secret"

    assert settings_service._cache["fofa_keys"] == [
        fofa_key_dict("Primary", "pool-secret", base_url="https://primary.example/api")
    ]


def test_public_view_does_not_expose_fofa_key_secrets(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "legacy-secret")
    set_cache(fofa_keys=[fofa_key_dict("Primary", "pool-secret")])

    public = settings_service.public_settings_view()

    assert "pool-secret" not in repr(public)
    assert "legacy-secret" not in repr(public)


def test_disabled_global_fofa_keeps_task_specific_key_available() -> None:
    set_cache(
        fofa={
            "key": "disabled-global-key",
            "base_url": "https://global-fofa.example",
            "enabled": False,
        }
    )
    task = make_task({})
    task.fofa_config = {
        "key": "task-fofa-key",
        "base_url": "https://task-fofa.example",
    }

    assert settings_service.resolve_fofa_key() == ""
    assert settings_service.resolve_fofa_key(task) == "task-fofa-key"
    assert settings_service.resolve_fofa_base_url(task) == "https://task-fofa.example"


def make_task(model_config: dict) -> Task:
    return Task(
        id="task-1",
        name="test",
        model_config_json=model_config,
        src_type="edusrc",
        vuln_types=[],
        src_rules="",
        target_source="manual",
        fofa_query="",
        manual_targets=[],
        fofa_config={},
        engine="",
        concurrency=1,
        status="created",
    )


def test_explicit_task_override_pins_one_provider() -> None:
    set_cache(providers=[provider_dict("A"), provider_dict("B")])
    task = make_task({
        "use_global_pool": False,
        "base_url": "https://task.example/v1",
        "api_key": "sk-task-secret-123456",
        "model": "task-model",
        "protocol": "anthropic_messages",
        "temperature": 0.7,
    })

    providers = settings_service.resolve_llm_providers(task)

    assert len(providers) == 1
    assert providers[0].name == "Task override"
    assert providers[0].protocol == "anthropic_messages"
    assert providers[0].weight == 1


def test_use_global_pool_ignores_stale_override_fields() -> None:
    set_cache(providers=[provider_dict("A"), provider_dict("B")])
    task = make_task({
        "use_global_pool": True,
        "api_key": "sk-stale-secret-123456",
        "model": "stale-model",
        "prompt_version": "modern",
    })

    providers = settings_service.resolve_llm_providers(task)

    assert [item.name for item in providers] == ["A", "B"]


def test_legacy_task_override_without_flag_remains_supported() -> None:
    set_cache(providers=[provider_dict("A")])
    task = make_task({
        "base_url": "https://old-task.example/v1",
        "api_key": "sk-old-task-secret-123456",
        "model": "old-task-model",
    })

    providers = settings_service.resolve_llm_providers(task)

    assert len(providers) == 1
    assert providers[0].name == "Task override"
    assert providers[0].protocol == "openai_chat"


def test_prompt_version_alone_does_not_pin_provider() -> None:
    set_cache(providers=[provider_dict("A"), provider_dict("B")])
    task = make_task({"prompt_version": "modern"})

    providers = settings_service.resolve_llm_providers(task)

    assert [item.name for item in providers] == ["A", "B"]


def test_public_view_masks_every_provider_key() -> None:
    set_cache(providers=[provider_dict("A"), provider_dict("B")])

    public = settings_service.public_settings_view()

    assert len(public["llm_providers"]) == 2
    assert all(item["api_key"] == settings_service._MASK_PLACEHOLDER for item in public["llm_providers"])
    assert all(item["api_key_set"] is True for item in public["llm_providers"])
    assert "sk-a-secret" not in repr(public)


def test_public_view_masks_legacy_fallback_provider(monkeypatch) -> None:
    monkeypatch.setenv("LLM_API_KEY", "sk-legacy-secret-123456")
    set_cache()

    public = settings_service.public_settings_view()

    assert public["llm_providers"] == [{
        "name": "Legacy default",
        "base_url": "https://api.deepseek.com/v1",
        "api_key": settings_service._MASK_PLACEHOLDER,
        "api_key_set": True,
        "model": "deepseek-chat",
        "temperature": 0.3,
        "weight": 1,
        "protocol": "openai_chat",
        "enabled": True,
    }]
    assert "sk-legacy-secret" not in repr(public)


def test_resolve_llm_config_uses_first_provider_for_compat_display() -> None:
    set_cache(providers=[
        provider_dict("First", protocol="openai_responses"),
        provider_dict("Second"),
    ])

    config = settings_service.resolve_llm_config()

    assert config.name == "First"
    assert config.model == "model-first"
    assert config.protocol == "openai_responses"


def test_global_router_disable_callback_schedules_on_captured_loop(monkeypatch) -> None:
    set_cache(providers=[provider_dict("A")])
    persisted: list[tuple[str, str]] = []

    class CapturingRouter:
        def __init__(self, providers, usage_key=None, on_provider_disabled=None):
            self.providers = providers
            self.usage_key = usage_key
            self.on_provider_disabled = on_provider_disabled

    async def scenario() -> None:
        loop = asyncio.get_running_loop()
        completed = asyncio.Event()

        async def fake_persist(
            name: str, reason: str, expected_fingerprint: str | None = None
        ) -> None:
            assert asyncio.get_running_loop() is loop
            assert expected_fingerprint
            persisted.append((name, reason))
            completed.set()

        monkeypatch.setattr(settings_service, "LLMRouter", CapturingRouter)
        monkeypatch.setattr(settings_service, "_persist_global_provider_disabled", fake_persist)
        router = settings_service.llm_router_for_task()

        assert router.on_provider_disabled is not None
        await asyncio.to_thread(router.on_provider_disabled, "A", "auth: safe reason")
        await asyncio.wait_for(completed.wait(), timeout=1)

    asyncio.run(scenario())
    assert persisted == [("A", "auth: safe reason")]


def test_task_override_router_has_no_global_disable_callback(monkeypatch) -> None:
    set_cache(providers=[provider_dict("Global")])
    task = make_task({
        "use_global_pool": False,
        "base_url": "https://task.example/v1",
        "api_key": "sk-task-secret-123456",
        "model": "task-model",
    })

    class CapturingRouter:
        def __init__(self, providers, usage_key=None, on_provider_disabled=None):
            self.providers = providers
            self.usage_key = usage_key
            self.on_provider_disabled = on_provider_disabled

    monkeypatch.setattr(settings_service, "LLMRouter", CapturingRouter)

    async def scenario() -> CapturingRouter:
        return settings_service.llm_router_for_task(task)

    router = asyncio.run(scenario())
    assert router.on_provider_disabled is None


def test_disabling_legacy_fallback_materializes_a_disabled_provider(
    tmp_path, monkeypatch
) -> None:
    secret = "legacy-token-VERYSECRET"
    monkeypatch.setenv("LLM_API_KEY", secret)
    set_cache()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'legacy-disable.db'}")
    session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async def scenario() -> list[dict]:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(SystemSettings(id="global", llm={}, llm_providers=[]))
            await session.commit()

        monkeypatch.setattr(settings_service, "SessionLocal", session_maker)
        await settings_service._persist_global_provider_disabled(
            "Legacy default", "auth: invalid credentials"
        )

        async with session_maker() as session:
            row = await session.get(SystemSettings, "global")
            return list(row.llm_providers or [])

    try:
        providers = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert len(providers) == 1
    assert providers[0]["name"] == "Legacy default"
    assert providers[0]["api_key"] == secret
    assert providers[0]["enabled"] is False
    assert settings_service.resolve_llm_providers()[0].enabled is False


def test_concurrent_provider_disables_do_not_overwrite_each_other(
    tmp_path, monkeypatch
) -> None:
    class YieldingSession(AsyncSession):
        async def get(self, *args, **kwargs):
            row = await super().get(*args, **kwargs)
            # Force concurrent callers to load the same pre-update JSON snapshot.
            await asyncio.sleep(0.03)
            return row

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'disable-race.db'}")
    session_maker = async_sessionmaker(
        engine, class_=YieldingSession, expire_on_commit=False
    )
    providers = [provider_dict("A"), provider_dict("B")]
    set_cache(providers=providers)

    async def no_refresh(_session) -> None:
        return None

    async def scenario() -> list[dict]:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(SystemSettings(id="global", llm_providers=providers))
            await session.commit()

        monkeypatch.setattr(settings_service, "SessionLocal", session_maker)
        monkeypatch.setattr(settings_service, "refresh_cache", no_refresh)
        await asyncio.gather(
            settings_service._persist_global_provider_disabled("A", "auth: A"),
            settings_service._persist_global_provider_disabled("B", "quota: B"),
        )

        async with session_maker() as session:
            row = await session.get(SystemSettings, "global")
            return list(row.llm_providers or [])

    try:
        stored = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert {item["name"]: item["enabled"] for item in stored} == {
        "A": False,
        "B": False,
    }


def test_concurrent_provider_creates_do_not_overwrite_each_other(
    tmp_path, monkeypatch
) -> None:
    class YieldingSession(AsyncSession):
        async def get(self, *args, **kwargs):
            row = await super().get(*args, **kwargs)
            await asyncio.sleep(0.03)
            return row

    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'create-race.db'}")
    session_maker = async_sessionmaker(
        engine, class_=YieldingSession, expire_on_commit=False
    )
    set_cache()

    async def scenario() -> list[dict]:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(SystemSettings(id="global", llm_providers=[]))
            await session.commit()

        async with session_maker() as first, session_maker() as second:
            await asyncio.gather(
                settings_service.create_llm_provider(first, provider_dict("A")),
                settings_service.create_llm_provider(second, provider_dict("B")),
            )
        async with session_maker() as session:
            row = await session.get(SystemSettings, "global")
            return list(row.llm_providers or [])

    try:
        stored = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert [item["name"] for item in stored] == ["A", "B"]


def test_update_settings_and_provider_create_publish_latest_state(
    tmp_path, monkeypatch
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'settings-provider-race.db'}")

    async def scenario() -> tuple[list[dict], dict, list[str], dict]:
        update_refreshed = asyncio.Event()
        release_update = asyncio.Event()
        provider_waiting = asyncio.Event()

        class PausingRefreshSession(AsyncSession):
            async def refresh(self, *args, **kwargs):
                await super().refresh(*args, **kwargs)
                update_refreshed.set()
                await release_update.wait()

        class ObservedLock(asyncio.Lock):
            async def acquire(self):
                if self.locked():
                    provider_waiting.set()
                return await super().acquire()

        shared_lock = ObservedLock()
        monkeypatch.setattr(
            settings_service, "_provider_mutation_lock", lambda: shared_lock
        )
        update_sessions = async_sessionmaker(
            engine, class_=PausingRefreshSession, expire_on_commit=False
        )
        provider_sessions = async_sessionmaker(
            engine, class_=AsyncSession, expire_on_commit=False
        )
        initial = [provider_dict("A")]

        async with engine.begin() as connection:
            await connection.exec_driver_sql("PRAGMA journal_mode=WAL")
            await connection.run_sync(Base.metadata.create_all)
        async with provider_sessions() as session:
            session.add(
                SystemSettings(id="global", defaults={}, llm_providers=initial)
            )
            await session.commit()

        async with update_sessions() as update_session, provider_sessions() as provider_session:
            update_task = asyncio.create_task(
                settings_service.update_settings(
                    update_session, {"defaults": {"concurrency": 7}}
                )
            )
            await asyncio.wait_for(update_refreshed.wait(), timeout=2)

            provider_task = asyncio.create_task(
                settings_service.create_llm_provider(
                    provider_session, provider_dict("B")
                )
            )
            waiting_task = asyncio.create_task(provider_waiting.wait())
            await asyncio.wait_for(
                asyncio.wait(
                    {provider_task, waiting_task},
                    return_when=asyncio.FIRST_COMPLETED,
                ),
                timeout=2,
            )
            release_update.set()
            await asyncio.gather(update_task, provider_task)
            if not waiting_task.done():
                waiting_task.cancel()
            await asyncio.gather(waiting_task, return_exceptions=True)

        async with provider_sessions() as session:
            row = await session.get(SystemSettings, "global")
            stored_providers = list(row.llm_providers or [])
            stored_defaults = dict(row.defaults or {})
        cached_names = [
            provider.name for provider in settings_service.resolve_llm_providers()
        ]
        cached_defaults = dict(settings_service._cache.get("defaults") or {})
        return stored_providers, stored_defaults, cached_names, cached_defaults

    try:
        stored, defaults, cached_names, cached_defaults = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert [item["name"] for item in stored] == ["A", "B"]
    assert defaults["concurrency"] == 7
    assert cached_names == ["A", "B"]
    assert cached_defaults["concurrency"] == 7


def test_refresh_cache_does_not_publish_stale_identity_map_after_provider_write(
    tmp_path,
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'stale-refresh.db'}")
    session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    initial = [provider_dict("A")]

    async def scenario() -> list[str]:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(SystemSettings(id="global", llm_providers=initial))
            await session.commit()

        async with session_maker() as stale_session:
            stale_row = await stale_session.get(SystemSettings, "global")
            assert [item["name"] for item in stale_row.llm_providers] == ["A"]
            async with session_maker() as writer_session:
                await settings_service.create_llm_provider(
                    writer_session, provider_dict("B")
                )
            await settings_service.refresh_cache(stale_session)

        return [
            provider.name for provider in settings_service.resolve_llm_providers()
        ]

    try:
        cached_names = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert cached_names == ["A", "B"]


def test_stale_auth_failure_does_not_disable_rotated_provider(
    tmp_path, monkeypatch
) -> None:
    old = LLMProviderConfig.model_validate(provider_dict("A", api_key="old-secret"))
    new_value = provider_dict("A", api_key="new-secret")
    set_cache(providers=[new_value])
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'stale-auth.db'}")
    session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async def scenario() -> dict:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(SystemSettings(id="global", llm_providers=[new_value]))
            await session.commit()
        monkeypatch.setattr(settings_service, "SessionLocal", session_maker)
        await settings_service._persist_global_provider_disabled(
            "A",
            "auth: old request failed",
            expected_fingerprint=settings_service._provider_fingerprint(old),
        )
        async with session_maker() as session:
            row = await session.get(SystemSettings, "global")
            return dict(row.llm_providers[0])

    try:
        stored = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert stored["api_key"] == "new-secret"
    assert stored["enabled"] is True


def test_invalid_stored_provider_blocks_mutation_without_data_loss(
    tmp_path, monkeypatch
) -> None:
    invalid = provider_dict("Broken", api_key="invalid-secret", protocol="invalid")
    original = [provider_dict("A"), invalid]
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'invalid-pool.db'}")
    session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async def scenario() -> list[dict]:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(SystemSettings(id="global", llm_providers=original))
            await session.commit()
        async with session_maker() as session:
            with pytest.raises(settings_service.LLMProviderValidationError):
                await settings_service.update_llm_provider(
                    session, "A", {"model": "new-model"}
                )
        async with session_maker() as session:
            row = await session.get(SystemSettings, "global")
            return list(row.llm_providers or [])

    try:
        stored = asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert stored == original


def test_refresh_cache_tolerates_non_mapping_provider_entries(
    tmp_path, monkeypatch
) -> None:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'malformed-pool.db'}")
    session_maker = async_sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    async def scenario() -> None:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with session_maker() as session:
            session.add(SystemSettings(id="global", llm_providers=["not-a-provider"]))
            await session.commit()
        async with session_maker() as session:
            await settings_service.refresh_cache(session)

    try:
        asyncio.run(scenario())
    finally:
        asyncio.run(engine.dispose())

    assert settings_service.resolve_llm_providers() == []


def test_legacy_display_config_survives_an_all_invalid_provider_cache(monkeypatch) -> None:
    monkeypatch.setattr(
        settings_service,
        "_cache",
        {
            "llm": {
                "base_url": "https://legacy.example/v1",
                "api_key": "legacy-key",
                "model": "legacy-model",
                "protocol": "openai_chat",
                "temperature": 0.3,
            },
            "llm_providers": ["not-a-provider"],
            "fofa": {},
            "engines": {},
            "defaults": {},
        },
    )

    resolved = settings_service.resolve_llm_config()

    assert resolved.model == "legacy-model"
    assert resolved.base_url == "https://legacy.example/v1"
