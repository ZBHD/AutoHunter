"""全局系统配置：DB 持久化 + 内存缓存 + 与 env / 任务级合并解析。"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
import time
from typing import Any, AsyncIterator
from weakref import ReferenceType, WeakKeyDictionary, ref

from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import FofaKeyConfig, LLMConfig, LLMProviderConfig
from app.agents.prompts import normalize_worker_prompt_version
from app.db.models import SystemSettings, Task, to_cst_iso
from app.db.session import SessionLocal
from app.engines import get_engine, list_engines, get_default_engine
from app.fofa.client import get_userinfo as get_fofa_userinfo
from app.llm.client import LLMClient, LLMError, _sanitize_error_detail
from app.llm.router import LLMRouter

SETTINGS_ID = "global"

logger = logging.getLogger("autohunter.settings")

_cache: dict[str, Any] = {
    "llm": {},
    "llm_providers": [],
    "fofa": {},
    "fofa_keys": [],
    "engines": {},
    "defaults": {},
}

_provider_mutation_locks: WeakKeyDictionary[
    asyncio.AbstractEventLoop, ReferenceType[asyncio.Lock]
] = WeakKeyDictionary()
_provider_fingerprint_secret = os.urandom(32)

_TASK_PROVIDER_FIELDS = frozenset({"base_url", "api_key", "model", "temperature", "protocol"})


# 统一脱敏占位：不再泄露密钥首尾字符，避免降低离线爆破成本。
_MASK_PLACEHOLDER = "••••••••"


class LLMProviderConflictError(ValueError):
    pass


class LLMProviderNotFoundError(ValueError):
    pass


class LLMProviderOrderError(ValueError):
    pass


class LLMProviderValidationError(ValueError):
    pass


def mask_secret(value: str) -> str:
    v = str(value or "").strip()
    if not v:
        return ""
    return _MASK_PLACEHOLDER


def is_masked_secret(value: str) -> bool:
    """判断传入值是否为前端回显的脱敏占位（应视为"未修改"，不可回写覆盖真实密钥）。"""
    v = str(value or "").strip()
    if not v:
        return False
    return set(v) <= {"*", "•", "·", "●", "…", ".", "○", "◦"}


def _env_llm() -> dict[str, Any]:
    return {
        "base_url": os.environ.get("LLM_BASE_URL", "https://api.deepseek.com/v1"),
        "api_key": os.environ.get("LLM_API_KEY", ""),
        "model": os.environ.get("LLM_MODEL", "deepseek-chat"),
        "temperature": float(os.environ.get("LLM_TEMPERATURE", "0.3")),
        "protocol": os.environ.get("LLM_PROTOCOL", "openai_chat"),
    }


def _env_fofa() -> dict[str, Any]:
    return {
        "key": os.environ.get("FOFA_KEY", ""),
        "base_url": os.environ.get("FOFA_BASE_URL") or "https://fofa.info",
        "enabled": True,
        "max_pages": 20,
        "page_size": 100,
        "default_intent_mode": "",
    }


def _env_engines() -> dict[str, Any]:
    """从环境变量读取所有已注册引擎的 API Key 和 base_url。
    约定环境变量名为 {ENGINE_ENV_KEY}_KEY 和 {ENGINE_ENV_KEY}_BASE_URL。
    """
    result: dict[str, dict[str, str]] = {}
    for eng in list_engines():
        name = eng["name"]
        env_key = name.upper()
        key = os.environ.get(f"{env_key}_KEY", "")
        base_url = os.environ.get(f"{env_key}_BASE_URL", "")
        if key:
            result.setdefault(name, {})["key"] = key
        if base_url:
            result.setdefault(name, {})["base_url"] = base_url
    # 兼容旧 FOFA_KEY / FOFA_BASE_URL
    if "fofa" not in result:
        fofa_key = os.environ.get("FOFA_KEY", "")
        fofa_base = os.environ.get("FOFA_BASE_URL", "")
        if fofa_key:
            result["fofa"] = {"key": fofa_key}
            if fofa_base:
                result["fofa"]["base_url"] = fofa_base
    return result


def _env_defaults() -> dict[str, Any]:
    return {
        "concurrency": 3,
        "skip_score_threshold": float(os.environ.get("SKIP_SCORE_THRESHOLD", "-10")),
        "worker_prompt_version": normalize_worker_prompt_version(os.environ.get("WORKER_PROMPT_VERSION", "current")),
        "engine": os.environ.get("SEARCH_ENGINE", get_default_engine()),
    }


def _merge_section(stored: dict, env: dict) -> dict[str, Any]:
    out = dict(env)
    for k, v in (stored or {}).items():
        if v is not None and v != "":
            out[k] = v
    return out


def effective_settings() -> dict[str, Any]:
    """合并 env + DB 缓存的有效配置（含明文密钥，仅服务端内部使用）。"""
    providers = resolve_llm_providers()
    return {
        "llm": _merge_section(_cache.get("llm"), _env_llm()),
        "llm_providers": [provider.model_dump(mode="json") for provider in providers],
        "fofa": _merge_section(_cache.get("fofa"), _env_fofa()),
        "fofa_keys": deepcopy(_cache.get("fofa_keys") or []),
        "engines": _merge_section(_cache.get("engines"), _env_engines()),
        "defaults": _merge_section(_cache.get("defaults"), _env_defaults()),
    }


def _legacy_llm_settings() -> dict[str, Any]:
    return _merge_section(_cache.get("llm"), _env_llm())


def task_uses_global_pool(task: Task | None) -> bool:
    if task is None:
        return True
    config = dict(task.model_config_json or {})
    if "use_global_pool" in config:
        return config.get("use_global_pool") is not False
    return not any(
        key in config and config.get(key) not in (None, "")
        for key in _TASK_PROVIDER_FIELDS
    )


def _provider_from_value(value: Any) -> LLMProviderConfig:
    if isinstance(value, LLMProviderConfig):
        return value.model_copy(deep=True)
    return LLMProviderConfig.model_validate(value)


def _provider_fingerprint(provider: LLMProviderConfig) -> str:
    canonical = json.dumps(
        provider.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(
        _provider_fingerprint_secret, canonical, hashlib.sha256
    ).hexdigest()


def _settings_fingerprint(value: dict[str, Any]) -> str:
    canonical = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(
        _provider_fingerprint_secret, canonical, hashlib.sha256
    ).hexdigest()


def _legacy_provider() -> LLMProviderConfig:
    legacy = _legacy_llm_settings()
    return LLMProviderConfig(
        name="Legacy default",
        base_url=legacy.get("base_url") or "https://api.deepseek.com/v1",
        api_key=legacy.get("api_key") or "",
        model=legacy.get("model") or "deepseek-chat",
        temperature=legacy.get("temperature", 0.3),
        weight=1,
        protocol=legacy.get("protocol") or "openai_chat",
        enabled=True,
    )


def _legacy_provider_from_row(row: SystemSettings) -> LLMProviderConfig:
    legacy = _merge_section(dict(row.llm or {}), _env_llm())
    return LLMProviderConfig(
        name="Legacy default",
        base_url=legacy.get("base_url") or "https://api.deepseek.com/v1",
        api_key=legacy.get("api_key") or "",
        model=legacy.get("model") or "deepseek-chat",
        temperature=legacy.get("temperature", 0.3),
        weight=1,
        protocol=legacy.get("protocol") or "openai_chat",
        enabled=True,
    )


def _fofa_probe_config_from_row(row: SystemSettings) -> dict[str, Any]:
    effective = _merge_section(dict(row.fofa or {}), _env_fofa())
    engines = _merge_section(dict(row.engines or {}), _env_engines())
    engine_fofa = engines.get("fofa") or {}
    return {
        "key": str(effective.get("key") or engine_fofa.get("key") or ""),
        "base_url": str(effective.get("base_url") or "https://fofa.info"),
        "enabled": effective.get("enabled") is not False,
    }


def _task_override_provider(task: Task) -> LLMProviderConfig:
    legacy = _legacy_llm_settings()
    config = dict(task.model_config_json or {})

    def value_or_legacy(key: str, default: Any) -> Any:
        value = config.get(key)
        return legacy.get(key, default) if value in (None, "") else value

    return LLMProviderConfig(
        name="Task override",
        base_url=value_or_legacy("base_url", "https://api.deepseek.com/v1"),
        api_key=value_or_legacy("api_key", ""),
        model=value_or_legacy("model", "deepseek-chat"),
        temperature=value_or_legacy("temperature", 0.3),
        weight=1,
        protocol=value_or_legacy("protocol", "openai_chat"),
        enabled=True,
    )


def resolve_llm_providers(task: Task | None = None) -> list[LLMProviderConfig]:
    """解析任务实际使用的 provider 列表，不过滤 disabled/keyless 项。"""
    if task is not None and not task_uses_global_pool(task):
        return [_task_override_provider(task)]

    stored_pool = list(_cache.get("llm_providers") or [])
    if stored_pool:
        providers: list[LLMProviderConfig] = []
        for item in stored_pool:
            try:
                providers.append(_provider_from_value(item))
            except (TypeError, ValidationError):
                logger.error(
                    "忽略无法解析的缓存 LLM provider: name=%s",
                    item.get("name") if isinstance(item, dict) else "<unknown>",
                )
        return providers
    return [_legacy_provider()]


def resolve_llm_config(task: Task | None = None) -> LLMConfig:
    """兼容旧展示调用方：返回首个可用 provider，否则返回池中首项。"""
    providers = resolve_llm_providers(task)
    if not providers:
        providers = [_legacy_provider()]
    selected = next(
        (provider for provider in providers if provider.enabled and provider.api_key),
        providers[0],
    )
    return LLMConfig.model_validate(selected.model_dump())


def _fofa_key_from_value(value: Any) -> FofaKeyConfig:
    if isinstance(value, FofaKeyConfig):
        return value.model_copy(deep=True)
    return FofaKeyConfig.model_validate(value)


def resolve_fofa_keys(task: Task | None = None) -> list[FofaKeyConfig]:
    """解析 FOFA Key 池，保留禁用项并兼容任务及旧单 Key 配置。"""
    if task is not None:
        task_config = task.fofa_config or {}
        task_key = str(task_config.get("key") or "").strip()
        if task_key:
            task_base_url = str(task_config.get("base_url") or "").strip()
            if not task_base_url:
                task_base_url = resolve_fofa_base_url()
            return [
                FofaKeyConfig(
                    name="Task override",
                    key=task_key,
                    base_url=task_base_url,
                )
            ]

    stored_pool = list(_cache.get("fofa_keys") or [])
    if stored_pool:
        keys: list[FofaKeyConfig] = []
        for item in stored_pool:
            try:
                keys.append(_fofa_key_from_value(item))
            except (TypeError, ValidationError):
                logger.error(
                    "忽略无法解析的缓存 FOFA Key: name=%s",
                    item.get("name") if isinstance(item, dict) else "<unknown>",
                )
        return keys

    fofa = dict(_cache.get("fofa") or {})
    engines = dict(_cache.get("engines") or {})
    engine_fofa = engines.get("fofa") or {}
    if not isinstance(engine_fofa, dict):
        engine_fofa = {}
    key = str(
        fofa.get("key")
        or engine_fofa.get("key")
        or os.environ.get("FOFA_KEY", "")
    ).strip()
    return [
        FofaKeyConfig(
            name="Legacy Key",
            key=key,
            base_url=resolve_fofa_base_url(),
            enabled=fofa.get("enabled") is not False,
        )
    ]


# ── 引擎相关解析函数 ──────────────────────────────────────────

def resolve_engine_name(task: Task | None = None) -> str:
    """获取任务使用的搜索引擎名称。"""
    if task and task.engine:
        return task.engine
    eff = effective_settings()["defaults"]
    return str(eff.get("engine") or get_default_engine())


def resolve_engine_key(engine_name: str, task: Task | None = None) -> str:
    """获取指定引擎的 API Key（任务级 > DB缓存 > 环境变量）。"""
    effective = effective_settings()
    # 任务级 fofa_config 兼容旧版
    if engine_name == "fofa" and task:
        cfg = task.fofa_config or {}
        if cfg.get("key"):
            return str(cfg["key"])
    if engine_name == "fofa":
        fofa = effective["fofa"]
        if fofa.get("enabled") is False:
            return ""
        if fofa.get("key"):
            return str(fofa["key"])
    eng_cfg = effective["engines"].get(engine_name, {})
    return str(eng_cfg.get("key") or "")


def resolve_engine_base_url(engine_name: str, task: Task | None = None) -> str:
    """获取指定引擎的 base_url。"""
    engine = get_engine(engine_name)
    default = engine.get_default_base_url() if engine else ""
    effective = effective_settings()
    # 任务级 fofa_config 兼容旧版
    if engine_name == "fofa" and task:
        cfg = task.fofa_config or {}
        if cfg.get("base_url"):
            return str(cfg["base_url"])
    if engine_name == "fofa" and effective["fofa"].get("base_url"):
        return str(effective["fofa"]["base_url"])
    eng_cfg = effective["engines"].get(engine_name, {})
    return str(eng_cfg.get("base_url") or default)


def resolve_engine_config(task: Task | None = None) -> dict[str, Any]:
    """解析任务使用的引擎完整配置。"""
    engine_name = resolve_engine_name(task)
    # 兼容旧版 fofa_config 分页设置
    cfg = (task.fofa_config or {}) if task else {}
    effective = effective_settings()
    eng_cfg = dict(effective["engines"].get(engine_name, {}))
    if engine_name == "fofa":
        eng_cfg.update(effective["fofa"])
    return {
        "engine": engine_name,
        "key": resolve_engine_key(engine_name, task),
        "base_url": resolve_engine_base_url(engine_name, task),
        "max_pages": int(cfg.get("max_pages") or eng_cfg.get("max_pages") or 20),
        "page_size": int(cfg.get("page_size") or eng_cfg.get("page_size") or 100),
        "intent_mode": str(
            cfg.get("intent_mode")
            or eng_cfg.get("intent_mode")
            or eng_cfg.get("default_intent_mode")
            or ""
        ),
    }


# ── 旧版兼容 ──────────────────────────────────────────────────

def resolve_fofa_key(task: Task | None = None) -> str:
    """兼容旧版：等价于 resolve_engine_key('fofa', task)。"""
    return resolve_engine_key("fofa", task)


def resolve_fofa_base_url(task: Task | None = None) -> str:
    """兼容旧版：等价于 resolve_engine_base_url('fofa', task)。"""
    return resolve_engine_base_url("fofa", task)


def resolve_fofa_defaults(task: Task | None = None) -> dict[str, Any]:
    """兼容旧版。"""
    return resolve_engine_config(task)


# ── 其他 ──────────────────────────────────────────────────────

def resolve_skip_score_threshold() -> float:
    return float(effective_settings()["defaults"].get("skip_score_threshold", -10))


def resolve_worker_prompt_version(task: Task | None = None) -> str:
    mc = (task.model_config_json or {}) if task else {}
    if mc.get("prompt_version"):
        return normalize_worker_prompt_version(mc.get("prompt_version"))
    return normalize_worker_prompt_version(effective_settings()["defaults"].get("worker_prompt_version"))


def _public_provider(provider: LLMProviderConfig) -> dict[str, Any]:
    return {
        "name": provider.name,
        "base_url": provider.base_url,
        "api_key": mask_secret(provider.api_key),
        "api_key_set": bool(provider.api_key),
        "model": provider.model,
        "temperature": provider.temperature,
        "weight": provider.weight,
        "protocol": provider.protocol,
        "enabled": provider.enabled,
    }


def _provider_api_view(
    provider: LLMProviderConfig, *, read_only: bool = False
) -> dict[str, Any]:
    view = _public_provider(provider)
    view["read_only"] = read_only
    view["source"] = "legacy" if read_only else "database"
    return view


def _provider_payload(provider: LLMProviderConfig) -> dict[str, Any]:
    return provider.model_dump(mode="json")


def _provider_name_key(name: str) -> str:
    return str(name or "").strip().casefold()


def _validated_provider(value: Any, *, allow_masked_key: bool = False) -> LLMProviderConfig:
    try:
        provider = _provider_from_value(value)
    except ValidationError as exc:
        raise LLMProviderValidationError("Provider 配置无效") from exc
    if provider.enabled and not provider.api_key:
        raise LLMProviderValidationError("启用的 Provider 必须配置 API Key")
    if provider.api_key and is_masked_secret(provider.api_key) and not allow_masked_key:
        raise LLMProviderValidationError("脱敏占位不能作为新的 API Key")
    return provider


def _provider_list_response(providers: list[LLMProviderConfig]) -> dict[str, Any]:
    return {"providers": [_provider_api_view(provider) for provider in providers]}


def public_settings_view() -> dict[str, Any]:
    """API 返回：密钥脱敏。"""
    eff = effective_settings()
    llm = eff["llm"]
    fofa = eff["fofa"]
    engines = eff.get("engines", {})
    defaults = eff["defaults"]

    # 构建引擎列表视图
    engines_view = {}
    for eng in list_engines():
        name = eng["name"]
        ecfg = engines.get(name, {})
        engines_view[name] = {
            "display_name": eng["display_name"],
            "key": mask_secret(ecfg.get("key", "")),
            "key_set": bool(ecfg.get("key")),
            "base_url": ecfg.get("base_url", ""),
        }

    return {
        "llm": {
            "base_url": llm["base_url"],
            "model": llm["model"],
            "temperature": llm["temperature"],
            "protocol": llm.get("protocol", "openai_chat"),
            "api_key": mask_secret(llm["api_key"]),
            "api_key_set": bool(llm["api_key"]),
        },
        "llm_providers": [
            _public_provider(_provider_from_value(provider))
            for provider in eff.get("llm_providers", [])
        ],
        "fofa": {
            "base_url": fofa.get("base_url") or "https://fofa.info",
            "enabled": fofa.get("enabled") is not False,
            "max_pages": int(fofa.get("max_pages") or 20),
            "page_size": int(fofa.get("page_size") or 100),
            "default_intent_mode": fofa.get("default_intent_mode") or "",
            "key": mask_secret(fofa.get("key") or ""),
            "key_set": bool(fofa.get("key")),
        },
        "engines": engines_view,
        "defaults": {
            "concurrency": int(defaults.get("concurrency") or 3),
            "skip_score_threshold": float(defaults.get("skip_score_threshold", -10)),
            "worker_prompt_version": normalize_worker_prompt_version(defaults.get("worker_prompt_version")),
            "engine": defaults.get("engine", get_default_engine()),
        },
        "available_engines": list_engines(),
        "updated_at": _cache.get("updated_at"),
    }


def _publish_settings_cache(row: SystemSettings) -> None:
    global _cache
    raw_providers = row.llm_providers
    if isinstance(raw_providers, list):
        providers = deepcopy(raw_providers)
    elif raw_providers is None:
        providers = []
    else:
        providers = [deepcopy(raw_providers)]
    raw_fofa_keys = row.fofa_keys
    if isinstance(raw_fofa_keys, list):
        fofa_keys = deepcopy(raw_fofa_keys)
    elif raw_fofa_keys is None:
        fofa_keys = []
    else:
        fofa_keys = [deepcopy(raw_fofa_keys)]
    _cache = {
        "llm": dict(row.llm or {}),
        "llm_providers": providers,
        "fofa": dict(row.fofa or {}),
        "fofa_keys": fofa_keys,
        "engines": dict(row.engines or {}),
        "defaults": dict(row.defaults or {}),
        "updated_at": to_cst_iso(row.updated_at),
    }


async def refresh_cache(session: AsyncSession) -> SystemSettings:
    async with _provider_mutation_lock():
        row = await session.get(
            SystemSettings, SETTINGS_ID, populate_existing=True
        )
        if row is None:
            row = SystemSettings(id=SETTINGS_ID)
            session.add(row)
            await session.commit()
            await session.refresh(row)
        _publish_settings_cache(row)
        return row


async def init_settings_cache() -> None:
    async with SessionLocal() as session:
        await refresh_cache(session)


async def update_settings(session: AsyncSession, payload: dict[str, Any]) -> dict[str, Any]:
    async with _provider_write_transaction(session) as row:
        if "llm" in payload and payload["llm"]:
            llm = dict(row.llm or {})
            for k, v in payload["llm"].items():
                if k == "api_key":
                    if not str(v or "").strip() or is_masked_secret(v):
                        continue
                if v is not None:
                    llm[k] = v
            row.llm = llm

        if "fofa" in payload and payload["fofa"]:
            fofa = dict(row.fofa or {})
            for k, v in payload["fofa"].items():
                if k == "key":
                    if not str(v or "").strip() or is_masked_secret(v):
                        continue
                if v is not None:
                    fofa[k] = v
                    if k == "key" and str(v or "").strip():
                        fofa["enabled"] = True
            row.fofa = fofa

        # 多引擎配置
        if "engines" in payload and payload["engines"]:
            engines = dict(row.engines or {})
            for eng_name, eng_cfg in payload["engines"].items():
                if not isinstance(eng_cfg, dict):
                    continue
                current = dict(engines.get(eng_name, {}))
                for k, v in eng_cfg.items():
                    if k == "key":
                        if not str(v or "").strip() or is_masked_secret(v):
                            continue
                    if v is not None:
                        current[k] = v
                if current:
                    engines[eng_name] = current
            row.engines = engines

        if "defaults" in payload and payload["defaults"]:
            defaults = dict(row.defaults or {})
            for k, v in payload["defaults"].items():
                if v is not None:
                    defaults[k] = v
            row.defaults = defaults

        await session.commit()
        await session.refresh(row)
        _publish_settings_cache(row)
    return public_settings_view()


async def _settings_row(session: AsyncSession) -> SystemSettings:
    row = await session.get(
        SystemSettings, SETTINGS_ID, populate_existing=True
    )
    if row is None:
        row = SystemSettings(id=SETTINGS_ID)
        session.add(row)
        await session.flush()
    return row


def _stored_providers(row: SystemSettings) -> list[LLMProviderConfig]:
    if not isinstance(row.llm_providers, list):
        raise LLMProviderValidationError("数据库中的 Provider 池格式无效，已拒绝修改")
    providers: list[LLMProviderConfig] = []
    for value in row.llm_providers or []:
        try:
            providers.append(_provider_from_value(value))
        except (TypeError, ValidationError) as exc:
            logger.error(
                "数据库中存在无法解析的 LLM provider，已拒绝修改: name=%s",
                (value or {}).get("name") if isinstance(value, dict) else "<unknown>",
            )
            raise LLMProviderValidationError(
                "数据库中存在无效 Provider，已拒绝修改以避免数据丢失"
            ) from exc
    return providers


async def list_llm_providers(
    session: AsyncSession, *, include_legacy: bool = True
) -> list[dict[str, Any]]:
    row = await refresh_cache(session)
    providers = _stored_providers(row)
    if providers:
        return [_provider_api_view(provider) for provider in providers]
    if include_legacy:
        return [_provider_api_view(_legacy_provider(), read_only=True)]
    return []


async def create_llm_provider(
    session: AsyncSession, payload: dict[str, Any]
) -> dict[str, Any]:
    provider = _validated_provider(payload)
    async with _provider_write_transaction(session) as row:
        providers = _stored_providers(row)
        wanted = _provider_name_key(provider.name)
        if any(_provider_name_key(item.name) == wanted for item in providers):
            raise LLMProviderConflictError(f"Provider 名称已存在: {provider.name}")
        providers.append(provider)
        row.llm_providers = [_provider_payload(item) for item in providers]
        await session.commit()
        _publish_settings_cache(row)
        return _provider_list_response(providers)


async def update_llm_provider(
    session: AsyncSession, name: str, patch: dict[str, Any]
) -> dict[str, Any]:
    async with _provider_write_transaction(session) as row:
        providers = _stored_providers(row)
        wanted = _provider_name_key(name)
        index = next(
            (
                i
                for i, item in enumerate(providers)
                if _provider_name_key(item.name) == wanted
            ),
            None,
        )
        if index is None:
            raise LLMProviderNotFoundError(f"Provider 不存在: {name}")

        current = providers[index]
        merged = _provider_payload(current)
        for key, value in patch.items():
            if value is None:
                continue
            if key == "api_key" and (
                not str(value or "").strip() or is_masked_secret(value)
            ):
                continue
            merged[key] = value
        merged["name"] = current.name
        providers[index] = _validated_provider(merged)

        row.llm_providers = [_provider_payload(item) for item in providers]
        await session.commit()
        _publish_settings_cache(row)
        return _provider_list_response(providers)


async def delete_llm_provider(
    session: AsyncSession, name: str
) -> dict[str, Any]:
    async with _provider_write_transaction(session) as row:
        providers = _stored_providers(row)
        wanted = _provider_name_key(name)
        kept = [item for item in providers if _provider_name_key(item.name) != wanted]
        if len(kept) == len(providers):
            raise LLMProviderNotFoundError(f"Provider 不存在: {name}")
        row.llm_providers = [_provider_payload(item) for item in kept]
        await session.commit()
        _publish_settings_cache(row)
        return _provider_list_response(kept)


async def reorder_llm_providers(
    session: AsyncSession, names: list[str]
) -> dict[str, Any]:
    async with _provider_write_transaction(session) as row:
        providers = _stored_providers(row)
        requested = [_provider_name_key(name) for name in names]
        existing = [_provider_name_key(provider.name) for provider in providers]
        if (
            len(requested) != len(existing)
            or len(set(requested)) != len(requested)
            or set(requested) != set(existing)
        ):
            raise LLMProviderOrderError("排序必须包含所有 Provider 名称且不能重复")
        by_name = {_provider_name_key(provider.name): provider for provider in providers}
        ordered = [by_name[name] for name in requested]
        row.llm_providers = [_provider_payload(item) for item in ordered]
        await session.commit()
        _publish_settings_cache(row)
        return _provider_list_response(ordered)


async def get_llm_provider(
    session: AsyncSession, name: str, *, include_legacy: bool = True
) -> LLMProviderConfig:
    row = await refresh_cache(session)
    providers = _stored_providers(row)
    wanted = _provider_name_key(name)
    for provider in providers:
        if _provider_name_key(provider.name) == wanted:
            return provider
    if not providers and include_legacy:
        legacy = _legacy_provider()
        if _provider_name_key(legacy.name) == wanted:
            return legacy
    raise LLMProviderNotFoundError(f"Provider 不存在: {name}")


def _redact_provider_error(text_value: str, provider: LLMProviderConfig) -> str:
    return _sanitize_error_detail(
        str(text_value or ""), redact_values=(provider.api_key,)
    )


async def probe_llm_provider(provider: LLMProviderConfig) -> dict[str, Any]:
    started = time.perf_counter()
    client = None
    error = ""
    ok = False
    try:
        client = LLMClient(provider)
        await asyncio.to_thread(
            client.chat,
            messages=[{"role": "user", "content": "Reply with OK."}],
            tool_choice="none",
            max_tokens=8,
        )
        ok = True
    except Exception as exc:
        if isinstance(exc, LLMError) and exc.args:
            error = _redact_provider_error(str(exc.args[0]), provider)
        elif not provider.api_key:
            error = "未配置 LLM API Key"
        else:
            error = "LLM Provider 不可用，请检查 Key、端点、模型、协议或网络"
    finally:
        http_client = getattr(client, "_client", None)
        close = getattr(http_client, "close", None)
        if callable(close):
            try:
                await asyncio.to_thread(close)
            except Exception:
                pass
    return {
        "ok": ok,
        "latency_ms": max(0, round((time.perf_counter() - started) * 1000)),
        "model": provider.model,
        "protocol": provider.protocol,
        "error": error,
    }


async def probe_fofa_key(key: str, base_url: str) -> dict[str, Any]:
    started = time.perf_counter()
    error = ""
    ok = False
    if not str(key or "").strip():
        error = "未配置 FOFA key"
    else:
        try:
            await get_fofa_userinfo(key, base_url)
            ok = True
        except Exception as exc:
            if getattr(exc, "account_error", False):
                error = "FOFA Key 无效、额度不足或无权限"
            else:
                error = "FOFA 服务不可用，请检查 Key、端点或网络"
    return {
        "ok": ok,
        "latency_ms": max(0, round((time.perf_counter() - started) * 1000)),
        "error": error,
    }


async def run_settings_health_check(session: AsyncSession) -> dict[str, Any]:
    """探测所有外部服务，并以一次事务写回仍匹配快照的可用状态。"""
    row = await refresh_cache(session)
    stored_providers = _stored_providers(row)
    uses_legacy = not stored_providers
    providers = stored_providers or [_legacy_provider_from_row(row)]
    provider_fingerprints = {
        _provider_name_key(provider.name): _provider_fingerprint(provider)
        for provider in providers
    }
    fofa_snapshot = _fofa_probe_config_from_row(row)
    fofa_fingerprint = _settings_fingerprint(fofa_snapshot)

    # Do not retain a SQLite read transaction while waiting on external services.
    await session.rollback()

    semaphore = asyncio.Semaphore(3)
    all_secrets = tuple(
        secret
        for secret in [
            *(provider.api_key for provider in providers),
            fofa_snapshot["key"],
        ]
        if secret
    )

    async def probe_provider(provider: LLMProviderConfig) -> dict[str, Any]:
        async with semaphore:
            try:
                result = await probe_llm_provider(provider)
            except Exception as exc:
                result = {
                    "ok": False,
                    "latency_ms": 0,
                    "model": provider.model,
                    "protocol": provider.protocol,
                    "error": str(exc),
                }
        return {
            "ok": bool(result.get("ok")),
            "latency_ms": max(0, int(result.get("latency_ms") or 0)),
            "model": str(result.get("model") or provider.model),
            "protocol": str(result.get("protocol") or provider.protocol),
            "error": _sanitize_error_detail(
                str(result.get("error") or ""), redact_values=all_secrets
            ),
        }

    async def probe_fofa() -> dict[str, Any]:
        async with semaphore:
            try:
                result = await probe_fofa_key(
                    fofa_snapshot["key"], fofa_snapshot["base_url"]
                )
            except Exception as exc:
                result = {"ok": False, "latency_ms": 0, "error": str(exc)}
        return {
            "ok": bool(result.get("ok")),
            "latency_ms": max(0, int(result.get("latency_ms") or 0)),
            "error": _sanitize_error_detail(
                str(result.get("error") or ""), redact_values=all_secrets
            ),
        }

    gathered = await asyncio.gather(
        *(probe_provider(provider) for provider in providers),
        probe_fofa(),
    )
    provider_probe_results = list(gathered[:-1])
    fofa_probe_result = gathered[-1]

    provider_results: list[dict[str, Any]] = []
    async with _provider_write_transaction(session) as current_row:
        current_stored = _stored_providers(current_row)
        current_by_name = {
            _provider_name_key(provider.name): (index, provider)
            for index, provider in enumerate(current_stored)
        }
        provider_payloads = [_provider_payload(provider) for provider in current_stored]

        for provider, probe_result in zip(providers, provider_probe_results):
            name_key = _provider_name_key(provider.name)
            current_index: int | None = None
            current_provider: LLMProviderConfig | None = None
            if uses_legacy and not current_stored:
                current_provider = _legacy_provider_from_row(current_row)
            elif not uses_legacy and name_key in current_by_name:
                current_index, current_provider = current_by_name[name_key]

            matches_snapshot = bool(
                current_provider
                and hmac.compare_digest(
                    _provider_fingerprint(current_provider),
                    provider_fingerprints[name_key],
                )
            )
            stale = not matches_snapshot
            auto_disabled = False
            enabled = current_provider.enabled if current_provider else False

            if matches_snapshot and not probe_result["ok"] and enabled:
                disabled_payload = _provider_payload(current_provider)
                disabled_payload["enabled"] = False
                if uses_legacy:
                    provider_payloads = [disabled_payload]
                    current_stored = [LLMProviderConfig.model_validate(disabled_payload)]
                else:
                    provider_payloads[current_index] = disabled_payload
                enabled = False
                auto_disabled = True

            provider_results.append(
                {
                    "name": provider.name,
                    **probe_result,
                    "enabled": enabled,
                    "auto_disabled": auto_disabled,
                    "stale": stale,
                }
            )

        current_fofa = _fofa_probe_config_from_row(current_row)
        fofa_stale = not hmac.compare_digest(
            _settings_fingerprint(current_fofa), fofa_fingerprint
        )
        fofa_enabled = current_fofa["enabled"]
        fofa_auto_disabled = False
        if not fofa_stale:
            desired_fofa_enabled = bool(fofa_probe_result["ok"])
            fofa_auto_disabled = fofa_enabled and not desired_fofa_enabled
            fofa_enabled = desired_fofa_enabled
            stored_fofa = dict(current_row.fofa or {})
            stored_fofa["enabled"] = desired_fofa_enabled
            current_row.fofa = stored_fofa

        if provider_payloads != list(current_row.llm_providers or []):
            current_row.llm_providers = provider_payloads

        await session.commit()
        await session.refresh(current_row)
        _publish_settings_cache(current_row)

        final_stored = _stored_providers(current_row)
        if final_stored:
            public_providers = [_provider_api_view(provider) for provider in final_stored]
        else:
            public_providers = [
                _provider_api_view(_legacy_provider_from_row(current_row), read_only=True)
            ]

    return {
        "checked_at": to_cst_iso(datetime.now(timezone.utc)),
        "provider_results": provider_results,
        "fofa_result": {
            "name": "FOFA",
            **fofa_probe_result,
            "enabled": fofa_enabled,
            "auto_disabled": fofa_auto_disabled,
            "stale": fofa_stale,
        },
        "providers": public_providers,
    }


def _provider_mutation_lock() -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    lock_ref = _provider_mutation_locks.get(loop)
    lock = lock_ref() if lock_ref is not None else None
    if lock is None:
        lock = asyncio.Lock()
        _provider_mutation_locks[loop] = ref(lock)
    return lock


@asynccontextmanager
async def _provider_write_transaction(
    session: AsyncSession,
) -> AsyncIterator[SystemSettings]:
    async with _provider_mutation_lock():
        if session.in_transaction():
            raise RuntimeError("Provider 写入要求使用未开启事务的独立 session")
        await session.execute(text("BEGIN IMMEDIATE"))
        try:
            yield await _settings_row(session)
        except Exception:
            await session.rollback()
            raise


async def _persist_global_provider_disabled(
    name: str,
    safe_reason: str,
    expected_fingerprint: str | None = None,
) -> None:
    """持久化 Router 在线程中判定的 auth/quota 禁用状态。"""
    async with SessionLocal() as session:
        async with _provider_write_transaction(session) as row:
            if not isinstance(row.llm_providers, list) or any(
                not isinstance(provider, dict)
                for provider in (row.llm_providers or [])
            ):
                await session.rollback()
                return
            providers = [dict(provider) for provider in (row.llm_providers or [])]
            changed = False
            for index, provider in enumerate(providers):
                if _provider_name_key(provider.get("name")) != _provider_name_key(name):
                    continue
                try:
                    current = _provider_from_value(provider)
                except (TypeError, ValidationError):
                    await session.rollback()
                    return
                if expected_fingerprint and not hmac.compare_digest(
                    _provider_fingerprint(current), expected_fingerprint
                ):
                    await session.rollback()
                    return
                if provider.get("enabled", True):
                    updated = dict(provider)
                    updated["enabled"] = False
                    providers[index] = updated
                    changed = True
                break
            else:
                if not providers and _provider_name_key(name) == _provider_name_key("Legacy default"):
                    legacy_provider = _legacy_provider()
                    if expected_fingerprint and not hmac.compare_digest(
                        _provider_fingerprint(legacy_provider), expected_fingerprint
                    ):
                        await session.rollback()
                        return
                    legacy = _provider_payload(legacy_provider)
                    legacy["enabled"] = False
                    providers.append(legacy)
                    changed = True
            if not changed:
                await session.rollback()
                return
            row.llm_providers = providers
            await session.commit()
            _publish_settings_cache(row)

    redacted_reason = str(safe_reason or "")
    for provider in providers:
        secret = str(provider.get("api_key") or "")
        if secret:
            redacted_reason = redacted_reason.replace(secret, "<masked>")
    logger.warning("LLM provider '%s' 已持久禁用: %s", name, redacted_reason)


def _provider_disable_callback(
    loop: asyncio.AbstractEventLoop,
    expected_fingerprints: dict[str, str] | None = None,
):
    fingerprints = dict(expected_fingerprints or {})

    def callback(name: str, safe_reason: str) -> None:
        if loop.is_closed():
            logger.warning("事件循环已关闭，无法持久禁用 LLM provider '%s'", name)
            return
        coroutine = _persist_global_provider_disabled(
            name,
            safe_reason,
            expected_fingerprint=fingerprints.get(_provider_name_key(name)),
        )
        try:
            future = asyncio.run_coroutine_threadsafe(coroutine, loop)
        except Exception:
            coroutine.close()
            logger.exception("调度 LLM provider 持久禁用失败: %s", name)
            return

        def consume_result(done) -> None:
            try:
                done.result()
            except Exception:
                logger.exception("持久禁用 LLM provider 失败: %s", name)

        future.add_done_callback(consume_result)

    return callback


def llm_router_for_task(task: Task | None = None) -> LLMRouter:
    """构造任务 Router；仅全局池 Router 会持久化自动禁用。"""
    providers = resolve_llm_providers(task)
    callback = None
    if task_uses_global_pool(task):
        try:
            fingerprints = {
                _provider_name_key(provider.name): _provider_fingerprint(provider)
                for provider in providers
            }
            callback = _provider_disable_callback(
                asyncio.get_running_loop(), fingerprints
            )
        except RuntimeError:
            logger.warning("当前线程没有运行中的事件循环，Provider 自动禁用将不持久化")
    return LLMRouter(
        providers,
        usage_key=task.id if task else None,
        on_provider_disabled=callback,
    )


def llm_router_for_task_optional(task: Task | None = None) -> LLMRouter | None:
    providers = resolve_llm_providers(task)
    if not any(provider.enabled and provider.api_key for provider in providers):
        return None
    try:
        return llm_router_for_task(task)
    except Exception:
        return None


async def list_available_models(
    base_url: str | None = None,
    api_key: str | None = None,
    protocol: str = "openai_chat",
) -> dict[str, Any]:
    """按 Provider 协议拉取可用模型列表。"""
    import httpx

    eff = effective_settings()["llm"]
    requested_base = str(base_url or "").strip()
    base = (requested_base or eff["base_url"] or "").strip().rstrip("/")
    if api_key is None:
        key = "" if requested_base else str(eff["api_key"] or "").strip()
    else:
        key = str(api_key or "").strip()
    if not base:
        return {"ok": False, "error": "未配置模型 base_url", "models": []}
    if not key:
        return {"ok": False, "error": "未配置 API Key，无法拉取模型列表", "models": []}
    try:
        base = LLMProviderConfig(base_url=base).base_url.rstrip("/")
    except ValidationError:
        return {"ok": False, "error": "模型 base_url 格式无效", "models": []}
    if protocol not in {"openai_chat", "anthropic_messages", "openai_responses"}:
        return {"ok": False, "error": "不支持的 LLM 协议", "models": []}
    if base.endswith("/models"):
        url = base
    elif base.endswith("/v1"):
        url = f"{base}/models"
    else:
        url = f"{base}/v1/models"
    from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url

    try:
        assert_safe_outbound_url(url)
    except SsrfBlocked as e:
        return {"ok": False, "error": f"base_url 不被允许：{e}", "models": []}
    if protocol == "anthropic_messages":
        headers = {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        }
    else:
        headers = {"Authorization": f"Bearer {key}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(url, headers=headers)
        if resp.status_code != 200:
            return {"ok": False, "error": f"模型商返回 {resp.status_code}", "models": []}
        data = resp.json()
    except Exception as e:
        return {"ok": False, "error": f"拉取模型列表失败：{type(e).__name__}", "models": []}
    items = data.get("data") or data.get("models") or []
    models: list[str] = []
    for it in items:
        mid = it.get("id") if isinstance(it, dict) else str(it)
        if mid and mid not in models:
            models.append(mid)
    models.sort()
    return {"ok": True, "error": "", "models": models}
