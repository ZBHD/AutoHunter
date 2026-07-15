# FOFA Multi-Key Runtime Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 AutoHunter 增加全局 FOFA 多 Key 管理、逐项与一键检测、粘性故障切换、按失败类型冷却恢复，并让 Collector、Worker FOFA 查询和 Killsweep 共享同一运行时池。

**Architecture:** `SystemSettings.fofa_keys` 保存有序凭据（每项为 `key + base_url` 原子单元）和可恢复运行状态；`FofaKeyRouter` 只负责候选选择、单圈重试和状态变更通知；`settings_service` 负责脱敏 CRUD、指纹保护和事务持久化。任务级 `fofa_config.key` 通过单 Key Router 保持显式覆盖，并同时携带任务端点；池为空时继续回退旧 `fofa.key`、`engines.fofa.key` 或 `FOFA_KEY`，旧全局 `fofa.base_url` 只服务 Legacy/旧任务兼容。

**Tech Stack:** Python 3.12+, FastAPI, SQLAlchemy async/SQLite, Pydantic v2, httpx, pytest, Vue 3, Vite, Node test runner

---

## File Structure

- Create: `tests/test_fofa_key_config.py` - Key 模型、每项 `base_url` 校验、旧库迁移、缓存解析测试。
- Create: `tests/test_fofa_errors.py` - FOFA 错误结构与优先级测试。
- Create: `tests/test_fofa_router.py` - 纯 Router 粘性、轮换、冷却和并发测试。
- Create: `tests/test_fofa_key_api.py` - Key 池 CRUD、检测、脱敏和竞态测试。
- Create: `frontend/src/fofaKeys.js` - Key 列表、可用性、排序和健康结果纯函数。
- Create: `frontend/tests/fofaKeys.test.js` - 前端纯函数与接线契约测试。
- Create: `frontend/src/components/FofaKeysPanel.vue` - 与 LLM Provider 面板同风格的 FOFA Key 管理面板。
- Create: `app/fofa/router.py` - 同步/异步统一的 FOFA Key Router。
- Modify: `app/config.py` - 增加带安全 HTTP(S) `base_url` 的 `FofaKeyConfig`，复用 LLM 基址校验。
- Modify: `app/db/models.py`, `app/db/session.py` - 增加 `fofa_keys` 列和旧库自动迁移。
- Modify: `app/fofa/client.py`, `app/engines/fofa.py` - 统一结构化错误分类。
- Modify: `app/settings_service.py`, `app/api/dto.py`, `app/api/settings.py` - Key 池解析、CRUD、状态持久化和检测 API。
- Modify: `app/agents/collector.py`, `app/tools/executor.py`, `app/agents/worker.py`, `app/agents/killsweep.py`, `app/orchestrator.py`, `app/api/tasks.py` - 所有 FOFA 调用接入 Router，并只在任务重启时清理任务级覆盖状态。
- Modify: `tests/test_settings_service.py`, `tests/test_llm_provider_api.py`, `tests/test_killsweep_service.py` - 兼容与集成回归。
- Modify: `frontend/src/api.js`, `frontend/src/llmProviders.js`, `frontend/src/views/SettingsView.vue`, `frontend/src/style.css` - API、健康汇总和设置页集成。
- Modify: `.env.example`, `README.md` - 记录新池与旧配置优先级。

---

### Task 1: Persist And Validate The FOFA Key Pool

**Files:**
- Create: `tests/test_fofa_key_config.py`
- Modify: `app/config.py`
- Modify: `app/db/models.py`
- Modify: `app/db/session.py`
- Modify: `app/settings_service.py`

- [ ] **Step 1: Write failing model and migration tests**

Add focused tests with these exact contracts:

```python
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.config import FofaKeyConfig


def test_fofa_key_config_normalizes_name_and_runtime_defaults() -> None:
    item = FofaKeyConfig(name="  主账号  ", key="secret-a")
    assert item.name == "主账号"
    assert item.enabled is True
    assert item.runtime_state == "ready"
    assert item.failure_kind == ""
    assert item.failure_count == 0
    assert item.cooldown_until is None


@pytest.mark.parametrize("state", ["unknown", "disabled", "cooling"])
def test_fofa_key_config_rejects_unknown_runtime_state(state: str) -> None:
    with pytest.raises(ValidationError):
        FofaKeyConfig(name="A", key="secret-a", runtime_state=state)


def test_fofa_key_config_accepts_utc_cooldown() -> None:
    cooldown = datetime(2026, 7, 16, 1, 0, tzinfo=timezone.utc)
    item = FofaKeyConfig(
        name="A",
        key="secret-a",
        runtime_state="rate_limited",
        failure_kind="rate_limit",
        failure_count=1,
        cooldown_until=cooldown,
    )
    assert item.cooldown_until == cooldown
```

Extend `tests/test_db_migrations.py` with an old `system_settings` table lacking `fofa_keys`, run `_auto_migrate()`, and assert `PRAGMA table_info(system_settings)` contains `fofa_keys` with default `'[]'`.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q tests/test_fofa_key_config.py tests/test_db_migrations.py`

Expected: collection fails because `FofaKeyConfig` and the `fofa_keys` column are absent.

- [ ] **Step 3: Add the validated model and database column**

Add the model to `app/config.py`:

```python
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


FofaRuntimeState = Literal[
    "ready", "rate_limited", "daily_cooldown", "daily_suspended", "auth_invalid"
]
FofaFailureKindValue = Literal["", "auth", "rate_limit", "daily_limit", "transient"]


class FofaKeyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    key: str = ""
    base_url: str = "https://fofa.info"
    enabled: bool = True
    runtime_state: FofaRuntimeState = "ready"
    failure_kind: FofaFailureKindValue = ""
    failure_count: int = Field(default=0, ge=0)
    cooldown_until: datetime | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        normalized = str(value or "").strip()
        if not normalized or "/" in normalized or "\\" in normalized:
            raise ValueError("FOFA Key 名称必须非空且可用于 API 路径")
        if normalized.casefold() == "order":
            raise ValueError("FOFA Key 名称不能使用保留字 order")
        return normalized
```

`base_url` 校验必须与 `LLMProviderConfig` 共用同一 HTTP(S) URL 规则：绝对 URL、非空 host、合法端口、无 userinfo/query/fragment，trim 后保留私有路径。`repr`/`str` 继续隐藏 Key。

Add `fofa_keys: Mapped[list] = mapped_column(JSON, default=list)` to `SystemSettings`; add `("system_settings", "fofa_keys", "JSON DEFAULT '[]'")` to `_MIGRATIONS`; include a deep-copied `fofa_keys` list in `_cache`, `_publish_settings_cache()` and `effective_settings()`.

- [ ] **Step 4: Add legacy resolution tests and implementation**

Tests must assert:

```python
def test_empty_fofa_pool_uses_legacy_key(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "legacy-secret")
    set_cache(fofa_keys=[], fofa={})
    keys = settings_service.resolve_fofa_keys()
    assert [(item.name, item.key) for item in keys] == [("Legacy Key", "legacy-secret")]


def test_nonempty_fofa_pool_wins_over_legacy_key(monkeypatch) -> None:
    monkeypatch.setenv("FOFA_KEY", "legacy-secret")
    set_cache(fofa_keys=[fofa_key_dict("Primary", "pool-secret")])
    keys = settings_service.resolve_fofa_keys()
    assert [(item.name, item.key) for item in keys] == [("Primary", "pool-secret")]
```

Implement `resolve_fofa_keys(task=None)` so task `fofa_config.key` returns a single `Task override` entry carrying `fofa_config.base_url` (缺省回退旧全局端点); a stored nonempty pool wins and each item preserves its own `base_url`; an empty pool synthesizes read-only legacy behavior at the API layer from `fofa.key`, `engines.fofa.key`, then `FOFA_KEY`. Legacy `base_url` follows stored `fofa.base_url` > `FOFA_BASE_URL` > official default, with `engines.fofa.base_url` retained only through existing `resolve_engine_base_url` compatibility semantics. Historical pool items missing `base_url` receive the model default and never fall back to Legacy.

- [ ] **Step 5: Run GREEN and commit**

Run: `python -m pytest -q tests/test_fofa_key_config.py tests/test_db_migrations.py tests/test_settings_service.py -k "fofa or migration"`

Expected: all selected tests pass.

Commit:

```powershell
git add app/config.py app/db/models.py app/db/session.py app/settings_service.py tests/test_fofa_key_config.py tests/test_db_migrations.py tests/test_settings_service.py
git commit -m "功能：增加 FOFA Key 池模型与数据库迁移"
```

---

### Task 1B: Support A Per-Key FOFA Endpoint

**Files:**
- Modify: `app/config.py`
- Modify: `app/settings_service.py`
- Modify: `tests/test_fofa_key_config.py`
- Modify: `tests/test_settings_service.py`
- Modify: `docs/superpowers/specs/2026-07-16-fofa-multi-key-rotation-design.md`
- Modify: `docs/superpowers/plans/2026-07-16-fofa-multi-key-rotation-implementation.md`

- [ ] **Step 1: Write failing endpoint and resolution tests**

Cover the official default, private HTTP(S) paths, userinfo/query/fragment/bad-port/non-HTTP rejection, secret-free `repr`/`str`, pool preservation, task `key + base_url` override, task endpoint fallback to the old global resolver, Legacy storage/environment/default precedence, and deep-copy behavior for `base_url`.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q tests/test_fofa_key_config.py tests/test_settings_service.py`

Expected: endpoint-focused tests fail because `FofaKeyConfig` has no `base_url` and resolution returns incomplete credentials.

- [ ] **Step 3: Implement model and parser extension**

Extract the existing LLM HTTP base URL validator into a shared helper, add `FofaKeyConfig.base_url` with the official default, and pass `base_url` through task, pool and Legacy branches of `resolve_fofa_keys`. Do not modify FOFA clients or engine request logic; endpoint validation remains at model/parser boundaries.

- [ ] **Step 4: Run GREEN and commit**

Run:

```powershell
python -m pytest -q tests/test_fofa_key_config.py tests/test_settings_service.py tests/test_db_migrations.py
```

Commit:

```powershell
git add app/config.py app/settings_service.py tests/test_fofa_key_config.py tests/test_settings_service.py docs/superpowers/specs/2026-07-16-fofa-multi-key-rotation-design.md docs/superpowers/plans/2026-07-16-fofa-multi-key-rotation-implementation.md
git commit -m "功能：支持每个 FOFA Key 自定义端点"
```

---

### Task 2: Structure FOFA Failure Classification

**Files:**
- Create: `tests/test_fofa_errors.py`
- Modify: `app/fofa/client.py`
- Modify: `app/engines/fofa.py`

- [ ] **Step 1: Write failing priority and redaction tests**

```python
from app.fofa.client import FofaError, classify_fofa_failure


def test_daily_limit_wins_over_generic_quota_marker() -> None:
    classified = classify_fofa_failure("[820041] daily quota exceeded", status=200)
    assert classified == ("daily_limit", "820041", None)


def test_http_429_is_rate_limit() -> None:
    assert classify_fofa_failure("Too Many Requests", status=429) == (
        "rate_limit", "429", None
    )


def test_invalid_key_is_auth() -> None:
    assert classify_fofa_failure("invalid key", status=401)[0] == "auth"


def test_network_failure_is_transient() -> None:
    error = FofaError("connection reset")
    assert error.kind == "transient"
    assert error.account_error is False
```

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q tests/test_fofa_errors.py`

Expected: fails because `classify_fofa_failure` and structured fields are absent.

- [ ] **Step 3: Implement one shared error type and classifier**

In `app/fofa/client.py`, define:

```python
class FofaError(Exception):
    def __init__(
        self,
        message: str,
        *,
        kind: str = "transient",
        code: str = "",
        retry_after: int | None = None,
    ):
        super().__init__(message)
        self.kind = kind
        self.code = code
        self.retry_after = retry_after
        self.account_error = kind == "auth"


def classify_fofa_failure(
    message: str, *, status: int | None = None, retry_after: int | None = None
) -> tuple[str, str, int | None]:
    text = str(message or "").lower()
    if "820041" in text or any(marker in text for marker in ("每日", "daily limit", "daily quota")):
        return "daily_limit", "820041" if "820041" in text else "daily_limit", 3600
    if status == 429 or any(marker in text for marker in ("q3005", "too many", "rate limit", "请求太频繁")):
        return "rate_limit", str(status or "rate_limit"), retry_after
    if status in {401, 403} or any(marker in text for marker in ("invalid key", "账号无效", "账号过期", "权限不足", "unauthorized", "forbidden")):
        return "auth", str(status or "auth"), None
    return "transient", str(status or ""), None
```

Update `search()` and `get_userinfo()` to construct `FofaError` with these fields. Remove the duplicate error class from `app/engines/fofa.py`; import the shared type and classifier there, preserving `account_error` for current callers.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python -m pytest -q tests/test_fofa_errors.py tests/test_llm_provider_api.py -k "fofa_probe"`

Expected: classifier and existing probe tests pass; returned errors contain no Key.

Commit:

```powershell
git add app/fofa/client.py app/engines/fofa.py tests/test_fofa_errors.py tests/test_llm_provider_api.py
git commit -m "功能：统一 FOFA 结构化错误分类"
```

---

### Task 3: Build The Sticky FOFA Key Router

**Files:**
- Create: `app/fofa/router.py`
- Create: `tests/test_fofa_router.py`
- Modify: `app/fofa/__init__.py`

- [ ] **Step 1: Write failing sticky and failover tests**

Use an injected clock and fake operations; assert the exact request order:

```python
import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from app.config import FofaKeyConfig
from app.fofa.client import FofaError
from app.fofa.router import FofaKeyRouter, FofaPoolExhaustedError


def key(name: str, secret: str) -> FofaKeyConfig:
    return FofaKeyConfig(name=name, key=secret)


def test_sync_router_is_sticky_after_failover() -> None:
    calls: list[str] = []
    router = FofaKeyRouter([key("A", "a"), key("B", "b")], active_name="A")

    def first(secret: str) -> str:
        calls.append(secret)
        if secret == "a":
            raise FofaError("invalid key", kind="auth")
        return "ok"

    assert router.execute_sync(first) == "ok"
    assert router.execute_sync(lambda secret: calls.append(secret) or "again") == "again"
    assert calls == ["a", "b", "b"]


def test_async_router_tries_each_key_once() -> None:
    calls: list[str] = []
    router = FofaKeyRouter([key("A", "a"), key("B", "b")], active_name="A")

    async def fail(secret: str) -> str:
        calls.append(secret)
        raise FofaError("limited", kind="rate_limit")

    with pytest.raises(FofaPoolExhaustedError):
        asyncio.run(router.execute_async(fail))
    assert calls == ["a", "b"]
```

Add tests for 60/120/240/480/600 rate backoff, one-hour daily cooldown, transition to `daily_suspended` on count 12, transient failure retaining the active Key, earliest retry reporting, disabled entries, deletion/reorder reconstruction, state-change idempotence, and two threads reporting the same auth failure.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest -q tests/test_fofa_router.py`

Expected: import fails because `app.fofa.router` is absent.

- [ ] **Step 3: Implement the pure Router contract**

Create these public types and signatures:

```python
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Awaitable, Callable, Generic, TypeVar

from app.config import FofaKeyConfig

T = TypeVar("T")


class FofaFailureKind(StrEnum):
    AUTH = "auth"
    RATE_LIMIT = "rate_limit"
    DAILY_LIMIT = "daily_limit"
    TRANSIENT = "transient"


@dataclass(frozen=True)
class FofaKeyStateChange:
    name: str
    runtime_state: str
    failure_kind: str
    failure_count: int
    cooldown_until: datetime | None
    active_key_name: str


@dataclass(frozen=True)
class FofaPoolFailure:
    name: str
    kind: str
    message: str


class FofaPoolExhaustedError(RuntimeError):
    def __init__(
        self,
        failures: list[FofaPoolFailure],
        next_retry_at: datetime | None,
    ):
        self.failures = failures
        self.next_retry_at = next_retry_at
        super().__init__(f"FOFA Key 池暂不可用，共 {len(failures)} 项")


class FofaKeyRouter(Generic[T]):
    def __init__(
        self,
        keys: list[FofaKeyConfig],
        *,
        active_name: str = "",
        on_state_change: Callable[[FofaKeyStateChange], None] | None = None,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    ):
        self._keys = [item.model_copy(deep=True) for item in keys]
        self._active_name = active_name
        self._on_state_change = on_state_change
        self._now = now

    def execute_sync(self, operation: Callable[[str, str], T]) -> T:
        return self._execute_sync_ring(operation)

    async def execute_async(self, operation: Callable[[str, str], Awaitable[T]]) -> T:
        return await self._execute_async_ring(operation)
```

每次 operation/lease 必须同时传递选中凭据的 `key` 和 `base_url`；禁止只传 Key 再从全局端点补齐。候选快照、状态指纹和状态回调均包含这两个字段。

Use `threading.RLock` only around candidate snapshots and state mutation. Release the lock before calling `operation`. Sanitize `FofaPoolFailure.message` by replacing every configured Key with `<masked>`. State callbacks fire only when the tuple `(runtime_state, failure_kind, failure_count, cooldown_until, active_name)` changes.

Implement `_candidate_snapshot`, `_mark_success`, `_mark_failure`, `_execute_sync_ring`, and `_execute_async_ring` in the same module. Convert `FofaError.kind` through `FofaFailureKind`; unknown values map to `TRANSIENT`.

- [ ] **Step 4: Run Router tests repeatedly and commit**

Run:

```powershell
python -m pytest -q tests/test_fofa_router.py
python -m pytest -q tests/test_fofa_router.py -x --count=10
```

Expected: both runs pass. If `pytest-repeat` is absent, run the first command ten times with `1..10 | ForEach-Object { python -m pytest -q tests/test_fofa_router.py }`.

Commit:

```powershell
git add app/fofa/router.py app/fofa/__init__.py tests/test_fofa_router.py
git commit -m "功能：实现 FOFA Key 粘性轮换路由器"
```

---

### Task 4: Add Masked CRUD And Health APIs

**Files:**
- Create: `tests/test_fofa_key_api.py`
- Modify: `app/api/dto.py`
- Modify: `app/api/settings.py`
- Modify: `app/settings_service.py`
- Modify: `tests/test_llm_provider_api.py`

- [ ] **Step 1: Write failing CRUD and secret tests**

Cover the public contract with a temporary SQLite API fixture:

```python
def test_fofa_key_crud_never_returns_plaintext_keys(fofa_key_api) -> None:
    client, raw_keys = fofa_key_api
    secret = "fofa-secret-VERYSECRET"
    created = client.post(
        "/api/settings/fofa-keys",
        json={"name": "Primary", "key": secret, "enabled": True},
    )
    assert created.status_code == 200
    assert created.json()["fofa_keys"][0]["key_set"] is True
    assert secret not in created.text
    assert raw_keys()[0]["key"] == secret


def test_successful_probe_clears_runtime_block_but_preserves_manual_disable(
    fofa_key_api, monkeypatch
) -> None:
    client, _raw_keys = fofa_key_api
    seed_key(name="Paused", enabled=False, runtime_state="auth_invalid")
    monkeypatch.setattr(settings_service, "probe_fofa_key", successful_probe)
    response = client.post("/api/settings/fofa-keys/Paused/test")
    item = response.json()["fofa_key"]
    assert item["enabled"] is False
    assert item["runtime_state"] == "ready"
```

Add tests for case-insensitive duplicates, reserved names, masked-key preservation, replacing a Key clearing runtime state, enable/disable, active deletion, full permutation ordering, unknown names, read-only Legacy Key, and malformed stored pool recovery errors.

- [ ] **Step 2: Write failing one-click health and stale-result tests**

Extend the health endpoint tests to seed ready, auth-invalid, daily-cooldown and manually disabled keys. Assert `fofa_results` order matches storage order, every item is probed with concurrency cap three, successful results clear runtime blocks, manual disabled stays disabled, failures are sanitized, and a Key changed during probing yields `stale=true` without overwriting the replacement.

- [ ] **Step 3: Run tests and verify RED**

Run: `python -m pytest -q tests/test_fofa_key_api.py tests/test_llm_provider_api.py -k "fofa or health_check"`

Expected: new routes and `fofa_results` are absent.

- [ ] **Step 4: Implement DTOs, services and route order**

Add DTOs:

```python
class FofaKeyDTO(BaseModel):
    name: str
    key: str = ""
    base_url: str = "https://fofa.info"
    enabled: bool = True


class FofaKeyUpdateDTO(BaseModel):
    key: str | None = None
    base_url: str | None = None
    enabled: bool | None = None


class FofaKeyOrderDTO(BaseModel):
    names: list[str]
```

Add service functions `list_fofa_keys`, `create_fofa_key`, `update_fofa_key`, `delete_fofa_key`, `reorder_fofa_keys`, `get_fofa_key`, `test_fofa_key`, `_persist_fofa_key_state`, and `_fofa_state_callback`. Reuse `_MASK_PLACEHOLDER`, `_settings_fingerprint`, `_provider_write_transaction`, `BEGIN IMMEDIATE`, and URL-encoded secret sanitization patterns already used by LLM Provider health checks.

Add routes in this order:

```text
GET    /api/settings/fofa-keys
POST   /api/settings/fofa-keys
PUT    /api/settings/fofa-keys/order
PUT    /api/settings/fofa-keys/{name}
DELETE /api/settings/fofa-keys/{name}
POST   /api/settings/fofa-keys/{name}/test
```

`public_settings_view()` returns `fofa_keys` including each item’s `base_url`; `run_settings_health_check()` returns `fofa_results` for pool mode and retains `fofa_result` for legacy mode. Every single-item and one-click probe calls the item’s own `key + base_url` and applies SSRF validation per endpoint. Apply probe results atomically only when the full credential fingerprint still matches.

- [ ] **Step 5: Run GREEN and commit**

Run: `python -m pytest -q tests/test_fofa_key_api.py tests/test_llm_provider_api.py tests/test_settings_service.py`

Expected: all files pass and response bodies contain no configured secret.

Commit:

```powershell
git add app/api/dto.py app/api/settings.py app/settings_service.py tests/test_fofa_key_api.py tests/test_llm_provider_api.py tests/test_settings_service.py
git commit -m "功能：增加 FOFA Key 池管理与健康检测接口"
```

---

### Task 5: Route Every FOFA Runtime Consumer Through The Pool

**Files:**
- Modify: `app/agents/collector.py`
- Modify: `app/tools/executor.py`
- Modify: `app/agents/worker.py`
- Modify: `app/agents/killsweep.py`
- Modify: `app/orchestrator.py`
- Modify: `app/api/tasks.py`
- Modify: `tests/test_collector_stop_search.py`
- Modify: `tests/test_killsweep_service.py`
- Create: `tests/test_fofa_runtime_consumers.py`

- [ ] **Step 1: Write failing Collector integration tests**

```python
async def test_collector_retries_same_page_with_next_fofa_key(
    session, task, monkeypatch
) -> None:
    calls: list[tuple[str, int]] = []

    async def search(key, query, page, page_size, base_url):
        calls.append((key, page))
        if key == "bad":
            raise FofaError("invalid key", kind="auth")
        return EngineResult(
            fields=["host", "ip", "port", "title", "domain", "org"],
            results=[], size=0, page=page, engine="fofa"
        )

    router = FofaKeyRouter([fofa_key("A", "bad"), fofa_key("B", "good")])
    monkeypatch.setattr(settings_service, "fofa_router_for_task", lambda _task: router)
    monkeypatch.setattr(FofaEngine, "search", search)
    await collector._fofa_collect(session, task, set(), {}, None)
    assert calls == [("bad", 1), ("good", 1)]
    assert task.fofa_config["cursor"] == 1
```

Add tests that all-cooling returns set a task-level next retry once and stay silent during the wait, all-auth-invalid pauses with a safe summary, task override creates a single candidate, and transient errors leave the page cursor unchanged.

- [ ] **Step 2: Write failing Worker and Killsweep contract tests**

Inject a fake Router into `ToolExecutor` and `KillsweepHunter`; assert `fofa_lookup` and `fofa_search` call `execute_sync`, rotate after auth failure, return the existing result shapes, and keep raw Key values out of captures/events.

- [ ] **Step 3: Run tests and verify RED**

Run: `python -m pytest -q tests/test_fofa_runtime_consumers.py tests/test_collector_stop_search.py tests/test_killsweep_service.py -k "fofa"`

Expected: constructors and runtime paths still accept raw `fofa_key` only.

- [ ] **Step 4: Integrate Collector without duplicating retry policy**

Replace direct key resolution and `engine.search(key, ...)` with:

```python
router = fofa_router_for_task(task)
res = await router.execute_async(
    lambda key: engine.search(
        key,
        cur_query,
        page=next_cursor,
        page_size=size,
        base_url=base_url,
    )
)
```

Catch `FofaPoolExhaustedError` once. Store only pool-level `next_retry_at`, summary kind and transition marker in `task.fofa_config`; remove the old Collector substring classification for single-Key account and rate-limit failures. Keep non-FOFA engine handling on its current path.

- [ ] **Step 5: Integrate synchronous consumers and injection points**

Add `fofa_router` constructor parameters to `ToolExecutor` and `KillsweepHunter`. Wrap their current HTTP operations:

```python
return self.fofa_router.execute_sync(
    lambda key: self._fofa_lookup_with_key(key, query=q, size=safe_size)
)
```

Build the Router on the orchestrator event loop before dispatching Worker/Killsweep to threads, matching the LLM disable callback pattern. Pass each selected `key + base_url` pair through Collector, Worker and Killsweep operations; preserve task override endpoint behavior and keep the old `fofa_base_url` only for Legacy/old-task fallback. Remove long-lived global raw Key injection after all call sites migrate.

Update `start_task()` so it clears `daily_suspended`, failure count and pool-wait markers only from task-level `fofa_config` state. It must leave every item in global `SystemSettings.fofa_keys` unchanged.

- [ ] **Step 6: Run GREEN and commit**

Run:

```powershell
python -m pytest -q tests/test_fofa_runtime_consumers.py tests/test_collector_stop_search.py tests/test_killsweep_service.py
python -m pytest -q tests/test_src_workflow.py tests/test_llm_consumers.py
```

Expected: selected runtime tests pass and existing Worker/Killsweep contracts stay green.

Commit:

```powershell
git add app/agents/collector.py app/tools/executor.py app/agents/worker.py app/agents/killsweep.py app/orchestrator.py app/api/tasks.py tests/test_fofa_runtime_consumers.py tests/test_collector_stop_search.py tests/test_killsweep_service.py
git commit -m "功能：接入全部 FOFA 运行时调用的 Key 轮换"
```

---

### Task 6: Build The LLM-Style FOFA Key Management UI

**Files:**
- Create: `frontend/src/fofaKeys.js`
- Create: `frontend/tests/fofaKeys.test.js`
- Create: `frontend/src/components/FofaKeysPanel.vue`
- Modify: `frontend/src/api.js`
- Modify: `frontend/src/llmProviders.js`
- Modify: `frontend/src/views/SettingsView.vue`
- Modify: `frontend/src/style.css`
- Modify: `frontend/tests/settingsHealth.test.js`

- [ ] **Step 1: Write failing pure helper and health summary tests**

```javascript
import test from "node:test";
import assert from "node:assert/strict";
import { fofaKeyList, isFofaKeyUsable, moveFofaKey } from "../src/fofaKeys.js";
import { summarizeHealthCheck } from "../src/llmProviders.js";

test("FOFA key usability excludes disabled, blocked, and cooling entries", () => {
  assert.equal(isFofaKeyUsable({ enabled: true, key_set: true, runtime_state: "ready" }), true);
  assert.equal(isFofaKeyUsable({ enabled: false, key_set: true, runtime_state: "ready" }), false);
  assert.equal(isFofaKeyUsable({ enabled: true, key_set: true, runtime_state: "auth_invalid" }), false);
});

test("FOFA list accepts arrays and wrapped mutation responses", () => {
  const keys = [{ name: "Primary" }];
  assert.equal(fofaKeyList(keys), keys);
  assert.equal(fofaKeyList({ fofa_keys: keys }), keys);
});

test("FOFA order helper is immutable", () => {
  const names = ["A", "B", "C"];
  assert.deepEqual(moveFofaKey(names, 1, -1), ["B", "A", "C"]);
  assert.deepEqual(names, ["A", "B", "C"]);
});

test("health summary appends every FOFA key result", () => {
  const summary = summarizeHealthCheck({
    provider_results: [{ name: "LLM", ok: true }],
    fofa_results: [{ name: "FOFA A", ok: true }, { name: "FOFA B", ok: false }],
  });
  assert.deepEqual(summary.results.map((item) => item.name), ["LLM", "FOFA A", "FOFA B"]);
});
```

- [ ] **Step 2: Run tests and verify RED**

Run: `Set-Location frontend; npm test`

Expected: `fofaKeys.js` import fails and health summary ignores `fofa_results`.

- [ ] **Step 3: Implement pure helpers and API methods**

Implement `fofaKeyList`, `isFofaKeyUsable`, `moveFofaKey`, `fofaHealthSnapshot`, and `formatFofaCooldown`. Add API methods with encoded names:

```javascript
listFofaKeys: () => req("GET", "/api/settings/fofa-keys"),
createFofaKey: (data) => req("POST", "/api/settings/fofa-keys", data),
updateFofaKey: (name, data) => req("PUT", `/api/settings/fofa-keys/${encodeURIComponent(name)}`, data),
deleteFofaKey: (name) => req("DELETE", `/api/settings/fofa-keys/${encodeURIComponent(name)}`),
testFofaKey: (name) => req("POST", `/api/settings/fofa-keys/${encodeURIComponent(name)}/test`),
orderFofaKeys: (names) => req("PUT", "/api/settings/fofa-keys/order", { names }),
```

Update `summarizeHealthCheck()` to append `fofa_results` when present and fall back to legacy `fofa_result` otherwise.

- [ ] **Step 4: Implement `FofaKeysPanel.vue` in the LLM Provider visual pattern**

Copy the interaction structure of `LlmProvidersPanel.vue`: loading/empty/error states, ordered rows, up/down icon controls, enable switch, test action, edit/delete icon actions, edit modal, delete confirmation, `defineExpose({ applyHealthCheck })`, and `defineEmits(["change", "mutated"])`.

Use FOFA-specific row content only: masked Key, current marker, runtime status badge, cooldown time and latency. Reuse existing `.provider-*` classes where semantics match; add narrowly scoped `.fofa-key-*` rules for status colors. Use the existing lucide icon component/import pattern and tooltips.

- [ ] **Step 5: Integrate SettingsView and stale health behavior**

Replace the single global FOFA Key input with `<FofaKeysPanel ref="fofaKeyPanel" @change="fofaKeys = $event" @mutated="markHealthStale" />`. Each row edits its own `base_url`; keep the old `fofa_base_url` field only as the Legacy/old-task fallback alongside `max_pages`, `page_size`, and `default_intent_mode`. In `runHealthCheck()`, call both `providerPanel.applyHealthCheck(response)` and `fofaKeyPanel.applyHealthCheck(response)`; health results identify the endpoint used for each Key.

- [ ] **Step 6: Verify frontend and commit**

Run:

```powershell
Set-Location frontend
npm test
npm run build
```

Expected: all Node tests pass and Vite production build succeeds.

Commit:

```powershell
git add frontend/src/fofaKeys.js frontend/tests/fofaKeys.test.js frontend/src/components/FofaKeysPanel.vue frontend/src/api.js frontend/src/llmProviders.js frontend/src/views/SettingsView.vue frontend/src/style.css frontend/tests/settingsHealth.test.js
git commit -m "功能：增加 FOFA Key 池设置面板"
```

---

### Task 7: Document Compatibility And Run Full Verification

**Files:**
- Modify: `.env.example`
- Modify: `README.md`
- Modify: `tests/test_app_imports.py`

- [ ] **Step 1: Add documentation and import regression assertions**

Document the exact precedence:

```text
任务级 fofa_config.key > 非空全局 fofa_keys 池 > 旧 fofa.key > engines.fofa.key > FOFA_KEY
```

Document sticky selection, failure-triggered ring rotation, runtime states, one-click recovery, legacy read-only display, and shared use by Collector/Worker/Killsweep. Keep `.env.example` describing `FOFA_KEY` as the empty-pool compatibility fallback.

Add import checks for `app.fofa.router`, `app.api.settings`, and `app.main`.

- [ ] **Step 2: Run focused secret and migration verification**

Run:

```powershell
python -m pytest -q tests/test_fofa_key_config.py tests/test_fofa_errors.py tests/test_fofa_router.py tests/test_fofa_key_api.py tests/test_fofa_runtime_consumers.py
python -m pytest -q tests/test_db_migrations.py tests/test_settings_service.py tests/test_llm_provider_api.py
```

Expected: all focused tests pass; no assertion finds configured Key material in logs or API responses.

- [ ] **Step 3: Run complete backend verification**

Run:

```powershell
python -m pytest -q
python -m compileall -q app tests
python -c "import app.main; import app.fofa.router; print('OK')"
```

Expected: full suite passes, compileall exits zero, import command prints `OK`.

- [ ] **Step 4: Run complete frontend verification**

Run:

```powershell
Set-Location frontend
npm test
npm run build
```

Expected: all Node tests pass and Vite emits a successful production build.

- [ ] **Step 5: Start an isolated server and smoke-test masked APIs**

Use a temporary `DB_PATH`, start Uvicorn on a free port, then verify:

```text
GET  /health                                      -> 200
GET  /api/settings                                -> fofa_keys present, secrets masked
POST /api/settings/fofa-keys                      -> creates masked row
PUT  /api/settings/fofa-keys/order                -> preserves secrets and order
POST /api/settings/fofa-keys/{name}/test          -> safe result shape
POST /api/settings/health-check                   -> provider_results + fofa_results
```

Use mocked probes or disposable test credentials for outbound checks. Stop the server after smoke verification.

- [ ] **Step 6: Review the final diff and commit documentation**

Run:

```powershell
git diff --check
git status --short
git diff --stat
```

Confirm the existing user changes in `app/agents/history.py`, `app/agents/worker.py`, and `tests/test_src_workflow.py` remain intact and only feature files enter this commit.

Commit:

```powershell
git add .env.example README.md tests/test_app_imports.py
git commit -m "文档：说明 FOFA 多 Key 轮换与兼容优先级"
```

---

## Final Review Checklist

- [ ] 池为空时旧 FOFA Key 仍可用，池非空时不会回退旧 Key。
- [ ] 每个凭据单元始终以 `key + base_url` 原子传递、轮换、检测和指纹校验；池项缺省端点补为官网。
- [ ] Legacy/旧任务才读取全局 `fofa.base_url`；池项和任务自定义端点不被全局值覆盖。
- [ ] 任务级单 Key 绕过全局池，同时复用结构化错误分类。
- [ ] 每次业务请求对每个 Key 最多尝试一次，分页游标只推进一次。
- [ ] 认证失败、限流、每日额度和瞬时故障按设计进入不同状态。
- [ ] `820041` 优先于通用 quota 分类，冷却期间保持静默。
- [ ] 手动停用与运行阻断彼此独立，检测成功保留手动开关。
- [ ] CRUD、健康检测、日志、事件和抓包证据均无明文或 URL 编码后的 Key。
- [ ] 每个 Key 的健康检测、单项检测和 SSRF 防护均针对其自身端点执行。
- [ ] Collector、Worker、Killsweep 的 FOFA 请求全部经过 Router。
- [ ] 设置页视觉和交互与 LLM Provider 面板一致。
- [ ] 后端全量测试、前端测试和生产构建全部通过。
