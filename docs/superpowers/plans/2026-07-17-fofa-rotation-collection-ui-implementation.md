# FOFA 轮换搜集界面实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在现有 FOFA 多 Key Router 与 Key 池设置功能之上，补齐任务搜集进度、轮换摘要、全池等待/阻断状态，以及新建/编辑任务的全局池与任务专用 Key 分流。

**Architecture:** 复用已经合入的 `app/fofa/router.py`、`app/settings_service.py` 和 `FofaKeysPanel.vue`，新增一个无凭据的任务运行摘要模块。Router 通过每次请求的尝试回调把实际使用的 Key 与切换原因交给 Collector；Collector 将脱敏摘要持久化到任务 `fofa_config` 并通过 WebSocket 发布。前端用纯函数状态机消费任务快照和事件，BoardView 只展示本任务最近成功 Key，SettingsView 继续展示全局粘性 Key。

**Tech Stack:** Python 3.12、FastAPI、SQLAlchemy async、Pydantic v2、pytest、Vue 3、Vite、Node test runner

---

## 当前基线与边界

多 Key Router、Key 池数据库/API、`FofaKeysPanel.vue`、`fofaKeys.js` 及其基础测试已经存在于当前分支。本计划不重做这些功能，不触碰工作区中与本功能无关的 Markdown 下载改动：

- `app/fofa/router.py` 已提供粘性选择、失败分类、冷却、`FofaPoolExhaustedError` 和状态回调。
- `app/settings_service.py` 已提供全局池、任务级覆盖、Legacy 回退和 Router 缓存。
- `frontend/src/components/FofaKeysPanel.vue` 已提供 Key 池 CRUD、排序、启停、检测和冷却展示。
- 当前缺口是任务级运行摘要、Collector 轮换事件、BoardView 状态机，以及任务表单清除/选择任务专用 Key 的能力。

每个任务完成后先运行对应的定向测试，再提交中文 commit；实现时只暂存本计划列出的文件。

### Task 1: 增加无凭据的任务 FOFA 运行摘要

**Files:**
- Create: `app/fofa/runtime.py`
- Create: `tests/test_fofa_runtime_ui.py`
- Modify: `app/api/tasks.py:76-83,205-223`
- Modify: `tests/test_task_operations_api.py:216-232`

- [ ] **Step 1: 写运行摘要失败测试**

在 `tests/test_fofa_runtime_ui.py` 中加入：

```python
from datetime import datetime, timezone
from types import SimpleNamespace

from app.config import FofaKeyConfig
from app.fofa.router import FofaKeyRouter
from app.fofa.runtime import public_runtime_summary


def test_public_runtime_summary_distinguishes_pool_active_and_task_last_key() -> None:
    router = FofaKeyRouter([
        FofaKeyConfig(name="Primary", key="secret-a"),
        FofaKeyConfig(name="Backup", key="secret-b", runtime_state="rate_limited",
                      cooldown_until=datetime(2026, 7, 17, 1, 0, tzinfo=timezone.utc)),
    ], active_name="Primary")
    task = SimpleNamespace(fofa_config={
        "last_key_name": "Backup",
        "last_rotation": {
            "from_key_name": "Primary",
            "to_key_name": "Backup",
            "reason": "rate_limit",
        },
    })

    result = public_runtime_summary(task, router, now=datetime(2026, 7, 17, 0, 0, tzinfo=timezone.utc))

    assert result["key_source"] == "global_pool"
    assert result["active_key_name"] == "Primary"
    assert result["last_key_name"] == "Backup"
    assert result["pool_available"] == 1
    assert result["pool_total"] == 2
    assert result["pool_state"] == "ready"
    assert result["last_rotation"]["reason"] == "rate_limit"
    assert "secret" not in repr(result)


def test_public_runtime_summary_marks_all_cooling_with_earliest_retry() -> None:
    retry = datetime(2026, 7, 17, 0, 20, tzinfo=timezone.utc)
    router = FofaKeyRouter([
        FofaKeyConfig(name="Primary", key="secret-a", runtime_state="rate_limited",
                      cooldown_until=retry),
    ], active_name="Primary")

    result = public_runtime_summary(
        SimpleNamespace(fofa_config={}), router,
        now=datetime(2026, 7, 17, 0, 0, tzinfo=timezone.utc),
    )

    assert result["pool_state"] == "cooling"
    assert result["pool_available"] == 0
    assert result["cooldown_until"].startswith("2026-07-17T00:20:00")


def test_public_runtime_summary_marks_task_override_without_pool_details() -> None:
    router = FofaKeyRouter([FofaKeyConfig(name="Task override", key="secret")])

    result = public_runtime_summary(
        SimpleNamespace(fofa_config={"key": "secret", "last_key_name": "Task override"}),
        router,
    )

    assert result["key_source"] == "task_override"
    assert result["last_key_name"] == "Task override"
    assert result["pool_total"] == 1

```

- [ ] **Step 2: 运行失败测试**

Run: `python -m pytest -q tests/test_fofa_runtime_ui.py`

Expected: FAIL with `ModuleNotFoundError: No module named 'app.fofa.runtime'`.

- [ ] **Step 3: 实现运行摘要模块**

在 `app/fofa/runtime.py` 中实现只返回逻辑名称和状态的函数：

```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


_BLOCKED = {"auth_invalid", "daily_suspended"}
_COOLING = {"rate_limited", "daily_cooldown"}
_ROTATION_REASONS = {"auth", "rate_limit", "daily_limit"}


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def public_runtime_summary(task: Any, router: Any, now: datetime | None = None) -> dict[str, Any]:
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    cfg = dict(getattr(task, "fofa_config", None) or {})
    snapshots = list(router.state_snapshot)
    configured = [item for item in snapshots if item.key_set]
    available = []
    cooling = []
    blocked = []
    for item in configured:
        if not item.enabled:
            continue
        if item.runtime_state in _BLOCKED:
            blocked.append(item)
            continue
        if item.cooldown_until is not None and item.cooldown_until > current:
            cooling.append(item)
            continue
        available.append(item)

    if available:
        pool_state = "ready"
    elif cooling:
        pool_state = "cooling"
    else:
        pool_state = "blocked"

    retry_values = [item.cooldown_until for item in cooling if item.cooldown_until is not None]
    last_rotation = cfg.get("last_rotation")
    if not isinstance(last_rotation, dict):
        last_rotation = None
    elif last_rotation.get("reason") not in _ROTATION_REASONS:
        last_rotation = None

    source = "task_override" if any(item.name == "Task override" for item in configured) else "global_pool"
    if any(item.name == "Legacy Key" for item in configured):
        source = "legacy"

    return {
        "key_source": source,
        "active_key_name": "" if source != "global_pool" else str(router.active_name or ""),
        "last_key_name": str(cfg.get("last_key_name") or ("Task override" if source == "task_override" else "")),
        "pool_available": len(available),
        "pool_total": len(configured),
        "pool_state": pool_state,
        "last_rotation": last_rotation,
        "cooldown_until": _iso(min(retry_values) if retry_values else None),
    }
```

In `app/api/tasks.py`, call `fofa_router_for_task(task)` only for non-observer FOFA snapshots and merge `public_runtime_summary(task, router)` into `_public_fofa_config()`. Keep `_observer_fofa_config()` free of Key names and credential counts; it may expose only `pool_state` and `collector_phase`.

- [ ] **Step 4: Add immediate initialization to task start**

Extend `tests/test_task_operations_api.py::test_start_task_reenables_search` with a task seeded as `target_source="fofa", engine="fofa"`, then assert:

```python
assert started.json()["fofa_config"]["collector_phase"] == "initializing"
assert started.json()["fofa_config"]["collector_phase_text"] == "正在初始化 FOFA 搜集引擎"
```

In `app/api/tasks.py::start_task`, after clearing task-level runtime markers and before `session.commit()`, write `collector_phase`, `collector_phase_text`, and an empty `collector_phase_payload` when `target_source in {"fofa", "both"}`. For a non-FOFA engine use `正在初始化 {engine_name} 搜集引擎`; for `manual` and `site`, do not create an initialization phase. Preserve the existing behavior that global Router cooldowns are not cleared by task restart.

- [ ] **Step 5: Run Task 1 tests and commit**

Run: `python -m pytest -q tests/test_fofa_runtime_ui.py tests/test_task_operations_api.py -k "runtime or start_task_reenables_search"`

Expected: all selected tests pass.

Commit:

```powershell
git add app/fofa/runtime.py app/api/tasks.py tests/test_fofa_runtime_ui.py tests/test_task_operations_api.py
git commit -m "功能：增加 FOFA 任务运行摘要与启动状态"
```

### Task 2: Expose per-request Key attempts without changing existing consumers

**Files:**
- Modify: `app/fofa/router.py:104-161,519-577`
- Modify: `tests/test_fofa_router.py`

- [ ] **Step 1: Write the failing attempt metadata tests**

Add the dataclass import and tests:

```python
from app.fofa.router import FofaRequestAttempt


def test_async_router_reports_failed_key_then_successful_key() -> None:
    events: list[FofaRequestAttempt] = []
    calls: list[str] = []
    router = FofaKeyRouter([key("Primary", "key-a"), key("Backup", "key-b")], active_name="Primary")

    async def operation(value: str, _base_url: str) -> str:
        calls.append(value)
        if value == "key-a":
            raise FofaError("429", kind="rate_limit", code="429")
        return "ok"

    result = asyncio.run(router.execute_async(operation, on_attempt=events.append))

    assert result == "ok"
    assert calls == ["key-a", "key-b"]
    assert [(item.key_name, item.outcome, item.failure_kind) for item in events] == [
        ("Primary", "failed", "rate_limit"),
        ("Backup", "success", ""),
    ]


def test_transient_failure_reports_failure_and_does_not_try_next_key() -> None:
    events: list[FofaRequestAttempt] = []
    router = FofaKeyRouter([key("Primary", "key-a"), key("Backup", "key-b")], active_name="Primary")

    async def operation(_value: str, _base_url: str) -> str:
        raise FofaError("temporary", kind="transient")

    with pytest.raises(FofaError):
        asyncio.run(router.execute_async(operation, on_attempt=events.append))

    assert [(item.key_name, item.outcome) for item in events] == [("Primary", "failed")]

```

- [ ] **Step 2: Run the router tests to verify failure**

Run: `python -m pytest -q tests/test_fofa_router.py -k "attempt or transient_failure_reports"`

Expected: FAIL with `ImportError: cannot import name 'FofaRequestAttempt'`.

- [ ] **Step 3: Implement the optional callback**

Add this immutable event type and keyword-only parameter to both sync and async entry points:

```python
@dataclass(frozen=True)
class FofaRequestAttempt:
    key_name: str
    outcome: str
    failure_kind: str = ""


AttemptCallback = Callable[[FofaRequestAttempt], None]


async def execute_async(
    self,
    operation: Callable[[str, str], Awaitable[T]],
    *,
    on_attempt: AttemptCallback | None = None,
) -> T:
    return await self._execute_async_ring(operation, on_attempt=on_attempt)
```

Apply the same keyword to `execute_sync`; in `_execute_sync_ring` and `_execute_async_ring`, call `on_attempt(FofaRequestAttempt(candidate.name, "failed", kind.value))` immediately before retry/raise and `on_attempt(FofaRequestAttempt(candidate.name, "success"))` after `_mark_success`. Keep the default `None` path allocation-free and preserve every existing caller signature.

- [ ] **Step 4: Run the full Router regression set**

Run: `python -m pytest -q tests/test_fofa_router.py tests/test_fofa_errors.py`

Expected: all tests pass, including the new attempt metadata tests.

- [ ] **Step 5: Commit the Router contract**

```powershell
git add app/fofa/router.py tests/test_fofa_router.py
git commit -m "功能：暴露 FOFA 请求轮换尝试摘要"
```

### Task 3: Persist Collector rotation summaries and publish structured events

**Files:**
- Modify: `app/agents/collector.py:50,419-545`
- Modify: `app/orchestrator.py:730-739`
- Modify: `app/api/tasks.py:41-50,205-223,653-668`
- Modify: `tests/test_fofa_runtime_consumers.py`

- [ ] **Step 1: Extend the existing Collector rotation tests**

Update `test_collector_auth_rotation_keeps_cursor` in `tests/test_fofa_runtime_consumers.py` to pass a progress callback and assert the persisted summary:

```python
events: list[tuple[str, str, dict]] = []

async def progress(phase: str, text: str, payload: dict) -> None:
    events.append((phase, text, payload))

await collector._fofa_collect(
    session, task, seen, cluster, progress, fofa_router=router,
)

assert task.fofa_config["cursor"] == 1
assert task.fofa_config["last_key_name"] == "B"
assert task.fofa_config["last_rotation"] == {
    "from_key_name": "A",
    "to_key_name": "B",
    "reason": "auth",
}
assert any(payload.get("event_kind") == "fofa_key_rotated" for _, _, payload in events)
assert "key-b" not in repr(task.fofa_config)
```

Update the existing cooldown and terminal-pool tests to pass `progress` and assert:

```python
assert any(payload.get("event_kind") == "fofa_pool_waiting" for _, _, payload in cooldown_events)
assert any(payload.get("event_kind") == "fofa_pool_blocked" for _, _, payload in blocked_events)
```

Change the fake `CoolingRouter` and `TerminalRouter` signatures to accept `execute_async(self, operation, *, on_attempt=None)` so they keep matching the new Router API.

- [ ] **Step 2: Run the modified tests to verify failure**

Run: `python -m pytest -q tests/test_fofa_runtime_consumers.py -k "collector"`

Expected: FAIL because Collector does not pass `on_attempt` and does not persist `last_key_name` or `last_rotation`.

- [ ] **Step 3: Add Collector request metadata and task fields**

In `app/agents/collector.py`, collect `FofaRequestAttempt` objects for the FOFA request:

```python
attempts: list[FofaRequestAttempt] = []
res = await fofa_router.execute_async(
    lambda routed_key, routed_base: engine.search(
        routed_key, cur_query, page=next_cursor, page_size=size, base_url=routed_base,
    ),
    on_attempt=attempts.append,
)
successful = next((item for item in reversed(attempts) if item.outcome == "success"), None)
failed = [item for item in attempts if item.outcome == "failed" and item.failure_kind in {"auth", "rate_limit", "daily_limit"}]
if successful:
    cfg["last_key_name"] = successful.key_name
if successful and failed:
    cfg["last_rotation"] = {
        "from_key_name": failed[-1].key_name,
        "to_key_name": successful.key_name,
        "reason": failed[-1].failure_kind,
    }
    await report(
        "querying",
        f"已切换到备用 Key：{successful.key_name}",
        event_kind="fofa_key_rotated",
        from_key_name=failed[-1].key_name,
        to_key_name=successful.key_name,
        reason=failed[-1].failure_kind,
    )
```

The event payload must never include the credential. Rename the existing `fofa_cooldown` report to event kind `fofa_pool_waiting` while keeping its phase text; keep `fofa_pool_blocked` as an error event. Set `fofa_next_retry_at` only for waiting, and clear `last_rotation` only when a new successful request has no preceding failure.

- [ ] **Step 4: Route event kinds through the orchestrator**

Change `collector_progress` in `app/orchestrator.py` to pop `event_kind` from the payload and use it as the TaskEvent/WebSocket kind, defaulting to `collector_phase`:

```python
async def collector_progress(phase: str, text: str, payload: dict) -> None:
    data = dict(payload)
    event_kind = str(data.pop("event_kind", "collector_phase"))
    await self._log(session, "collector", event_kind, text, phase=phase, **data)
```

Add `fofa_key_rotated`, `fofa_pool_waiting`, and `fofa_pool_blocked` to `_STREAM_IMPORTANT_KINDS`. Include only the safe event fields in historical board events; the public task snapshot remains the source of truth after refresh.

- [ ] **Step 5: Persist and expose the summary**

Add `last_key_name`, `last_rotation`, `fofa_pool_summary`, `fofa_next_retry_at`, and `fofa_pool_blocked` to the public task config through `public_runtime_summary`. Keep the observer DTO generic. Add a test that `/api/tasks/{id}/board` returns the phase and pool state without a credential value.

- [ ] **Step 6: Run Collector and API tests and commit**

Run: `python -m pytest -q tests/test_fofa_runtime_consumers.py tests/test_task_operations_api.py`

Expected: all selected tests pass.

```powershell
git add app/agents/collector.py app/orchestrator.py app/api/tasks.py tests/test_fofa_runtime_consumers.py tests/test_task_operations_api.py
git commit -m "功能：发布 FOFA 轮换与凭据池状态事件"
```

### Task 4: Add the frontend collector status state machine and BoardView UI

**Files:**
- Create: `frontend/src/collectorStatus.js`
- Create: `frontend/tests/collectorStatus.test.js`
- Modify: `frontend/src/views/BoardView.vue:476-520,584-617,930-970,1150-1245`
- Modify: `frontend/src/style.css:1978-2012, mobile mission rules`
- Modify: `frontend/tests/taskOperationsPanels.test.js`

- [ ] **Step 1: Write pure state-machine tests**

Create `frontend/tests/collectorStatus.test.js` with these contracts:

```js
import test from "node:test";
import assert from "node:assert/strict";
import {
  collectorViewModel,
  isAutoCollectionTask,
  mergeCollectorEvent,
} from "../src/collectorStatus.js";

test("FOFA task with no targets starts in collecting mode", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", search_enabled: true },
    { queued: 0, scanning: 0, done: 0 },
    { collector_phase: "initializing", collector_phase_text: "正在初始化 FOFA 搜集引擎" },
  );
  assert.equal(isAutoCollectionTask({ target_source: "fofa", search_enabled: true }), true);
  assert.equal(model.progressMode, "collecting");
  assert.equal(model.tone, "active");
  assert.equal(model.indeterminate, true);
  assert.equal(model.label, "正在初始化 FOFA 搜集引擎");
});

test("rotation keeps disposition progress once targets exist", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", engine: "fofa", search_enabled: true },
    { queued: 3, scanning: 1, done: 4 },
    {
      collector_phase: "querying",
      pool_state: "ready",
      last_key_name: "Backup",
      last_rotation: { from_key_name: "Primary", to_key_name: "Backup", reason: "rate_limit" },
    },
  );
  assert.equal(model.progressMode, "disposition");
  assert.equal(model.rotation.to_key_name, "Backup");
  assert.equal(model.tone, "active");
});

test("all cooling stops animation and reports waiting state", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", engine: "fofa", search_enabled: true },
    { queued: 2, scanning: 0, done: 3 },
    { collector_phase: "fofa_cooldown", pool_state: "cooling", cooldown_until: "2026-07-17T00:20:00Z" },
  );
  assert.equal(model.tone, "waiting");
  assert.equal(model.indeterminate, false);
  assert.equal(model.cooldownUntil, "2026-07-17T00:20:00Z");
});

test("partial WebSocket event preserves existing runtime fields", () => {
  const merged = mergeCollectorEvent(
    { last_key_name: "Backup", pool_available: 2, last_rotation: { reason: "rate_limit" } },
    { kind: "fofa_key_rotated", to_key_name: "Reserve", reason: "auth" },
  );
  assert.equal(merged.last_key_name, "Reserve");
  assert.equal(merged.pool_available, 2);
  assert.deepEqual(merged.last_rotation, { to_key_name: "Reserve", reason: "auth" });
});
```

- [ ] **Step 2: Run the helper tests to verify failure**

Run: `npm --prefix frontend test -- --test-name-pattern="collecting mode|rotation keeps|all cooling|partial WebSocket"`

Expected: FAIL with `ERR_MODULE_NOT_FOUND` for `src/collectorStatus.js`.

- [ ] **Step 3: Implement the pure state helpers**

Create `frontend/src/collectorStatus.js` with these stable rules:

```js
const AUTO_SOURCES = new Set(["fofa", "both"]);
const ACTIVE_PHASES = new Set(["initializing", "querying", "prefilter", "scoring", "target_filter", "enrich"]);
const WAITING_PHASES = new Set(["fofa_cooldown", "fofa_pool_waiting"]);
const BLOCKED_PHASES = new Set(["fofa_pool_blocked"]);

export function isAutoCollectionTask(task = {}) {
  return AUTO_SOURCES.has(task.target_source) && task.search_enabled !== false;
}

export function mergeCollectorEvent(current = {}, event = {}) {
  const next = { ...current };
  if (event.to_key_name) next.last_key_name = event.to_key_name;
  if (event.kind === "fofa_key_rotated") {
    next.last_rotation = {
      ...(current.last_rotation || {}),
      from_key_name: event.from_key_name || current.last_rotation?.from_key_name || "",
      to_key_name: event.to_key_name,
      reason: event.reason || current.last_rotation?.reason || "",
    };
  }
  if (event.phase) next.collector_phase = event.phase;
  if (event.message) next.collector_phase_text = event.message;
  for (const key of ["pool_state", "pool_available", "pool_total", "cooldown_until", "fofa_pool_summary"]) {
    if (event[key] !== undefined) next[key] = event[key];
  }
  return next;
}

export function collectorViewModel(task = {}, stats = {}, cfg = {}) {
  const total = Math.max(0, Number(stats.queued) || 0) + Math.max(0, Number(stats.scanning) || 0) + Math.max(0, Number(stats.done) || 0);
  const phase = String(cfg.collector_phase || "");
  const waiting = WAITING_PHASES.has(phase) || cfg.pool_state === "cooling";
  const blocked = BLOCKED_PHASES.has(phase) || cfg.pool_state === "blocked";
  const active = isAutoCollectionTask(task) && task.status === "running" && !waiting && !blocked;
  const hasTargets = total > 0;
  return {
    visible: isAutoCollectionTask(task) && (active || waiting || blocked || Boolean(phase)),
    progressMode: active && !hasTargets ? "collecting" : "disposition",
    tone: blocked ? "blocked" : waiting ? "waiting" : active ? "active" : "neutral",
    indeterminate: active && ACTIVE_PHASES.has(phase) && !hasTargets,
    label: cfg.collector_phase_text || (blocked ? "FOFA 凭据池暂无可用 Key" : waiting ? "FOFA 凭据池处于冷却期" : "正在初始化搜集引擎"),
    lastKeyName: cfg.last_key_name || "",
    rotation: cfg.last_rotation || null,
    cooldownUntil: cfg.cooldown_until || cfg.fofa_next_retry_at || null,
  };
}
```

- [ ] **Step 4: Wire events and snapshots into BoardView**

Import the helpers in `BoardView.vue`. Treat `fofa_key_rotated`, `fofa_pool_waiting`, and `fofa_pool_blocked` as important events; pass every such event through `mergeCollectorEvent`. Keep the current `mergeTaskControlResponse` deep merge so a control response cannot erase the runtime summary. When loading `/board`, replace the current `fofa_config` with the public snapshot; when receiving WebSocket events, merge only fields present in the event.

Replace the current `collectorVisible`, `collectorText`, `collectorMeta`, and `collectorPct` block with the `collectorViewModel()` result. The mission ring label becomes `搜集进度` only when `progressMode === "collecting"`; otherwise it remains `处置进度`. Show the Key summary only when `collectorCfg.engine === "fofa"`:

```vue
<div v-if="collectorModel.visible" class="collector-stage" :class="`tone-${collectorModel.tone}`">
  <div class="collector-stage-head">
    <b>{{ collectorModel.label }}</b>
    <span v-if="collectorModel.lastKeyName">最近使用：{{ collectorModel.lastKeyName }}</span>
  </div>
  <p v-if="collectorModel.rotation" class="collector-rotation">
    {{ collectorModel.rotation.from_key_name }} → {{ collectorModel.rotation.to_key_name }} · {{ collectorModel.rotation.reason }}
  </p>
  <div class="collector-stage-bar" :class="{ indeterminate: collectorModel.indeterminate }">
    <i :style="{ transform: `scaleX(${collectorPct / 100})` }"></i>
  </div>
</div>
```

For `fofa_pool_blocked`, add a text link/button that routes to `/settings`; do not expose a Key value. For cooling, render the server UTC timestamp with the existing elapsed/countdown helper.

- [ ] **Step 5: Add CSS and static contract assertions**

Add `.mission-progress.indeterminate`, `.collector-stage.tone-waiting`, `.collector-stage.tone-blocked`, `.collector-rotation`, and a `@media (prefers-reduced-motion: reduce)` rule that sets animation to `none`. Ensure the mobile mission layout lets the status text wrap instead of forcing a single line.

Extend `frontend/tests/taskOperationsPanels.test.js` with assertions for `collectorViewModel`, `fofa_key_rotated`, `fofa_pool_waiting`, `fofa_pool_blocked`, `搜集进度`, `最近使用`, and `prefers-reduced-motion`.

- [ ] **Step 6: Run frontend status tests and commit**

Run: `npm --prefix frontend test -- --test-name-pattern="collector|task board"`

Expected: all matching tests pass.

```powershell
git add frontend/src/collectorStatus.js frontend/src/views/BoardView.vue frontend/src/style.css frontend/tests/collectorStatus.test.js frontend/tests/taskOperationsPanels.test.js
git commit -m "功能：展示 FOFA 轮换与搜集状态"
```

### Task 5: Make task forms choose or clear the FOFA pool explicitly

**Files:**
- Create: `frontend/src/taskSourceModes.js`
- Create: `frontend/tests/taskSourceModes.test.js`
- Modify: `app/api/tasks.py:503-526`
- Modify: `tests/test_task_model_config.py`
- Modify: `frontend/src/views/CreateView.vue:1-220`
- Modify: `frontend/src/components/TaskEditModal.vue:1-335`
- Modify: `frontend/tests/taskOperationsPanels.test.js`

- [ ] **Step 1: Write mode and clear-override tests**

Create `frontend/tests/taskSourceModes.test.js`:

```js
import test from "node:test";
import assert from "node:assert/strict";
import { isAutoSource, isFofaPoolMode, isManualOnly, isSiteSource } from "../src/taskSourceModes.js";

test("target source matrix keeps manual and site fields distinct", () => {
  assert.equal(isAutoSource("fofa"), true);
  assert.equal(isAutoSource("both"), true);
  assert.equal(isManualOnly("manual"), true);
  assert.equal(isSiteSource("site"), true);
});

test("FOFA pool mode follows the selected engine and default engine", () => {
  assert.equal(isFofaPoolMode("fofa", "fofa"), true);
  assert.equal(isFofaPoolMode("both", ""), true);
  assert.equal(isFofaPoolMode("fofa", "quake"), false);
  assert.equal(isFofaPoolMode("manual", "fofa"), false);
});
```

Add a backend test that patches an existing task with `{"fofa_config": {"key": None}}` and asserts the stored `key` is removed, while a patch that omits `key` keeps the old value.

- [ ] **Step 2: Run the mode and API tests to verify failure**

Run: `npm --prefix frontend test -- --test-name-pattern="target source matrix|FOFA pool mode"; python -m pytest -q tests/test_task_model_config.py -k "fofa_key or config"`

Expected: frontend fails because `taskSourceModes.js` is absent; backend fails because `key: null` currently leaves the old task override in place.

- [ ] **Step 3: Implement source-mode helpers and backend key clearing**

Create `frontend/src/taskSourceModes.js`:

```js
const AUTO_SOURCES = new Set(["fofa", "both"]);

export function isAutoSource(source) {
  return AUTO_SOURCES.has(String(source || ""));
}

export function isManualOnly(source) {
  return String(source || "") === "manual";
}

export function isSiteSource(source) {
  return String(source || "") === "site";
}

export function isFofaPoolMode(source, engine) {
  return isAutoSource(source) && (!engine || String(engine) === "fofa");
}
```

In `app/api/tasks.py`, handle an explicitly supplied null in the partial FOFA config:

```python
if "key" in patch:
    if patch["key"] is None:
        cfg.pop("key", None)
    elif str(patch["key"]).strip():
        cfg["key"] = str(patch["key"]).strip()
```

Keep the existing “empty string means preserve” behavior for clients that send a blank password field without selecting the global-pool mode. Add `key` to `FofaConfigDTO` only as the existing create-time value; no credential is returned in public DTOs.

- [ ] **Step 4: Update CreateView and TaskEditModal**

Add `fofa_key_mode: "global"` to both form models and compute `isFofaPoolMode`. Render a two-option `model-mode-switch` only for FOFA pool mode:

```vue
<div v-if="isFofaPoolMode" class="model-mode-switch" role="group" aria-label="FOFA Key 来源">
  <button type="button" :class="{ active: form.fofa_key_mode === 'global' }"
    :aria-pressed="form.fofa_key_mode === 'global'" @click="form.fofa_key_mode = 'global'">
    使用全局 FOFA Key 池
  </button>
  <button type="button" :class="{ active: form.fofa_key_mode === 'task' }"
    :aria-pressed="form.fofa_key_mode === 'task'" @click="form.fofa_key_mode = 'task'">
    任务专用 Key
  </button>
</div>
<p v-if="isFofaPoolMode" class="model-mode-copy">
  {{ form.fofa_key_mode === 'global' ? '按 Key 池顺序轮换并在冷却后自动恢复。' : '固定使用此任务的单个 Key，不参与全局轮换。' }}
</p>
<label v-if="isFofaPoolMode && form.fofa_key_mode === 'task'">任务专用 FOFA Key
  <input v-model="form.fofa_key" type="password" autocomplete="new-password" />
</label>
```

Hide search engine, intent, query and FOFA fields for `manual`/`site` according to `taskSourceModes.js`; keep manual targets for `both` and `manual`, and keep the site URL label for `site`. On create, include `fofa_config.key` only when `fofa_key_mode === "task"`. On edit, send `key: null` exactly when the user switches an existing task from `task` to `global`; omit it when the mode is unchanged and the password is blank. Reset the mode to `global` when the selected engine is not FOFA.

- [ ] **Step 5: Add form contract assertions and run tests**

Extend `frontend/tests/taskOperationsPanels.test.js` to assert both `CreateView.vue` and `TaskEditModal.vue` contain `fofa_key_mode`, `isFofaPoolMode`, `使用全局 FOFA Key 池`, `任务专用 Key`, and `key: null` handling. Run:

`npm --prefix frontend test -- --test-name-pattern="target source matrix|FOFA pool mode|task form"; python -m pytest -q tests/test_task_model_config.py -k "fofa_key"`

Expected: all selected tests pass.

- [ ] **Step 6: Commit task form integration**

```powershell
git add frontend/src/taskSourceModes.js frontend/src/views/CreateView.vue frontend/src/components/TaskEditModal.vue frontend/tests/taskSourceModes.test.js frontend/tests/taskOperationsPanels.test.js app/api/tasks.py tests/test_task_model_config.py
git commit -m "功能：让任务表单显式选择 FOFA Key 来源"
```

### Task 6: Verify settings integration, visual states, and compatibility

**Files:**
- Create: `frontend/tests/fofaKeyPanelContract.test.js`
- Test: `frontend/tests/fofaKeys.test.js`, `frontend/tests/settingsHealth.test.js`, `tests/test_fofa_key_api.py`

- [ ] **Step 1: Add regression assertions for existing Key pool UI**

Add to `frontend/tests/settingsHealth.test.js` or a new `frontend/tests/fofaKeyPanelContract.test.js`:

```js
import fs from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";

const panel = fs.readFileSync(new URL("../src/components/FofaKeysPanel.vue", import.meta.url), "utf8");
const settings = fs.readFileSync(new URL("../src/views/SettingsView.vue", import.meta.url), "utf8");

test("settings keeps Key pool management and stale health results", () => {
  assert.match(panel, /FOFA Key 池/);
  assert.match(panel, /fofaKeyStatus/);
  assert.match(panel, /cooldownLabel/);
  assert.match(panel, /接管并编辑/);
  assert.match(settings, /FofaKeysPanel/);
  assert.match(settings, /applyHealthCheck/);
});
```

- [ ] **Step 2: Run the full focused regression set**

Run:

```powershell
python -m pytest -q tests/test_fofa_key_config.py tests/test_fofa_errors.py tests/test_fofa_router.py tests/test_fofa_key_api.py tests/test_fofa_runtime_consumers.py tests/test_task_operations_api.py tests/test_task_model_config.py
npm --prefix frontend test
npm --prefix frontend run build
```

Expected: all backend tests pass, all Node tests pass, and Vite prints a successful production build.

- [ ] **Step 3: Perform browser acceptance checks**

Start the frontend with `npm --prefix frontend run dev -- --host 127.0.0.1`. Check at desktop width 1440px and mobile width 390px:

1. A running FOFA task with no targets shows `搜集进度` and an animated initialization/query state.
2. A task with targets shows `处置进度`; a `fofa_key_rotated` event displays the source and destination logical names.
3. `fofa_pool_waiting` stops the animation and shows the server cooldown timestamp.
4. `fofa_pool_blocked` shows a settings link without a credential value.
5. Settings lists available, cooling, blocked, disabled and Legacy rows without overlap; reduced motion removes the animation.
6. Create/Edit forms show only the relevant source fields and switching from task Key to global removes the stored override.

Take screenshots only for local review; do not add generated screenshots to the repository.

- [ ] **Step 4: Commit final verification adjustments**

```powershell
git add frontend/tests/fofaKeyPanelContract.test.js
git commit -m "测试：验证 FOFA 轮换界面与兼容回退"
```

The existing Key pool component and SettingsView are treated as prerequisites; this task adds only the regression contract test and must not stage unrelated worktree modifications.

## Self-review checklist

- Spec coverage: runtime snapshot, initial state, per-request rotation, waiting/blocked states, Key names, form matrix, clear override, settings regression, privacy and visual acceptance are covered by Tasks 1–6.
- Type consistency: `FofaRequestAttempt`, `public_runtime_summary`, `collectorViewModel`, `mergeCollectorEvent`, `isFofaPoolMode` and `fofa_key_mode` are defined before their consumers.
- Compatibility: existing Router callers keep the default `on_attempt=None`; blank task passwords preserve existing values unless the UI explicitly sends `key: null`; Legacy fallback and non-FOFA engines remain on their current paths.
- Scope: the plan modifies only the runtime/UI delta; the already-implemented multi-Key persistence and settings CRUD remain unchanged except for integration fields.
