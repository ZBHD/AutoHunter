# 停止搜索并排空队列实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` to implement this plan task-by-task with verification checkpoints.

**Goal:** 在任务看板增加“停止搜索”，持久化关闭资产搜索，继续处理既有队列，队列完全排空后自动停止，并在下一次启动时恢复搜索。

**Architecture:** 在 `Task` 增加独立的 `search_enabled` 布尔列，避免 Collector 整体写回 `fofa_config` 时覆盖控制状态。Collector 始终保留手动/单站入队能力，仅在该开关关闭时跳过 `_fofa_collect()`；TaskRunner 在排空条件满足时持久化 `stopped` 并结束自身。前端通过独立 API 和纯函数状态映射区分“停止搜索”和“停止任务”。

**Tech Stack:** Python 3、FastAPI、SQLAlchemy async、SQLite 自动迁移、Vue 3、Vite、Node `node:test`、pytest。

---

## 文件边界

- Modify: `app/db/models.py` — `Task.search_enabled` 持久化字段。
- Modify: `app/db/session.py` — 旧数据库自动迁移。
- Modify: `app/api/dto.py` — `TaskResponse.search_enabled`。
- Modify: `app/api/tasks.py` — DTO 投影、启动恢复和新接口。
- Modify: `app/agents/collector.py` — 搜索开关只控制 FOFA/资产搜索分支。
- Modify: `app/orchestrator.py` — 关闭搜索后的排空自动停止。
- Modify: `frontend/src/api.js` — `stopSearch` 请求封装。
- Modify: `frontend/src/taskViews.js` — 可测试的搜索控制状态映射。
- Modify: `frontend/src/views/BoardView.vue` — 控制按钮、提示和请求状态。
- Modify: `frontend/src/style.css` — 琥珀色按钮和移动端稳定尺寸。
- Modify: `tests/test_db_migrations.py` — 旧表迁移覆盖。
- Modify: `tests/test_task_operations_api.py` — API DTO、停止搜索、启动恢复。
- Create: `tests/test_collector_stop_search.py` — Collector 分支行为。
- Modify: `tests/test_task_queue.py` — TaskRunner 排空判定。
- Modify: `frontend/tests/operationsRegression.test.js` — 纯函数状态测试。
- Modify: `frontend/tests/taskOperationsPanels.test.js` — Board/API/CSS 源码契约。

## Task 1: 持久化搜索开关和响应字段

**Files:**
- Test: `tests/test_db_migrations.py`
- Test: `tests/test_task_operations_api.py`
- Modify: `app/db/models.py`, `app/db/session.py`, `app/api/dto.py`, `app/api/tasks.py`

- [ ] **Step 1: 写失败测试**

在 `tests/test_db_migrations.py` 增加旧 `tasks` 表迁移测试，确认新列和默认值：

```python
def test_old_tasks_table_gains_search_enabled_without_data_loss() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as conn:
                await conn.exec_driver_sql(
                    "CREATE TABLE tasks (id VARCHAR(32) PRIMARY KEY, name VARCHAR(200) NOT NULL)"
                )
                await conn.exec_driver_sql(
                    "INSERT INTO tasks (id, name) VALUES ('legacy-search', 'Legacy search')"
                )
                await _auto_migrate(conn)
                columns = await conn.exec_driver_sql("PRAGMA table_info(tasks)")
                assert "search_enabled" in {row[1] for row in columns.fetchall()}
                row = await conn.exec_driver_sql(
                    "SELECT id, name, search_enabled FROM tasks WHERE id='legacy-search'"
                )
                assert row.one() == ("legacy-search", "Legacy search", 1)
        finally:
            await engine.dispose()

    asyncio.run(scenario())
```

在 `tests/test_task_operations_api.py` 的 GET 任务测试中增加 `assert response.json()["search_enabled"] is True`，让响应契约在字段尚未实现时失败。

- [ ] **Step 2: 运行迁移和 API 测试确认失败**

Run: `python -m pytest -q tests/test_db_migrations.py::test_old_tasks_table_gains_search_enabled_without_data_loss tests/test_task_operations_api.py -k search_enabled`

Expected: FAIL，分别提示 `search_enabled` 列不存在或 `TaskResponse` 返回中缺少字段。

- [ ] **Step 3: 实现最小数据链路**

在 `Task` 的 `fofa_config` 后加入：

```python
search_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
```

在 `app/db/session.py` 的 `_MIGRATIONS` 中加入：

```python
("tasks", "search_enabled", "BOOLEAN DEFAULT 1"),
```

在 `TaskResponse` 加入 `search_enabled: bool = True`，并在 `_task_to_dto()` 传入 `search_enabled=bool(t.search_enabled)`。不要把它放入 observer 的敏感配置投影；它只是运行状态。

- [ ] **Step 4: 运行测试确认通过**

Run: `python -m pytest -q tests/test_db_migrations.py::test_old_tasks_table_gains_search_enabled_without_data_loss tests/test_task_operations_api.py -k search_enabled`

Expected: PASS。

## Task 2: Collector 只关闭资产搜索分支

**Files:**
- Create: `tests/test_collector_stop_search.py`
- Modify: `app/agents/collector.py`

- [ ] **Step 1: 写失败测试**

创建两个异步测试，替换 `_fofa_collect` 为记录调用的 stub；关闭搜索时仍消费 `both` 的手动目标，开启搜索时调用 FOFA 分支：

```python
async def test_refill_skips_fofa_when_search_disabled(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'collector-stop.db'}")
    sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    called = []

    async def fake_fofa(*args, **kwargs):
        called.append(True)
        return 9

    monkeypatch.setattr(collector, "_fofa_collect", fake_fofa)
    async with sessions() as session:
        task = Task(id="task-stop", name="Stop", target_source="both",
                    manual_targets=["manual.example"], search_enabled=False)
        session.add(task)
        await session.commit()
        assert await collector.refill(session, task, low_watermark=5) == 1
        assert called == []
        assert task.manual_targets == []
        assert await session.scalar(select(func.count()).select_from(Target)) == 1
    await engine.dispose()
```

添加对应的 `search_enabled=True` 测试，断言 `fake_fofa` 收到一次调用。

- [ ] **Step 2: 运行 Collector 测试确认失败**

Run: `python -m pytest -q tests/test_collector_stop_search.py`

Expected: FAIL，因为当前 `refill()` 无条件执行 `_fofa_collect()`。

- [ ] **Step 3: 写最小实现**

把 `collector.refill()` 中的资产搜索分支改为：

```python
if task.target_source in ("fofa", "both") and task.search_enabled:
    added += await _fofa_collect(session, task, seen, cluster_state, progress)
```

保留前面的手动清单和 `site` 分支，确保关闭搜索不会丢失手动目标。

- [ ] **Step 4: 运行测试确认通过**

Run: `python -m pytest -q tests/test_collector_stop_search.py tests/test_collector_scope.py`

Expected: PASS。

## Task 3: 新增停止搜索 API，并让启动恢复搜索

**Files:**
- Modify: `tests/test_task_operations_api.py`
- Modify: `app/api/tasks.py`

- [ ] **Step 1: 写失败测试**

在现有 `operations_api` fixture 上增加：

```python
def test_stop_search_is_idempotent_and_preserves_queue(operations_api: TestClient) -> None:
    first = operations_api.post("/api/tasks/task-ops/stop-search")
    assert first.status_code == 200
    assert first.json()["search_enabled"] is False

    second = operations_api.post("/api/tasks/task-ops/stop-search")
    assert second.status_code == 200
    assert second.json()["search_enabled"] is False

    queue = operations_api.get("/api/tasks/task-ops/queue-targets")
    assert queue.json()["total"] == 2


def test_start_reenables_search(monkeypatch, operations_api: TestClient) -> None:
    async def no_runner(_task_id):
        return None

    monkeypatch.setattr(tasks_api.manager, "ensure_running", no_runner)
    assert operations_api.post("/api/tasks/task-ops/stop-search").json()["search_enabled"] is False
    restarted = operations_api.post("/api/tasks/task-ops/start")
    assert restarted.status_code == 200
    assert restarted.json()["search_enabled"] is True
```

- [ ] **Step 2: 运行 API 测试确认失败**

Run: `python -m pytest -q tests/test_task_operations_api.py -k "stop_search or start_reenables"`

Expected: FAIL with 404 for the new route and no state change on start.

- [ ] **Step 3: 实现 API**

在 `app/api/tasks.py` 增加 `search_stopped` 和 `search_drained` 到 `_STREAM_IMPORTANT_KINDS`，并增加接口：

```python
@router.post("/{task_id}/stop-search", response_model=TaskResponse)
async def stop_search_task(task_id: str, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    if task.search_enabled:
        task.search_enabled = False
        session.add(TaskEvent(
            task_id=task.id,
            agent="collector",
            kind="search_stopped",
            level="info",
            message="资产搜索已停止，剩余队列将继续处理",
            payload={},
        ))
        await session.commit()
    await session.refresh(task)
    return _task_to_dto(task)
```

在 `start_task()` 设置 `task.search_enabled = True`，再提交现有状态变更。重复停止请求只读当前状态，不重复写事件。

- [ ] **Step 4: 运行 API 和既有任务操作测试**

Run: `python -m pytest -q tests/test_task_operations_api.py tests/test_task_model_config.py`

Expected: PASS。

## Task 4: 搜索关闭后的 TaskRunner 自动排空停止

**Files:**
- Modify: `tests/test_task_queue.py`
- Modify: `app/orchestrator.py`

- [ ] **Step 1: 写失败测试**

增加一个 runner drain 测试，使用临时 SQLite 和 monkeypatch 隔离外部 Collector/Worker：

```python
def test_disabled_search_stops_runner_after_all_work_is_drained(tmp_path, monkeypatch):
    async def scenario():
        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'drain.db'}")
        sessions = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            session.add(Task(id="task-drain", name="Drain", status="running", search_enabled=False))
            await session.commit()

        monkeypatch.setattr(orchestrator, "SessionLocal", sessions)
        monkeypatch.setattr(orchestrator.collector, "refill", lambda *args, **kwargs: _zero())
        runner = orchestrator.TaskRunner("task-drain")
        monkeypatch.setattr(runner, "_dispatch_reviews", _noop)
        monkeypatch.setattr(runner, "_dispatch_escalation_attempts", _noop)
        monkeypatch.setattr(runner, "_dispatch_killsweep_attempts", _noop)
        await runner._tick()

        async with sessions() as session:
            task = await session.get(Task, "task-drain")
            assert task.status == "stopped"
        assert runner._stop.is_set()
        await engine.dispose()

    async def _zero(*args, **kwargs):
        return 0

    async def _noop(*args, **kwargs):
        return None

    asyncio.run(scenario())
```

另加覆盖：存在 queued 或 active review 时不停止；`search_enabled=True` 且无目标时仍保持既有 `idle`。

- [ ] **Step 2: 运行 runtime 测试确认失败**

Run: `python -m pytest -q tests/test_task_queue.py -k "drain or idle"`

Expected: FAIL，因为当前逻辑只会把任务置为 `idle`，不会结束 runner，也没有 `search_stopped` 排空事件。

- [ ] **Step 3: 实现最小排空逻辑**

在 `_tick()` 的现有 `queued/inflight/busy` 统计之后，先把 `_review_tasks` 纳入 drain busy，再加入关闭搜索分支：

```python
drain_busy = (
    bool(self._active_workers)
    or bool(self._review_tasks)
    or bool(self._killsweep_tasks)
    or bool(self._escalation_tasks)
    or inflight > 0
)
if not task.search_enabled and queued == 0 and not drain_busy:
    task.status = "stopped"
    await session.commit()
    await self._log(
        session,
        "orchestrator",
        "search_drained",
        "资产搜索已停止，队列已排空，任务自动停止",
    )
    self._stop.set()
    return
```

将原有 idle 判定继续用于 `search_enabled=True`，避免改变 24x7 搜索任务的行为。排空分支不调用 `self.stop()`，因为条件已确认没有需要取消的后台任务。

- [ ] **Step 4: 运行队列和 runtime 测试确认通过**

Run: `python -m pytest -q tests/test_task_queue.py tests/test_missed_signal_runtime.py -k "drain or idle or stop"`

Expected: PASS。

## Task 5: 前端搜索控制状态纯函数

**Files:**
- Modify: `frontend/src/taskViews.js`
- Modify: `frontend/tests/operationsRegression.test.js`

- [ ] **Step 1: 写失败测试**

在前端回归测试中增加：

```js
test("search control distinguishes active, draining, and unsupported tasks", () => {
  assert.equal(typeof taskViews.taskSearchControl, "function");
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "fofa", status: "running", search_enabled: true }),
    { visible: true, canStop: true, draining: false, label: "停止搜索" },
  );
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "both", status: "running", search_enabled: false }),
    { visible: true, canStop: false, draining: true, label: "搜索已停止" },
  );
  assert.equal(
    taskViews.taskSearchControl({ target_source: "manual", status: "running", search_enabled: true }).visible,
    false,
  );
});
```

- [ ] **Step 2: 运行前端测试确认失败**

Run: `node --test --test-name-pattern="search control" tests/*.test.js` from `frontend/`

Expected: FAIL because `taskSearchControl` is not exported.

- [ ] **Step 3: 实现纯函数**

在 `frontend/src/taskViews.js` 增加：

```js
const SEARCH_SOURCES = new Set(["fofa", "both"]);

export function taskSearchControl(task, working = false) {
  const visible = SEARCH_SOURCES.has(task?.target_source);
  const enabled = task?.search_enabled !== false;
  const active = ["running", "idle"].includes(task?.status);
  return {
    visible,
    canStop: visible && active && enabled && !working,
    draining: visible && !enabled && active,
    label: working ? "正在停止" : enabled ? "停止搜索" : "搜索已停止",
  };
}
```

- [ ] **Step 4: 运行前端测试确认通过**

Run: `node --test --test-name-pattern="search control" tests/*.test.js` from `frontend/`

Expected: PASS。

## Task 6: BoardView、API 和视觉样式

**Files:**
- Modify: `frontend/src/api.js`, `frontend/src/views/BoardView.vue`, `frontend/src/style.css`
- Modify: `frontend/tests/taskOperationsPanels.test.js`

- [ ] **Step 1: 写失败的源码契约测试**

在 `taskOperationsPanels.test.js` 增加：

```js
test("task board exposes separate stop-search and stop-task controls", () => {
  assert.match(api, /stopSearch:\s*\(id\)\s*=>\s*req\("POST", `\\/api\\/tasks\\/\$\\{id\\}\\/stop-search`\)/);
  assert.match(board, /taskSearchControl/);
  assert.match(board, /停止搜索/);
  assert.match(board, /停止任务/);
  assert.match(style, /mission-actions.*stop-search|stop-search.*mission-actions/);
});
```

为测试读取 `style.css`，保留现有 `board`、`api` 常量并新增 `style` 常量。

- [ ] **Step 2: 运行前端契约测试确认失败**

Run: `node --test --test-name-pattern="separate stop-search" tests/*.test.js` from `frontend/`

Expected: FAIL，因为 API、BoardView 和样式尚未出现。

- [ ] **Step 3: 实现 API 和 BoardView 控件**

在 `api` 对象的 `stop` 附近加入：

```js
stopSearch: (id) => req("POST", `/api/tasks/${id}/stop-search`),
```

在 `BoardView.vue`：

```js
import { taskProgressSummary, taskSearchControl, taskViewForRole } from "../taskViews.js";
const stopSearchWorking = ref(false);
const searchControl = computed(() => taskSearchControl(task.value, stopSearchWorking.value));

async function stopSearch() {
  if (!searchControl.value.canStop) return;
  stopSearchWorking.value = true;
  try {
    task.value = await api.stopSearch(props.id);
    toast("已停止继续搜索，剩余队列将继续处理");
    await loadBoard();
  } catch (e) {
    toast(`停止搜索失败：${e?.message || e}`);
  } finally {
    stopSearchWorking.value = false;
  }
}
```

控制区顺序改为编辑、启动、暂停、停止搜索、停止任务：

```vue
<button
  v-if="searchControl.visible"
  class="stop-search"
  :disabled="!searchControl.canStop"
  @click="stopSearch"
>{{ searchControl.label }}</button>
<button @click="ctl('stop')">停止任务</button>
```

在任务元信息增加 `v-if="searchControl.draining"` 的“FOFA 已停止 · 正在排空队列”提示。只读角色沿用现有整个控制区隐藏逻辑。

- [ ] **Step 4: 添加琥珀色样式并验证移动端尺寸**

在任务操作样式附近加入：

```css
.mission-actions .stop-search {
  color: var(--warn);
  border-color: color-mix(in oklch, var(--warn) 48%, var(--border));
  background: color-mix(in oklch, var(--warn-bg) 66%, var(--surface));
}
.mission-actions .stop-search:hover:not(:disabled) { background: var(--warn-bg); }
.mission-actions .stop-search:disabled { color: var(--faint); }
```

保持现有桌面纵向布局和移动端三列网格；按钮最小高度沿用全局 button 规则，必要时在 `@media (max-width: 640px)` 为 `.mission-actions button` 保持 `min-height: 42px`。

- [ ] **Step 5: 运行契约测试和构建**

Run: `npm test -- --test-name-pattern="separate stop-search" && npm run build` from `frontend/`

Expected: PASS，Vite 输出 `dist/` 构建成功。

## Task 7: 全量验证和浏览器检查

**Files:** 无新增业务文件；只检查前述改动。

- [ ] **Step 1: 运行后端全量测试**

Run: `python -m pytest -q`

Expected: 全部通过，失败数为 0。若有与本功能无关的既有失败，记录精确测试名和输出，不修改无关代码。

- [ ] **Step 2: 运行前端全量测试和构建**

Run: `npm test && npm run build` from `frontend/`

Expected: Node 测试全部通过，Vite 构建退出码为 0。

- [ ] **Step 3: 启动前端并检查桌面/移动端**

Run: `npm run dev -- --host 127.0.0.1` from `frontend/`。

通过浏览器打开任务看板，确认：FOFA 任务显示五个操作按钮；点击“停止搜索”后按钮变为“搜索已停止”，任务元信息出现排空提示；手动/单站任务不显示该按钮；桌面和 `390x844` 视口无横向溢出、按钮文字不重叠。

- [ ] **Step 4: 完成前检查工作区范围**

Run: `git diff --check; git status --short`

确认只报告本功能涉及的文件和用户原有的其他改动，不回滚、不覆盖原有工作区内容。
