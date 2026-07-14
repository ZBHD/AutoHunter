# 任务指定挖掘方向 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为任务增加独立的“指定挖掘方向（可选）”字段，让 Worker 在不改变授权、证据和审核边界的前提下优先深入用户指定方向，并支持运行中编辑对后续 Worker 生效。

**Architecture:** `Task.hunt_direction` 作为独立的任务偏好字段，经过 DTO trim/长度校验后持久化，Observer 响应隐藏其内容。编排层每次创建 Worker 时读取当前任务快照；Worker 仅在任务级 user 消息加入固定方向块，system prompt、Collector、Reviewer、Escalate 和 Killsweep 保持不变。Vue 创建页和编辑弹窗复用现有表单/网格样式，不增加新的视觉层。

**Tech Stack:** Python 3, FastAPI, Pydantic v2, SQLAlchemy async/SQLite, pytest, Vue 3, Vite, Node test runner.

---

### Task 1: 数据库、DTO 与任务 API

**Files:**
- Modify: `app/db/models.py:45-70` — 增加 `Task.hunt_direction`。
- Modify: `app/db/session.py:45-90` — 为旧库增加轻量迁移。
- Modify: `app/api/dto.py:65-175` — 创建/更新/响应 DTO 的字段、trim 与 2000 字符校验。
- Modify: `app/api/tasks.py:210-335,445-510` — 创建、响应、PATCH 和 Observer 脱敏。
- Test: `tests/test_task_model_config.py` — 创建、PATCH、长度与 Observer 行为。
- Test: `tests/test_db_migrations.py` — 旧 `tasks` 表迁移和旧行默认值。

- [ ] **Step 1: Write the failing API and migration tests**

```python
def test_create_task_trims_and_persists_hunt_direction(task_api):
    client, session_maker = task_api
    response = client.post("/api/tasks", json={
        "name": "directional",
        "hunt_direction": "  优先检查后台对象越权  ",
    })
    assert response.status_code == 200
    assert response.json()["hunt_direction"] == "优先检查后台对象越权"
    stored = asyncio.run(_stored_task(session_maker, response.json()["id"]))
    assert stored == "优先检查后台对象越权"


def test_patch_can_modify_and_explicitly_clear_hunt_direction(task_api):
    client, _ = task_api
    created = client.post("/api/tasks", json={"name": "patch"}).json()
    updated = client.patch(
        f"/api/tasks/{created['id']}",
        json={"hunt_direction": "  检查导出接口  "},
    )
    assert updated.json()["hunt_direction"] == "检查导出接口"
    cleared = client.patch(
        f"/api/tasks/{created['id']}",
        json={"hunt_direction": ""},
    )
    assert cleared.json()["hunt_direction"] == ""


def test_hunt_direction_limit_is_2000(task_api):
    response = task_api[0].post(
        "/api/tasks", json={"name": "too-long", "hunt_direction": "x" * 2001}
    )
    assert response.status_code == 422


def test_observer_task_responses_hide_hunt_direction(task_api):
    client, _ = task_api
    created = client.post(
        "/api/tasks", json={"name": "private", "hunt_direction": "敏感方向"}
    ).json()
    headers = {"x-autohunter-token": "observer-token"}
    assert client.get("/api/tasks", headers=headers).json()[0]["hunt_direction"] == ""
    assert client.get(
        f"/api/tasks/{created['id']}", headers=headers
    ).json()["hunt_direction"] == ""
```

Add a migration test that creates an old `tasks` table without the new column, calls `_auto_migrate`, asserts `hunt_direction` is present, and asserts an existing row reads `""`.

- [ ] **Step 2: Run the focused tests and verify the expected RED failures**

Run: `pytest tests/test_task_model_config.py -k hunt_direction -q` and `pytest tests/test_db_migrations.py -k hunt_direction -q`

Expected: FAIL because the request/response models, ORM column, migration and API handling do not yet expose `hunt_direction`.

- [ ] **Step 3: Implement the minimal persistence and API behavior**

Add `hunt_direction: Mapped[str] = mapped_column(Text, default="")` after `fofa_query`. Add `("tasks", "hunt_direction", "TEXT DEFAULT ''")` to `_MIGRATIONS`.

In `app/api/dto.py`, add:

```python
def _trim_hunt_direction(value: str) -> str:
    value = str(value or "").strip()
    if len(value) > 2000:
        raise ValueError("hunt_direction 长度不能超过 2000 个字符")
    return value
```

Use it as a `field_validator("hunt_direction")` on both create and update models. Create uses `hunt_direction: str = ""`; update uses `hunt_direction: Optional[str] = None`, preserving `None` as “no change”. Add `hunt_direction: str = ""` to `TaskResponse`.

In `app/api/tasks.py`, pass `req.hunt_direction` into `Task(...)`, include it in `_task_to_dto` as `"" if observer else (t.hunt_direction or "")`, and assign it in `update_task` only when `req.hunt_direction is not None`.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `pytest tests/test_task_model_config.py -k hunt_direction -q tests/test_db_migrations.py -k hunt_direction -q`

Expected: all new tests pass, including explicit empty-string clearing and Observer redaction.

- [ ] **Step 5: Commit the backend contract**

```bash
git add app/db/models.py app/db/session.py app/api/dto.py app/api/tasks.py tests/test_task_model_config.py tests/test_db_migrations.py
git commit -m "feat: add task hunt direction field"
```

### Task 2: Worker 与编排层方向注入

**Files:**
- Modify: `app/agents/worker.py:44-190,650-710` — 接收方向快照并构造任务级 user 消息。
- Modify: `app/orchestrator.py:1690-1800` — 派发 Worker 时读取最新任务方向并传入。
- Test: `tests/test_llm_consumers.py` or a focused new `tests/test_worker_hunt_direction.py` — prompt placement, precedence and empty behavior.
- Test: `tests/test_missed_signal_runtime.py` — ensure current task value is passed on a later dispatch when practical.

- [ ] **Step 1: Write failing prompt tests**

Instantiate `Worker` with a recording backend and `hunt_direction="优先测试对象级越权"`, call the existing first-message builder/run path, and assert:

```python
assert messages.count("# 用户指定的任务挖掘方向") == 1
assert "优先测试对象级越权" in task_user_message
assert "不得因此降低证据标准" in task_user_message
assert worker_system_prompt_before == worker_system_prompt_after
```

Add cases for `hunt_direction=""` (no heading or empty block), a `deepen_context` directive (the target-level directive appears before the task direction), and a unique sentinel that must not occur in Collector, Reviewer, Escalate, or Killsweep messages.

- [ ] **Step 2: Run the prompt tests and verify RED**

Run: `pytest tests/test_worker_hunt_direction.py -q` (or the focused test names in `tests/test_llm_consumers.py`).

Expected: FAIL because `Worker` has no direction argument and the orchestrator does not pass one.

- [ ] **Step 3: Implement the minimal Worker direction block**

Add `hunt_direction: str = ""` to `Worker.__init__`, trim it into `self.hunt_direction`, and add a helper:

```python
def _hunt_direction_block(self) -> str:
    direction = self.hunt_direction.strip()
    if not direction:
        return ""
    return (
        "# 用户指定的任务挖掘方向\n"
        f"{direction}\n\n"
        "正常挖掘时优先并深入覆盖此方向；它不预设漏洞一定存在。\n"
        "若当前目标带有定向回炉或单站协作路线，以更具体的目标级指令为先。\n"
        "不得因此降低证据标准、越出授权范围或忽略明显的高价值实证。\n"
    )
```

Insert this block once in the existing task-level user context, after target/deepen/site context so target-level instructions are visibly more specific, and before the normal playbook instructions. Do not alter `worker_system_prompt()`.

- [ ] **Step 4: Pass the latest task snapshot from the orchestrator**

In the dispatch section, derive `hunt_direction = (task_obj.hunt_direction or "").strip()` immediately before each new `Worker(...)` construction and pass `hunt_direction=hunt_direction`. Keep already-created Worker objects unchanged so edits affect only later dispatches. Do not pass the field into Collector, Reviewer, Escalate, or Killsweep constructors/messages.

- [ ] **Step 5: Run focused Worker/orchestrator tests and verify GREEN**

Run: `pytest tests/test_worker_hunt_direction.py tests/test_llm_consumers.py tests/test_missed_signal_runtime.py -q`

Expected: all focused tests pass and existing continuation/deepen behavior remains unchanged.

- [ ] **Step 6: Commit the runtime behavior**

```bash
git add app/agents/worker.py app/orchestrator.py tests/test_worker_hunt_direction.py tests/test_llm_consumers.py tests/test_missed_signal_runtime.py
git commit -m "feat: guide workers with task hunt direction"
```

### Task 3: 创建页与编辑弹窗

**Files:**
- Modify: `frontend/src/views/CreateView.vue:1-190` — form state, create payload and textarea.
- Modify: `frontend/src/components/TaskEditModal.vue:35-230` — form state, fill/save and textarea.
- Test: `frontend/test/task-hunt-direction.test.js` — source-level contract tests following existing Node test conventions.

- [ ] **Step 1: Write failing frontend contract tests**

Read both Vue sources and assert they contain `hunt_direction`, the exact label `指定挖掘方向（可选）`, `maxlength="2000"`, `rows="3"`, create payload mapping, edit fill mapping, update payload mapping, and an empty-string path for clearing.

```js
test("create view submits trimmed hunt direction", () => {
  const source = read("frontend/src/views/CreateView.vue");
  assert.match(source, /hunt_direction/);
  assert.match(source, /指定挖掘方向（可选）/);
  assert.match(source, /maxlength="2000"/);
  assert.match(source, /hunt_direction:\s*form\.hunt_direction\.trim\(\)/);
});
```

- [ ] **Step 2: Run the frontend contract tests and verify RED**

Run: `node --test frontend/test/task-hunt-direction.test.js`

Expected: FAIL because neither view has the new field.

- [ ] **Step 3: Add the field using existing form styles**

In `CreateView.vue`, initialize `hunt_direction: ""`, add `hunt_direction: form.hunt_direction.trim()` to the create payload, and place after the vulnerability-types label and before target source:

```vue
<label>指定挖掘方向（可选）
  <textarea v-model="form.hunt_direction" rows="3" maxlength="2000"
    placeholder="例：重点测试后台 API 的水平/垂直越权、批量导出和敏感写操作；优先关注 object_id、user_id 等对象参数。"></textarea>
</label>
```

In `TaskEditModal.vue`, initialize the same property, set `form.hunt_direction = task.hunt_direction || ""` in `fill`, add `hunt_direction: form.hunt_direction.trim()` to `api.updateTask`, and render the same label immediately after vulnerability types. Do not add new CSS; current `.form`, `settings-grid`, `label`, `textarea`, and mobile rules already provide the required layout.

- [ ] **Step 4: Run frontend tests and build**

Run: `node --test frontend/test/task-hunt-direction.test.js` and `npm --prefix frontend run build`

Expected: contract tests pass and Vite produces a successful production build.

- [ ] **Step 5: Commit the frontend behavior**

```bash
git add frontend/src/views/CreateView.vue frontend/src/components/TaskEditModal.vue frontend/test/task-hunt-direction.test.js
git commit -m "feat: add hunt direction task controls"
```

### Task 4: 全量验证与浏览器 QA

**Files:**
- Test: all existing backend and frontend tests; no production changes expected unless a regression is found.

- [ ] **Step 1: Run backend regression suite**

Run: `pytest -q`

Expected: all tests pass without warnings caused by this feature.

- [ ] **Step 2: Run frontend regression suite and build**

Run: `npm --prefix frontend test` (or the repository's documented frontend test command), `npm --prefix frontend run build`.

Expected: all frontend tests and the Vite build pass.

- [ ] **Step 3: Check formatting and inspect the diff**

Run: `git diff --check` and `git diff --stat`.

Expected: no whitespace errors; only the planned backend, worker, orchestrator, frontend and test files changed.

- [ ] **Step 4: Exercise the UI in the existing local app**

Open the existing task creation route, verify the textarea follows the current form typography and spacing at desktop and narrow/mobile widths, create a task with a direction, open edit, change it, then clear it. Verify the task response carries the trimmed value and the Observer route returns an empty value.

- [ ] **Step 5: Commit any verified regression fix and report evidence**

If a regression is found, add a focused failing test first, fix it, rerun the affected suite, then commit. Otherwise keep the implementation commits intact and report exact commands/results.

---

## Self-review checklist

- [ ] Independent field is not reused as `fofa_query`, `vuln_types`, `src_rules`, or model/FOFA config.
- [ ] `None` in PATCH means unchanged; `""` means explicit clear.
- [ ] Observer list/detail responses hide the value.
- [ ] Old databases gain `TEXT DEFAULT ''` without dropping rows.
- [ ] Worker system prompt remains unchanged and the task block appears once only for non-empty input.
- [ ] Target-level deepen/site instructions remain higher priority.
- [ ] Collector, Reviewer, Escalate and Killsweep never receive the sentinel direction.
- [ ] Create/edit Vue controls reuse existing styles and enforce 2000 characters.
- [ ] Every implementation step contains concrete code or an exact command.
