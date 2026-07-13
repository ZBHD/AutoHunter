# Multi-LLM Provider Pool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在保持旧任务与 `.env` 配置可用的前提下，为 AutoHunter 提供 OpenAI Chat、Anthropic Messages、OpenAI Responses 三协议、多 Provider 加权分配、请求内故障切换和运行时启停管理。

**Architecture:** `LLMClient` 只负责一个 Provider 的 HTTP 通信，协议差异由 `ProtocolAdapter` 处理；`LLMRouter` 持有多个 Client，每次 `chat()` 按权重选择首个 Provider，并在失败时遍历未尝试 Provider。全局 Provider 存于 `system_settings.llm_providers`，任务级模型配置仍可固定为单 Provider；旧 DB/环境单模型配置仅在 Provider 池为空时回退。

**Tech Stack:** Python 3.12+, FastAPI, SQLAlchemy async/SQLite, Pydantic v2, httpx, pytest, Vue 3, Vite

---

## Compatibility Contract

- 支持协议：`openai_chat`、`anthropic_messages`、`openai_responses`。
- 权重范围 `1..100`；只有 `enabled=true` 且配置了 key 的 Provider 参加选择。权重只决定首个 Provider，失败后按配置顺序稳定环形遍历其余 Provider。
- 一次 `chat()` 不重复同一 Provider；auth/quota 自动禁用并异步持久化，timeout/network/rate-limit/5xx 只在本次调用跳过。
- 新任务用 `use_global_pool` 显式区分全局池与任务专用模型；旧任务存在模型字段时按单 Provider 覆盖兼容。`prompt_version` 与 Provider 选择正交。
- DB Provider 池为空时，回退旧 `system_settings.llm` / `LLM_*` 环境变量；池非空但全部禁用时不回退。
- API 永不返回明文 key；更新时空 key 或脱敏占位表示保留原 key。
- Provider 名称大小写不敏感地唯一且首期不可重命名；重排请求只能提交名称顺序，不回传整组脱敏对象。
- 内部统一工具调用对象为 `ToolCall(id, name, arguments)`；Agent 不再读取 SDK 私有形状 `tc.function.*`。

## File Structure

- Create: `pytest.ini`, `requirements-dev.txt`, `tests/`
- Modify: `app/config.py`, `app/llm/protocols.py`, `app/llm/client.py`, `app/llm/router.py`, `app/llm/__init__.py`
- Modify: `app/db/session.py`, `app/settings_service.py`, `app/api/dto.py`, `app/api/settings.py`, `app/api/tasks.py`
- Modify: `app/orchestrator.py`, `app/agents/{worker,reviewer,collector,collector_llm,killsweep,escalate}.py`, `app/api/findings.py`
- Create: `frontend/src/components/LlmProvidersPanel.vue`, `frontend/src/llmProviders.js`, `frontend/tests/llmProviders.test.js`
- Modify: `frontend/src/api.js`, `frontend/src/views/SettingsView.vue`, `frontend/src/views/CreateView.vue`, `frontend/src/components/TaskEditModal.vue`, `frontend/src/style.css`, `frontend/package.json`
- Modify: `.env.example`, `README.md`

---

### Task 1: Establish A Real Test Harness

**Files:**
- Create: `pytest.ini`
- Create: `requirements-dev.txt`
- Create: `tests/test_app_imports.py`

- [ ] **Step 1: Restrict pytest discovery to the real test directory**

```ini
[pytest]
testpaths = tests
python_files = test_*.py
```

- [ ] **Step 2: Add the development test dependency**

```text
-r requirements.txt
pytest>=8.0,<9
```

- [ ] **Step 3: Add the import regression test**

```python
def test_application_imports() -> None:
    import app.main  # noqa: F401
```

- [ ] **Step 4: Run the test and verify RED**

Run: `python -m pytest tests/test_app_imports.py -q`

Expected: FAIL because `reviewer.py` imports the removed `_is_forced_tool_choice_unsupported` symbol.

---

### Task 2: Normalize Protocol Requests And Responses

**Files:**
- Create: `tests/test_llm_protocols.py`
- Modify: `app/llm/protocols.py`

- [ ] **Step 1: Write failing tests for all adapters**

Tests must assert:

```python
def test_openai_chat_round_trip_returns_normalized_tool_call(): ...
def test_anthropic_uses_x_api_key_and_converts_tool_history(): ...
def test_responses_preserves_assistant_function_call_before_output(): ...
def test_responses_extracts_text_from_output_items(): ...
def test_tool_call_serializes_to_openai_history_shape(): ...
```

The Responses history test must supply an assistant message with `tool_calls`, followed by a tool result, and assert the generated `input` contains a `function_call` before `function_call_output` with the same `call_id`.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest tests/test_llm_protocols.py -q`

Expected: FAIL on Anthropic auth header, Responses history, output text extraction, and normalized serialization.

- [ ] **Step 3: Implement the normalized contract**

`ToolCall` exposes:

```python
@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str

    def as_history_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "function",
            "function": {"name": self.name, "arguments": self.arguments},
        }
```

`LLMResponse.as_history_message()` must return canonical assistant history and retain private Responses continuation items. Adapters must preserve invalid JSON argument strings rather than parsing them eagerly. Anthropic uses `x-api-key` and merges adjacent same-role messages; Responses emits assistant `function_call` history, preserves opaque reasoning output items, forwards `tool_choice="none"`, and extracts text from both top-level `output_text` and nested output blocks. Chat requests strip all private history metadata before sending.

- [ ] **Step 4: Run protocol tests and verify GREEN**

Run: `python -m pytest tests/test_llm_protocols.py -q`

---

### Task 3: Make Weighted Routing And Failover Deterministic And Testable

**Files:**
- Create: `tests/test_llm_router.py`
- Modify: `app/llm/router.py`
- Modify: `app/llm/__init__.py`

- [ ] **Step 1: Write failing router tests**

```python
def test_weighted_selection_favors_higher_weight(): ...
def test_failure_uses_stable_ring_order_after_weighted_start(): ...
def test_auth_failure_disables_provider_and_calls_callback_once(): ...
def test_timeout_does_not_disable_provider(): ...
def test_all_failures_report_each_provider_without_keys(): ...
```

Use an injected `client_factory` and seeded RNG; no network mocks.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest tests/test_llm_router.py -q`

- [ ] **Step 3: Implement router seams and callback contract**

```python
class LLMRouter:
    def __init__(
        self,
        providers: list[LLMProviderConfig],
        usage_key: str | None = None,
        on_provider_disabled: Callable[[LLMProviderConfig, str], None] | None = None,
        client_factory: Callable[..., LLMClient] = LLMClient,
        rng: random.Random | None = None,
    ): ...
```

Filter disabled/keyless providers once, make one weighted start selection, then visit remaining providers in configured ring order. Preserve structured `ProviderFailure(name, error)` causes in `AllProvidersExhaustedError`. The callback is synchronous because `chat()` runs in worker threads; DB scheduling belongs to `settings_service`.

- [ ] **Step 4: Run router tests and verify GREEN**

Run: `python -m pytest tests/test_llm_router.py -q`

---

### Task 4: Persist And Resolve Provider Pools Safely

**Files:**
- Create: `tests/test_settings_service.py`
- Create: `tests/test_db_migrations.py`
- Modify: `app/config.py`
- Modify: `app/db/session.py`
- Modify: `app/settings_service.py`

- [ ] **Step 1: Write failing config and resolution tests**

Cover:

```python
def test_provider_protocol_and_weight_are_validated(): ...
def test_global_pool_wins_over_legacy_environment(): ...
def test_empty_pool_falls_back_to_legacy_environment(): ...
def test_nonempty_disabled_pool_does_not_fall_back(): ...
def test_explicit_task_override_pins_one_provider(): ...
def test_use_global_pool_clears_old_override_fields(): ...
def test_prompt_version_alone_does_not_pin_provider(): ...
def test_public_view_masks_every_provider_key(): ...
```

- [ ] **Step 2: Write the old-database migration test**

Create an in-memory `system_settings` table without `llm_providers`, run `_auto_migrate()`, and assert `PRAGMA table_info(system_settings)` includes `llm_providers` with an empty-list default.

- [ ] **Step 3: Run tests and verify RED**

Run: `python -m pytest tests/test_settings_service.py tests/test_db_migrations.py -q`

- [ ] **Step 4: Implement validated provider configuration**

`LLMProviderConfig` validates trimmed non-empty name, HTTP(S) base URL, `temperature 0..2`, `weight 1..100`, and protocol literal. Keep `LLMConfig` as a compatibility alias/subclass with the same protocol field until all imports are migrated.

- [ ] **Step 5: Implement resolution and router factories**

Add:

```python
def resolve_llm_providers(task: Task | None = None) -> list[LLMProviderConfig]: ...
def llm_router_for_task(task: Task | None = None) -> LLMRouter: ...
def llm_router_for_task_optional(task: Task | None = None) -> LLMRouter | None: ...
```

Capture the active event loop when building a global router. Its synchronous disable callback uses `asyncio.run_coroutine_threadsafe()` to persist `enabled=false` through a fresh `SessionLocal` session. Task override routers do not mutate the global pool.

- [ ] **Step 6: Add the migration and run tests GREEN**

Add `("system_settings", "llm_providers", "JSON DEFAULT '[]'")` to `_MIGRATIONS`, include the column in cache refresh/effective settings, then rerun both test files.

---

### Task 5: Add Masked Provider Management APIs

**Files:**
- Create: `tests/test_llm_provider_api.py`
- Modify: `app/api/dto.py`
- Modify: `app/api/settings.py`
- Modify: `app/settings_service.py`

- [ ] **Step 1: Write failing service/API tests**

Cover create, duplicate-name rejection, masked list, masked-key update preservation, enable/disable, delete, connectivity test, and reorder. Reorder must preserve original full keys and reject missing/unknown/duplicate names.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest tests/test_llm_provider_api.py -q`

- [ ] **Step 3: Implement DTOs and service operations**

```python
class LLMProviderDTO(BaseModel): ...
class LLMProviderUpdateDTO(BaseModel): ...  # name is immutable in the first release
class LLMProviderOrderDTO(BaseModel):
    names: list[str]
```

All service returns go through the same masking helper. Connectivity testing runs `LLMClient.chat()` via `asyncio.to_thread()` and returns `{ok, latency_ms, model, protocol, error}`.

- [ ] **Step 4: Add routes in non-conflicting order**

```text
GET    /api/settings/llm-providers
POST   /api/settings/llm-providers
PUT    /api/settings/llm-providers/order
PUT    /api/settings/llm-providers/{name}
DELETE /api/settings/llm-providers/{name}
POST   /api/settings/llm-providers/{name}/test
```

Define `/order` before `/{name}`. Return masked data only.

- [ ] **Step 5: Run API tests and verify GREEN**

Run: `python -m pytest tests/test_llm_provider_api.py -q`

---

### Task 6: Connect Every LLM Consumer To The Router

**Files:**
- Create: `tests/test_llm_consumers.py`
- Modify: `app/orchestrator.py`
- Modify: `app/agents/worker.py`
- Modify: `app/agents/reviewer.py`
- Modify: `app/agents/collector.py`
- Modify: `app/agents/collector_llm.py`
- Modify: `app/agents/killsweep.py`
- Modify: `app/agents/escalate.py`
- Modify: `app/api/findings.py`
- Modify: `app/api/tasks.py`

- [ ] **Step 1: Write failing consumer contract tests**

Use a fake chat backend returning `LLMResponse(tool_calls=[ToolCall(...)])`. Assert collector extracts arguments, Worker serializes assistant history, and application imports without stale client symbols.

- [ ] **Step 2: Run tests and verify RED**

Run: `python -m pytest tests/test_llm_consumers.py tests/test_app_imports.py -q`

- [ ] **Step 3: Replace old factories and tool-call access**

- `llm_client_for_task*` call sites become `llm_router_for_task*`.
- Constructors require the injected backend rather than calling `LLMClient()` without configuration.
- Every `tc.function.name/arguments` becomes `tc.name/tc.arguments`; assistant history uses `response.as_history_message()`.
- Reviewer and Collector single-tool schemas use `tool_choice="auto"`; they no longer depend on a single-client forced-tool fallback hidden by Router aggregation.
- `tasks.py` keeps `resolve_llm_config()` only as a compatibility presentation helper and exposes `protocol` in task model data.
- Report-assistant endpoints create the Router on the async application loop before entering the executor, so automatic-disable persistence can schedule safely.

- [ ] **Step 4: Run consumer/import tests and verify GREEN**

Run: `python -m pytest tests/test_llm_consumers.py tests/test_app_imports.py -q`

---

### Task 7: Build The Provider Management UI

**Files:**
- Create: `frontend/src/llmProviders.js`
- Create: `frontend/tests/llmProviders.test.js`
- Create: `frontend/src/components/LlmProvidersPanel.vue`
- Modify: `frontend/src/api.js`
- Modify: `frontend/src/views/SettingsView.vue`
- Modify: `frontend/src/views/CreateView.vue`
- Modify: `frontend/src/components/TaskEditModal.vue`
- Modify: `frontend/src/style.css`
- Modify: `frontend/package.json`

- [ ] **Step 1: Write failing pure frontend tests**

Use Node's built-in test runner for enabled-weight percentages, stable up/down reordering, and disabled-provider exclusion.

Run: `npm test`

Expected: FAIL because `frontend/src/llmProviders.js` does not exist.

- [ ] **Step 2: Implement pure helpers and verify GREEN**

Add `weightDistribution(providers)` and `moveProvider(names, index, delta)`; rerun `npm test`.

- [ ] **Step 3: Add API functions**

Encode provider names with `encodeURIComponent`; add list/create/update/delete/test/order functions. Order sends `{names}` only.

- [ ] **Step 4: Implement `LlmProvidersPanel.vue`**

Match the existing settings visual system. Include loading/empty/error states, enabled-only weight distribution, add/edit modal, protocol selector, key-preserving edit, weight input, enable toggle, test latency result, delete confirmation, and explicit up/down order controls. Legacy fallback rows are read-only.

- [ ] **Step 5: Integrate settings and task override protocol**

Replace the old single-LLM fieldset with the Provider panel while keeping FOFA/default forms. Add a default “使用全局 Provider 池” mode and an explicit “任务专用模型” mode with protocol/temperature/key fields; switching back to the pool clears stale provider fields while preserving prompt version.

- [ ] **Step 6: Verify frontend**

Run: `npm test && npm run build`

Expected: tests pass and Vite builds all modules without warnings/errors.

---

### Task 8: Documentation And End-To-End Verification

**Files:**
- Modify: `.env.example`
- Modify: `README.md`

- [ ] **Step 1: Document actual precedence and migration behavior**

Document DB Provider pool, legacy `.env` fallback, task pinning, supported protocols, weighted first selection, failure classes, automatic disable, and UI recovery/re-enable flow.

- [ ] **Step 2: Run the complete backend suite**

Run: `python -m pytest -q`

Expected: all tests under `tests/` pass; `test_endpoints.py` is not collected.

- [ ] **Step 3: Run syntax/import/build verification**

```powershell
python -m compileall -q app tests
python -c "import app.main; print('OK')"
Set-Location frontend
npm test
npm run build
```

- [ ] **Step 4: Start the application with an isolated DB and smoke-test APIs**

Use a temporary `DB_PATH`, start Uvicorn, verify `/health`, `/api/settings`, Provider CRUD/masking/reorder, and old-schema startup migration. Do not call external LLM services unless an explicit test key is available.

- [ ] **Step 5: Request final code review**

Review against this plan with emphasis on secret exposure, old DB migration, sync/async failover persistence, protocol tool-history validity, and frontend masked-key handling.
