# 原项目提交适配改造 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在保留当前多 Provider、FOFA Key 池和任务工作流的前提下，按现有架构适配十个原项目提交中的证据门槛、LLM 兼容、搜索引擎和登录凭据能力。

**Architecture:** 将行为拆分到现有提示词、单 Provider Client、协议适配器、测绘引擎适配器、Collector、Worker、任务 API 和 Vue 表单中。Router 与 FOFA Key Router 的公共接口保持稳定，新增数据库字段均为向后兼容字段。

**Tech Stack:** Python 3.11、FastAPI、SQLAlchemy Async、Pydantic v2、httpx、pytest、Vue 3、Vite、Node test runner。

---

### Task 1: 建立测试基线

**Files:**
- Verify: `tests/`
- Verify: `frontend/tests/`
- Verify: `frontend/src/`

- [ ] **Step 1: 记录工作区和分支状态**

Run:

```powershell
git status --short --branch
git log -3 --oneline
```

Expected: 当前分支为 `codex/upstream-commit-adaptation`；只存在用户原有未跟踪文件，没有实现代码改动。

- [ ] **Step 2: 运行后端基线**

Run:

```powershell
pytest -q
```

Expected: 全部现有 Python 测试通过。若存在基线失败，先记录并定位为当前分支已有问题，不把失败混入功能改造。

- [ ] **Step 3: 运行前端基线**

Run:

```powershell
npm --prefix frontend test
npm --prefix frontend run build
```

Expected: Node 测试和 Vite 生产构建通过。

### Task 2: 强化写操作侧面回读证据门槛

**Files:**
- Modify: `app/agents/prompts.py`
- Modify: `tests/test_enterprise_prompt_policy.py`
- Modify: `tests/test_reviewer_policy.py`
- Modify: `tests/test_prompt_profiles.py`

- [ ] **Step 1: 写入失败测试**

在提示词测试中增加精确语义断言：

```python
def test_write_actions_require_independent_readback_evidence():
    prompts = (
        prompts_module.ENTERPRISE_WORKER_SYSTEM_PROMPT,
        prompts_module.ENTERPRISE_REVIEWER_SYSTEM_PROMPT,
        prompts_module.WORKER_SYSTEM_PROMPT_COMPACT,
        prompts_module.REVIEWER_SYSTEM_PROMPT_COMPACT,
    )
    for prompt in prompts:
        assert "侧面" in prompt
        assert "回读" in prompt
        assert "before" in prompt.lower()
        assert "after" in prompt.lower()
```

- [ ] **Step 2: 验证测试因缺少完整语义而失败**

Run:

```powershell
pytest -q tests/test_enterprise_prompt_policy.py tests/test_reviewer_policy.py tests/test_prompt_profiles.py
```

Expected: 至少一个提示词缺少“侧面回读”断言而失败。

- [ ] **Step 3: 最小修改现有四类提示词**

将写操作规则统一为：

```text
写/删/改接口必须使用详情、列表、重新登录或其他独立读取路径侧面回读，给出 before→after；只有写接口自身的 200/success 不构成状态变化证据。
```

不改动现有 SRC 类型规则、工具边界和漏洞评级标准。

- [ ] **Step 4: 运行提示词测试和相关策略回归**

Run:

```powershell
pytest -q tests/test_enterprise_prompt_policy.py tests/test_reviewer_policy.py tests/test_prompt_profiles.py tests/test_edusrc_prompt_policy.py
```

Expected: 全部通过。

- [ ] **Step 5: 提交提示词改造**

```powershell
git add app/agents/prompts.py tests/test_enterprise_prompt_policy.py tests/test_reviewer_policy.py tests/test_prompt_profiles.py
git commit -m "修复：强化写操作侧面回读证据"
```

### Task 3: 适配 LLM 强制工具降级与非标准响应

**Files:**
- Modify: `app/llm/client.py`
- Modify: `app/llm/protocols.py`
- Modify: `tests/test_llm_client.py`
- Modify: `tests/test_llm_protocols.py`
- Modify: `tests/test_llm_router.py`

- [ ] **Step 1: 为强制工具选择写失败测试**

使用现有 fake HTTP client 构造先 422、后 200 的响应：

```python
def test_forced_tool_choice_422_retries_same_provider_with_auto(monkeypatch):
    client, transport = build_client_with_responses(
        error_response(422, "Upstream error: 422"),
        chat_response(content="ok"),
    )
    result = client.chat(
        [{"role": "user", "content": "review"}],
        tools=[SUBMIT_REVIEW_TOOL],
        tool_choice={"type": "function", "function": {"name": "submit_review"}},
    )
    assert result.content == "ok"
    assert transport.requests[0]["tool_choice"]["function"]["name"] == "submit_review"
    assert transport.requests[1]["tool_choice"] == "auto"
```

同时增加：普通 422 不降级、降级只发生一次、第二次失败向 Router 抛错的测试。

- [ ] **Step 2: 验证强制工具测试失败**

Run:

```powershell
pytest -q tests/test_llm_client.py tests/test_llm_router.py
```

Expected: 当前 Client 直接抛出 422，测试失败。

- [ ] **Step 3: 在 Client 内实现一次本地降级**

新增纯函数：

```python
def _is_forced_tool_choice(value: Any) -> bool:
    return isinstance(value, dict) and bool((value.get("function") or {}).get("name"))


def _is_forced_tool_choice_unsupported(error: LLMError) -> bool:
    text = f"{error.status or ''} {error.code} {error.detail}".lower()
    if "thinking mode does not support this tool_choice" in text:
        return True
    if str(error.status) not in {"400", "422"} and " 400 " not in f" {text} " and " 422 " not in f" {text} ":
        return False
    if str(error.status) == "422" or "upstream error" in text or "unprocessable" in text:
        return True
    return any(marker in text for marker in (
        "tool_choice", "tool choice", "function call", "invalid parameter",
        "invalid_request", "unsupported", "not support", "参数有误", "参数错误",
    ))
```

`LLMClient.chat()` 抽取单次发送函数；第一次失败满足条件时重建 `tool_choice="auto"` 的 payload 并使用同一 HTTP client 重试一次。其余错误处理继续使用 `_classify_error()`。

- [ ] **Step 4: 为非标准响应写失败测试**

在协议测试中覆盖：

```python
@pytest.mark.parametrize("raw, expected", [
    ('{"choices":[{"message":{"content":"json text"}}]}', "json text"),
    ("plain text", "plain text"),
    ('data: {"choices":[{"message":{"content":"sse text"}}]}\ndata: [DONE]', "sse text"),
])
def test_openai_chat_coerces_nonstandard_payload(raw, expected):
    normalized = coerce_response_payload(raw, "openai_chat")
    assert OpenAIChatAdapter().parse_response(normalized).content == expected
```

增加 content 文本块和对象类型 tool arguments 的断言。

- [ ] **Step 5: 验证响应归一化测试失败**

Run:

```powershell
pytest -q tests/test_llm_protocols.py
```

Expected: 当前适配器只接受字典，字符串用例失败。

- [ ] **Step 6: 实现协议入口归一化**

在 `protocols.py` 增加 `coerce_response_payload(raw, protocol_name)`。OpenAI Chat 的纯文本包装为：

```python
{"choices": [{"message": {"role": "assistant", "content": text}}]}
```

JSON 字符串先 `json.loads`；SSE 取最后一条有效 `data:`；结构化 `error` 抛给 Client 转为 `LLMError`。`OpenAIChatAdapter.parse_response()` 兼容 choice/message 字符串、文本块列表和对象 arguments。Client 在 usage 与 parse 前调用归一化函数。

- [ ] **Step 7: 验证 LLM 和 Router 回归**

Run:

```powershell
pytest -q tests/test_llm_client.py tests/test_llm_protocols.py tests/test_llm_router.py tests/test_llm_consumers.py tests/test_llm_provider_api.py
```

Expected: 全部通过；Router 权重、故障转移和自动禁用测试无变化。

- [ ] **Step 8: 提交 LLM 改造**

```powershell
git add app/llm/client.py app/llm/protocols.py tests/test_llm_client.py tests/test_llm_protocols.py tests/test_llm_router.py
git commit -m "修复：增强多Provider工具降级与响应兼容"
```

### Task 4: 适配查询翻译与测绘引擎 API

**Files:**
- Modify: `app/engines/base.py`
- Modify: `app/engines/translator.py`
- Modify: `app/engines/fofa.py`
- Modify: `app/engines/quake.py`
- Modify: `app/engines/hunter.py`
- Modify: `app/engines/zoomeye.py`
- Modify: `app/engines/shodan.py`
- Modify: `app/engines/censys.py`
- Modify: `app/agents/collector.py`
- Create: `tests/test_engine_translator.py`
- Create: `tests/test_engine_adapters.py`
- Modify: `tests/test_fofa_runtime_consumers.py`

- [ ] **Step 1: 写翻译器失败测试**

覆盖 FOFA 和原生语法：

```python
def test_translates_fofa_domain_and_preserves_native_queries():
    assert translate_fofa_query('domain=".edu.cn" && port="443"', "hunter") == (
        'domain.suffix="edu.cn" && port="443"'
    )
    native = 'domain.suffix="edu.cn" && web.status_code="200"'
    assert translate_fofa_query(native, "hunter") == native
```

为 Quake、ZoomEye、Shodan、Censys 增加字段、逻辑连接和否定断言。

- [ ] **Step 2: 验证翻译器测试失败**

Run:

```powershell
pytest -q tests/test_engine_translator.py
```

Expected: 当前翻译结果字段或原生透传不符合断言。

- [ ] **Step 3: 实现结构化翻译和原生语法检测**

将 `translator.py` 整理为：

```python
def translate_fofa_query(query: str, target_engine: str) -> str:
    engine = (target_engine or "fofa").strip().lower()
    if not query or engine in {"", "fofa"}:
        return query
    if looks_like_native_syntax(engine, query) or not looks_like_fofa_syntax(query):
        return query
    translator = _FOFA_TRANSLATORS.get(engine)
    return translator(query) if translator else query
```

解析器保留 join；各翻译器使用正确字段表并处理 domain 前导点。

- [ ] **Step 4: 写引擎请求失败测试**

使用 `httpx.MockTransport` 或 monkeypatch 的 `AsyncClient` 验证请求：

```python
def test_hunter_uses_openapi_and_base64_query():
    result, request = run_engine(HunterEngine(), response=HUNTER_RESPONSE)
    assert request.url.path.endswith("/openApi/search")
    assert decode_urlsafe(request.url.params["search"]) == 'domain="example.com"'
    assert request.url.params["is_web"] == "3"
    assert result.results[0][3] == "Login"
```

ZoomEye 验证 v2 POST；Shodan 验证没有 `limit`；Censys 验证 cursor 与 `next_cursor`。

- [ ] **Step 5: 验证引擎测试失败**

Run:

```powershell
pytest -q tests/test_engine_adapters.py
```

Expected: 当前 URL、参数或字段断言失败。

- [ ] **Step 6: 实现引擎 API 修复**

`EngineResult` 增加：

```python
next_cursor: str | None = None
```

所有 `search()` 增加 `cursor: str | None = None`。按设计文档分别修改 Hunter、ZoomEye、Shodan 和 Censys；FOFA 与 Quake 只接受兼容参数。

- [ ] **Step 7: 接入 Collector 且保持 FOFA Router 路径**

非 FOFA 分支调用：

```python
native_query = translate_fofa_query(cur_query, engine_name)
res = await engine.search(
    key,
    native_query,
    page=next_cursor,
    page_size=size,
    base_url=base_url,
    cursor=cfg.get("engine_cursor") or None,
)
```

FOFA Router lambda 保留现有 key/base 原子绑定，只额外接受可选参数签名。请求成功后才保存 `next_cursor`。

- [ ] **Step 8: 运行引擎与 FOFA 回归**

Run:

```powershell
pytest -q tests/test_engine_translator.py tests/test_engine_adapters.py tests/test_fofa_errors.py tests/test_fofa_router.py tests/test_fofa_runtime_consumers.py tests/test_fofa_key_config.py
```

Expected: 全部通过。

- [ ] **Step 9: 提交搜索引擎改造**

```powershell
git add app/engines app/agents/collector.py tests/test_engine_translator.py tests/test_engine_adapters.py tests/test_fofa_runtime_consumers.py
git commit -m "修复：适配测绘引擎语法与接口"
```

### Task 5: 实现登录凭据核心、模型和迁移

**Files:**
- Create: `app/agents/auth_bootstrap.py`
- Modify: `app/db/models.py`
- Modify: `app/db/session.py`
- Create: `tests/test_auth_bootstrap.py`
- Modify: `tests/test_db_migrations.py`

- [ ] **Step 1: 写解析与匹配失败测试**

```python
def test_explicit_url_beats_wildcard_binding():
    bindings = [
        {"target": "*", "cookie": "sid=default"},
        {"target": "https://app.test/login", "authorization": "Bearer exact"},
    ]
    result = match_auth_to_target("https://app.test/login", bindings)
    assert result.matched_by == "url"
    assert result.context["headers"]["Authorization"] == "Bearer exact"
    assert "sid" not in result.context["cookies"]
```

同时覆盖快捷粘贴、host:port、host、通配符、同层合并和无匹配。

- [ ] **Step 2: 写保守登录失败测试**

使用 fake executor 记录 URL：

```python
def test_password_login_without_login_url_only_checks_target_entry():
    executor = FakeExecutor(entry_html=LOGIN_FORM_HTML)
    result = bootstrap_auth(executor, PASSWORD_CONTEXT, "https://app.test/")
    assert result.status == "login_ok"
    assert {call.url for call in executor.calls} <= {"https://app.test/"}
```

增加显式 `login_url`、Cookie/Bearer 注入、跨源 `login_url` 拒绝、无上下文零请求、单独 200 不算登录成功和事件字段无明文测试。

- [ ] **Step 3: 验证凭据测试失败**

Run:

```powershell
pytest -q tests/test_auth_bootstrap.py
```

Expected: 模块尚未存在，测试收集失败。

- [ ] **Step 4: 实现凭据解析、匹配和保守登录**

实现以下公共函数和类型：

```python
normalize_binding(raw) -> dict
normalize_bindings(raw_list) -> list[dict]
has_any_bindings(raw_list) -> bool
match_auth_to_target(url, bindings, manual_lines=None) -> MatchResult
resolve_auth_context_for_target(task_bindings, url, manual_lines=None) -> dict | None
bootstrap_auth(executor, auth_context, base_url) -> AuthAttemptResult
format_auth_status_message(result) -> str
user_auth_prompt_block(context, attempt) -> str
```

登录实现只获取 `login_url` 或目标入口，解析其中第一个含 password input 的 form，保留 hidden input，并执行一次提交。使用 `urlparse` 校验目标同源。

- [ ] **Step 5: 写迁移失败测试**

在旧 schema 测试中断言新增列：

```python
assert {"auth_bindings"} <= task_columns
assert {"auth_context", "auth_status"} <= target_columns
```

- [ ] **Step 6: 验证迁移测试失败**

Run:

```powershell
pytest -q tests/test_db_migrations.py
```

Expected: 新列尚未存在。

- [ ] **Step 7: 增加模型字段和加法迁移**

```python
auth_bindings: Mapped[list] = mapped_column(JSON, default=list)
auth_context: Mapped[dict | None] = mapped_column(JSON, nullable=True)
auth_status: Mapped[dict | None] = mapped_column(JSON, nullable=True)
```

在 `_MIGRATIONS` 中追加三个 `ALTER TABLE ADD COLUMN` 描述，不修改已有迁移和索引。

- [ ] **Step 8: 运行核心与迁移测试**

Run:

```powershell
pytest -q tests/test_auth_bootstrap.py tests/test_db_migrations.py tests/test_app_imports.py
```

Expected: 全部通过。

- [ ] **Step 9: 提交凭据核心**

```powershell
git add app/agents/auth_bootstrap.py app/db/models.py app/db/session.py tests/test_auth_bootstrap.py tests/test_db_migrations.py
git commit -m "功能：增加目标登录凭据核心与迁移"
```

### Task 6: 接入 Collector、Worker、Orchestrator 和任务 API

**Files:**
- Modify: `app/agents/collector.py`
- Modify: `app/agents/worker.py`
- Modify: `app/orchestrator.py`
- Modify: `app/api/dto.py`
- Modify: `app/api/tasks.py`
- Modify: `tests/test_collector_scope.py`
- Modify: `tests/test_llm_consumers.py`
- Modify: `tests/test_task_operations_api.py`
- Modify: `tests/test_task_queue.py`

- [ ] **Step 1: 写任务 API 失败测试**

```python
def test_task_auth_bindings_round_trip(client):
    binding = {
        "target": "https://app.test",
        "username": "operator",
        "password": "secret",
        "login_url": "https://app.test/login",
    }
    created = client.post("/api/tasks", json=task_payload(auth_bindings=[binding]))
    assert created.status_code == 200
    assert created.json()["auth_bindings"][0]["password"] == "secret"
    fetched = client.get(f"/api/tasks/{created.json()['id']}")
    assert fetched.json()["auth_bindings"][0] == {**EMPTY_BINDING, **binding}
```

增加 PATCH 替换、缺省空列表和旧任务读取测试。

- [ ] **Step 2: 写入队与 Worker 启动失败测试**

断言手动、站点和非 FOFA 搜集目标获得匹配 `auth_context`；无绑定目标保持 `None`。Worker 测试断言 `auth_status` 在第一次 `llm.chat()` 前产生，并且凭据状态持久化异常不会阻断 Worker。

- [ ] **Step 3: 验证 API 与运行时测试失败**

Run:

```powershell
pytest -q tests/test_task_operations_api.py tests/test_collector_scope.py tests/test_llm_consumers.py tests/test_task_queue.py
```

Expected: 新 DTO 字段、模型赋值和启动事件断言失败。

- [ ] **Step 4: 接入 DTO 和任务 API**

新增 `AuthBindingDTO`，Create 默认空列表、Update 使用 Optional、Response 返回列表。创建和修改任务时使用 `model_dump()` 保存结构化字典，不额外脱敏任务响应。

- [ ] **Step 5: 在目标入队时绑定上下文**

Collector 增加：

```python
def _auth_context_for(task: Task, url: str) -> dict | None:
    return resolve_auth_context_for_target(
        task.auth_bindings or [],
        url,
        [str(item).strip() for item in task.manual_targets or [] if str(item).strip()],
    )
```

所有新增 Target 的路径只补充 `auth_context=`，保持原去重和状态逻辑。

- [ ] **Step 6: 在 Worker 开始前执行凭据启动**

Worker 增加 `_bootstrap_user_auth()` 和 `_user_auth_block()`。`run()` 在构建首次用户消息前调用启动函数，异常转换为脱敏 `auth_status` 事件后继续。

- [ ] **Step 7: 持久化并展示运行状态**

Orchestrator 将 `Target.auth_context` 放入 `target_meta`，在 live worker 中维护 `auth`、`auth_kinds`、`auth_label`。收到 `auth_status` 时异步写入 `Target.auth_status` 和 `TaskEvent`，持久化 payload 经过明确字段白名单。

- [ ] **Step 8: 运行后端集成测试**

Run:

```powershell
pytest -q tests/test_task_operations_api.py tests/test_collector_scope.py tests/test_llm_consumers.py tests/test_task_queue.py tests/test_auth_bootstrap.py tests/test_db_migrations.py
```

Expected: 全部通过。

- [ ] **Step 9: 提交后端集成**

```powershell
git add app/agents/collector.py app/agents/worker.py app/orchestrator.py app/api/dto.py app/api/tasks.py tests/test_collector_scope.py tests/test_llm_consumers.py tests/test_task_operations_api.py tests/test_task_queue.py
git commit -m "功能：接入任务凭据绑定与运行反馈"
```

### Task 7: 接入前端凭据表单和看板反馈

**Files:**
- Create: `frontend/src/authBindings.js`
- Modify: `frontend/src/views/CreateView.vue`
- Modify: `frontend/src/components/TaskEditModal.vue`
- Modify: `frontend/src/views/BoardView.vue`
- Modify: `frontend/src/style.css`
- Create: `frontend/tests/authBindings.test.js`
- Modify: `frontend/tests/taskSourceModes.test.js`
- Modify: `frontend/tests/operationsRegression.test.js`

- [ ] **Step 1: 写前端逻辑失败测试**

```javascript
test("纯 FOFA 隐藏凭据区，其他来源显示", () => {
  assert.equal(shouldShowAuthBindings("fofa"), false);
  for (const source of ["manual", "both", "site"]) {
    assert.equal(shouldShowAuthBindings(source), true);
  }
});

test("导出时过滤空绑定并保留明文", () => {
  const rows = exportAuthBindings([emptyAuthBinding(), {
    ...emptyAuthBinding(), target: "app.test", username: "u", password: "p",
  }]);
  assert.deepEqual(rows, [{
    ...emptyAuthBinding(), target: "app.test", username: "u", password: "p",
  }]);
});
```

增加徽章状态映射和 Vue 源码契约测试。

- [ ] **Step 2: 验证前端测试失败**

Run:

```powershell
npm --prefix frontend test
```

Expected: `authBindings.js` 尚未存在或组件契约缺失。

- [ ] **Step 3: 实现可复用前端逻辑**

`authBindings.js` 导出：

```javascript
export function emptyAuthBinding() { /* 返回完整空结构 */ }
export function shouldShowAuthBindings(source) { return source !== "fofa"; }
export function exportAuthBindings(rows) { /* trim 并过滤空行 */ }
export function loadAuthBindings(task) { /* 空列表返回一条空结构 */ }
export function authBadge(status) { /* 返回 text/className */ }
```

- [ ] **Step 4: 接入创建和编辑表单**

复用 helper 管理绑定数组。纯 FOFA 隐藏区并提交空数组；其他模式提交导出结果。表单提供目标选择、快捷粘贴、账号、密码、Cookie、Authorization 和登录 URL。编辑弹窗从任务响应加载完整绑定。

- [ ] **Step 5: 接入 Board**

Worker 卡片使用 helper 显示凭据状态徽章；活动流识别 `auth_status`。只展示后端已脱敏字段。

- [ ] **Step 6: 增加局部样式**

在当前表单和 Worker 卡片样式附近增加凭据布局。使用现有圆角、颜色变量和响应式断点；不改变全局布局和已有组件选择器。

- [ ] **Step 7: 运行前端测试和构建**

Run:

```powershell
npm --prefix frontend test
npm --prefix frontend run build
```

Expected: 全部通过，构建无 Vue 编译错误。

- [ ] **Step 8: 提交前端集成**

```powershell
git add frontend/src/authBindings.js frontend/src/views/CreateView.vue frontend/src/components/TaskEditModal.vue frontend/src/views/BoardView.vue frontend/src/style.css frontend/tests/authBindings.test.js frontend/tests/taskSourceModes.test.js frontend/tests/operationsRegression.test.js
git commit -m "功能：增加登录凭据表单与看板状态"
```

### Task 8: 全量验证和最终审查

**Files:**
- Verify: all changed files

- [ ] **Step 1: 运行完整后端测试**

Run:

```powershell
pytest -q
```

Expected: 全部通过，无新增 warning 或未处理异常。

- [ ] **Step 2: 运行完整前端测试与构建**

Run:

```powershell
npm --prefix frontend test
npm --prefix frontend run build
```

Expected: 全部通过。

- [ ] **Step 3: 静态检查差异范围**

Run:

```powershell
git diff --check HEAD~5..HEAD
git status --short
git log --oneline --decorate -10
```

Expected: 无空白错误；用户原有未跟踪文件仍未加入提交；实现提交均使用中文说明。

- [ ] **Step 4: 审查关键不变量**

逐项确认：

```text
LLMRouter 公共接口未变
Provider 权重与故障顺序未变
auth/quota 之外错误不自动禁用 Provider
FofaKeyRouter 调用与状态持久化未被绕过
FOFA 私有地址仍由 FOFA_ALLOWED_HOSTS 控制
无凭据任务不产生额外登录请求
auth_status 不包含凭据明文
旧任务数据可读取和执行
```

- [ ] **Step 5: 提交必要的回归修复**

若全量测试发现只与本次改造相关的问题，先写复现测试再修复，并使用中文提交：

```powershell
git diff --check
git commit -am "修复：完善原项目提交适配回归"
```
