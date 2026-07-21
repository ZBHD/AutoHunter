# FOFA 与 LiteLLM 可靠性修复实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 修复 FOFA 每日额度误判和高频重试刷屏，并让 LiteLLM Provider 的工具协议配置与健康检测准确匹配生产端点。

**Architecture:** FOFA 在错误分类层识别第三方额度文案，在 Router 层按 Key 保存 transient 冷却，在 Collector 层保存脱敏诊断并限制重复事件。LLM 继续使用每 Provider 独立协议，健康探测增加最小工具调用和备用协议诊断，但正常请求不隐式双发。

**Tech Stack:** Python 3、Pydantic、SQLAlchemy/SQLite、pytest、pytest-asyncio、Vue 3、Vitest/Node tests、Docker Compose。

---

### Task 1: 修复异步测试基线

**Files:**
- Modify: `requirements-dev.txt`

- [ ] **Step 1: 添加测试插件依赖**

在 `requirements-dev.txt` 的 pytest 依赖后加入：

```text
pytest-asyncio>=0.23,<1
```

- [ ] **Step 2: 安装并验证插件可用**

Run: `\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt`

Run: `\.venv\Scripts\python.exe -m pytest tests/test_fofa_runtime_consumers.py::test_collector_transient_keeps_page_and_does_not_rotate -q`

Expected: 测试被 pytest-asyncio 接管执行，不再出现 `async def functions are not natively supported`。

- [ ] **Step 3: 提交测试基线修复**

```text
git add requirements-dev.txt
git commit -m "修复：补充异步测试依赖"
```

### Task 2: 补齐 FOFA 每日额度分类

**Files:**
- Modify: `app/fofa/client.py:53-70`
- Test: `tests/test_fofa_errors.py`

- [ ] **Step 1: 写失败测试**

在 `tests/test_fofa_errors.py` 加入：

```python
@pytest.mark.parametrize("message", [
    "[-200] 今日调用次数已用完",
    "今日调用次数已用完",
    "调用次数已用完",
    "today's call limit has been exhausted",
])
def test_call_exhaustion_messages_are_daily_limit(message: str) -> None:
    kind, code, retry_after = classify(message, status=200)
    assert kind == "daily_limit"
    assert code in {"", "-200"}
    assert retry_after == 3600


def test_standalone_minus_200_is_not_daily_limit() -> None:
    assert classify("upstream returned -200", status=200)[0] == "transient"
```

- [ ] **Step 2: 运行测试确认红灯**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_fofa_errors.py -k "call_exhaustion or standalone_minus_200" -q`

Expected: 新增额度文案测试失败，当前结果为 `transient`。

- [ ] **Step 3: 实现最小分类修复**

在 `_FOFA_DAILY_LIMIT_MARKERS` 增加中英文额度耗尽短语；保留现有优先级，并在 `classify_fofa_failure` 中让文案匹配优先于 HTTP 状态。不要单独把 `-200` 加入 marker，避免误判普通上游错误。

- [ ] **Step 4: 运行 FOFA 错误测试**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_fofa_errors.py -q`

Expected: 全部通过。

- [ ] **Step 5: 提交分类修复**

```text
git add app/fofa/client.py tests/test_fofa_errors.py
git commit -m "修复：识别 FOFA 今日调用次数耗尽"
```

### Task 3: 为 Router 增加 transient Key 冷却

**Files:**
- Modify: `app/config.py:71-89`, `app/fofa/router.py:391-480`
- Modify: `frontend/src/fofaKeys.js:1-16`
- Test: `tests/test_fofa_router.py`, `tests/test_fofa_key_config.py`

- [ ] **Step 1: 写失败测试**

在 `tests/test_fofa_router.py` 加入基于现有 `clock()` helper 的测试：

```python
def test_transient_failure_enters_bounded_cooldown_and_recovers() -> None:
    start = datetime(2026, 7, 16, tzinfo=UTC)
    now, advance = clock(start)
    router = FofaKeyRouter([key("A", "secret-a"), key("B", "secret-b")], now=now)

    with pytest.raises(FofaError):
        router.execute_sync(lambda *_: (_ for _ in ()).throw(
            FofaError("gateway timeout", kind="transient")
        ))
    assert router.keys[0].runtime_state == "transient_cooldown"
    assert router.keys[0].cooldown_until == start + timedelta(seconds=15)

    advance(seconds=15)
    with pytest.raises(FofaError):
        router.execute_sync(lambda *_: (_ for _ in ()).throw(
            FofaError("gateway timeout", kind="transient")
        ))
    assert router.keys[0].failure_count == 2
    assert router.keys[0].cooldown_until == start + timedelta(seconds=45)
```

更新已有 transient 测试，期望运行态从 `ready` 改为 `transient_cooldown`，并保持同一次业务请求不轮换 Key。

- [ ] **Step 2: 运行测试确认红灯**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_fofa_router.py -k "transient" -q`

Expected: 当前运行态仍为 `ready`，新增断言失败。

- [ ] **Step 3: 实现状态与退避**

在 `FofaRuntimeState` 增加 `transient_cooldown`。在 `_apply_failure_locked` 的 transient 分支按当前同类失败次数计算 `15, 30, 60, 120, 300` 秒退避，设置 `runtime_state="transient_cooldown"` 和 `cooldown_until`。成功分支继续清除所有失败字段并恢复 `ready`。

候选快照只把 `auth_invalid` 和 `daily_suspended` 作为终止状态；未来 `cooldown_until` 统一排除。`_next_retry_at` 对 transient 冷却同样返回最早时间。并发 stale failure 合并逻辑增加 `transient_cooldown` 的同状态判断。

- [ ] **Step 4: 更新前端状态展示**

在 `frontend/src/fofaKeys.js` 增加：

```javascript
transient_cooldown: { code: "transient_cooldown", label: "临时故障冷却", tone: "warn" },
```

并让 `isFofaKeyUsable` 对 `transient_cooldown` 与其它带未来 `cooldown_until` 的状态采用相同到期判断。

- [ ] **Step 5: 运行 Router、配置和前端状态测试**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_fofa_router.py tests/test_fofa_key_config.py -q`

Run: `npm --prefix frontend test -- --runInBand`

Expected: Python 与前端相关测试均通过。

- [ ] **Step 6: 提交 Router 修复**

```text
git add app/config.py app/fofa/router.py frontend/src/fofaKeys.js tests/test_fofa_router.py tests/test_fofa_key_config.py
git commit -m "修复：为 FOFA 临时故障增加 Key 级退避"
```

### Task 4: 保存 FOFA 诊断并限制事件刷屏

**Files:**
- Modify: `app/agents/collector.py:413-550`
- Test: `tests/test_fofa_runtime_consumers.py`

- [ ] **Step 1: 写失败测试**

新增测试验证同一错误签名在 60 秒内只调用一次 progress，且配置保存错误码和脱敏摘要：

```python
@pytest.mark.asyncio
async def test_collector_transient_diagnostics_are_redacted_and_rate_limited(monkeypatch):
    from types import SimpleNamespace
    from app.agents import collector
    from app.config import FofaKeyConfig
    from app.fofa.client import FofaError
    from app.fofa.router import FofaKeyRouter

    secret = "secret-a"
    reports = []

    class Engine:
        display_name = "FOFA"

        async def search(self, key, query, page, page_size, base_url=None):
            raise FofaError(f"gateway timeout {key}", kind="transient", code="502")

    async def progress(phase, text, **payload):
        reports.append((phase, text, payload))

    monkeypatch.setattr(collector, "get_engine", lambda _name: Engine())
    monkeypatch.setattr(collector, "resolve_engine_config", lambda _task: {
        "engine": "fofa", "key": "", "base_url": "https://fofa.info",
        "max_pages": 2, "page_size": 1,
    })
    monkeypatch.setattr(collector, "_llm_for_task", lambda _task: None)
    task = SimpleNamespace(
        fofa_config={"current_query": 'host="example.com"', "cursor": 0},
        src_type="edusrc", fofa_query="",
    )
    router = FofaKeyRouter([FofaKeyConfig(name="A", key=secret)])
    session = SimpleNamespace(add=lambda _obj: None)

    await collector._fofa_collect(session, task, set(), {}, progress, fofa_router=router)
    first_report_count = len(reports)
    await collector._fofa_collect(session, task, set(), {}, progress, fofa_router=router)

    assert first_report_count == 1
    assert len(reports) == 1
    assert task.fofa_config["last_fofa_error_code"] == "502"
    assert secret not in repr(task.fofa_config)
    assert secret not in repr(reports)
```

- [ ] **Step 2: 运行测试确认红灯**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_fofa_runtime_consumers.py -k "diagnostics or transient" -q`

Expected: 新增诊断或事件次数断言失败。

- [ ] **Step 3: 实现诊断字段与签名限频**

在 Collector 中增加纯函数 `fofa_error_signature(error)` 和 `should_report_fofa_error(cfg, signature, now)`：签名由 `kind/code/脱敏消息` 组成，`fofa_last_error_signature` 与 `fofa_last_error_reported_at` 使用 UTC ISO 字符串持久化，间隔小于 60 秒时不调用 `report`。

`FofaError` 分支写入 `last_fofa_error`、`last_fofa_error_kind`、`last_fofa_error_code`、`fofa_retry_after`，并保持游标不变；只有 `should_report_fofa_error` 为真时写 `collector_phase` 事件。成功分支清除这些字段和限频字段。

- [ ] **Step 4: 运行 Collector 回归测试**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_fofa_runtime_consumers.py tests/test_collector_stop_search.py -q`

Expected: 全部通过，且旧的游标保持行为不变。

- [ ] **Step 5: 提交 Collector 修复**

```text
git add app/agents/collector.py tests/test_fofa_runtime_consumers.py
git commit -m "修复：保存 FOFA 诊断并限制重复事件"
```

### Task 5: 分类 LiteLLM 协议错误

**Files:**
- Modify: `app/llm/client.py:82-133`
- Test: `tests/test_llm_client.py`

- [ ] **Step 1: 写失败测试**

增加错误分类测试：

```python
def test_protocol_shape_errors_are_classified_as_protocol() -> None:
    error = _classify_error(Exception(
        "400 Bad Request unknown variant `custom`; expected `web_search_20250305`"
    ))
    assert error.kind == "protocol"
    assert "协议" in error.diagnostic()
```

同时覆盖 `unsupported model` 与 `tools[0]` 反序列化错误，确保不再落入 `unknown`。

- [ ] **Step 2: 运行测试确认红灯**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_llm_client.py -k "protocol_shape" -q`

Expected: 当前结果为 `unknown`，测试失败。

- [ ] **Step 3: 实现协议错误分类**

在 `_classify_error` 的未知错误分支之前增加协议 marker：`unknown variant`, `failed to deserialize`, `tools[`, `unsupported model`, `invalid tool schema`。返回 `LLMError("protocol", "LLM Provider 协议或工具格式不兼容，请检查协议配置。", e, status=status, code=safe_code, detail=detail)`，继续保留脱敏 detail、status 和 code。

- [ ] **Step 4: 运行 LLM Client 回归测试**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_llm_client.py tests/test_llm_protocols.py -q`

Expected: 全部通过。

- [ ] **Step 5: 提交协议错误分类**

```text
git add app/llm/client.py tests/test_llm_client.py
git commit -m "修复：明确分类 LiteLLM 协议错误"
```

### Task 6: 让 LLM 健康检测验证工具协议

**Files:**
- Modify: `app/settings_service.py:1279-1320`
- Modify: `app/api/settings.py:137-150`（仅在需要扩展响应字段时）
- Modify: `frontend/src/components/LlmProvidersPanel.vue`（显示协议建议）
- Test: `tests/test_llm_provider_api.py`, `tests/test_llm_protocols.py`

- [ ] **Step 1: 写失败测试**

为 `probe_llm_provider` 增加 fake `LLMClient` 测试：

```python
def test_probe_llm_provider_sends_minimal_tool_schema(monkeypatch):
    calls = []
    class FakeClient:
        def __init__(self, provider): pass
        def chat(self, **kwargs): calls.append(kwargs); return object()
        _client = None
    monkeypatch.setattr(settings_service, "LLMClient", FakeClient)
    result = asyncio.run(settings_service.probe_llm_provider(provider))
    assert result["ok"] is True
    assert calls[0]["tools"][0]["type"] == "function"
    assert calls[0]["tool_choice"] == "none"
```

增加协议失败 fake：返回 `LLMError(kind="protocol")`，断言结果包含 `category="protocol"`、当前 `protocol` 和备用协议建议，且不调用配置保存函数。

- [ ] **Step 2: 运行测试确认红灯**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_llm_provider_api.py -k "tool_schema or protocol" -q`

Expected: 当前探测未发送 `tools`，新增断言失败。

- [ ] **Step 3: 实现最小工具探测**

`probe_llm_provider` 发送一个名为 `noop` 的 object 工具，`tool_choice="none"`，`max_tokens=16`。结果增加 `category`、`recommended_protocol`、`diagnostic` 字段；普通文本成功仍返回 `ok=True`。

当当前协议返回 `LLMError.kind == "protocol"` 时，使用 `ADAPTER_REGISTRY` 中唯一的备用协议构建一次诊断请求，仅用于返回建议，不写配置、不覆盖当前 Provider。协议候选顺序固定为 `openai_chat -> anthropic_messages -> openai_responses`，排除当前值。

在 `LlmProvidersPanel.vue` 的健康结果区域显示 `recommended_protocol` 和脱敏 `diagnostic`，不自动保存。

- [ ] **Step 4: 运行协议与 API 回归测试**

Run: `\.venv\Scripts\python.exe -m pytest tests/test_llm_provider_api.py tests/test_llm_protocols.py tests/test_llm_client.py -q`

Expected: 全部通过。

- [ ] **Step 5: 提交健康检测修复**

```text
git add app/settings_service.py app/api/settings.py frontend/src/components/LlmProvidersPanel.vue tests/test_llm_provider_api.py tests/test_llm_protocols.py
git commit -m "功能：让 LiteLLM 健康检测验证工具协议"
```

### Task 7: 生产配置迁移与验收

**Files:**
- No source changes; operate through existing settings API/UI and deployment scripts.

- [ ] **Step 1: 建立生产回滚点**

在服务器执行现有数据备份脚本，确认 `autohunter_ah_data` 备份文件生成；记录当前镜像 ID、Provider 协议和任务状态。不得删除历史事件。

- [ ] **Step 2: 部署本地镜像**

Run: `\.venv\Scripts\python.exe -m pytest tests -q`

Run: `npm --prefix frontend test -- --runInBand`

Run: `docker build -t autohunter:reliability-fix .`

通过现有部署脚本滚动替换应用容器，保留数据卷和端口映射。

- [ ] **Step 3: 迁移 Provider 协议**

通过设置服务将 LLM-1 的 `protocol` 改为 `anthropic_messages`；确认 LLM-2 仍为 `openai_chat`。使用设置页逐项健康检测，预期 LLM-1 和 LLM-2 的工具探测均成功。

- [ ] **Step 4: 验证 FOFA 状态机**

确认 4 个生产 Key 中额度耗尽项显示 `额度冷却` 或 `今日暂停`，不再显示 `ready`；确认任务事件不再每几秒新增 transient；确认当前查询游标在额度恢复前保持不变。

- [ ] **Step 5: 验证 Worker/审核链路**

用一个小规模测试任务验证 Worker 能发起工具调用并收到正常响应；检查容器日志不再出现 `unknown variant custom`，且没有新增同类 `protocol` 事件。

- [ ] **Step 6: 回滚条件**

若健康检测失败、Worker 工具调用失败或容器错误率上升，恢复上一镜像和 LLM-1 原协议配置；FOFA 状态字段保持向后兼容，历史事件不删除。
