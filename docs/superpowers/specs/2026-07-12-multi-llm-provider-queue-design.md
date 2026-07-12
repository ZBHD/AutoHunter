# AutoHunter 多 LLM Provider 队列设计

> 2026-07-12 | status: draft

## 目标

将 AutoHunter 从单 LLM 端点改造为**多 provider 加权池 + 故障自动切换 + 三协议支持**，解决单点故障导致整个平台停摆的问题。

## 核心行为

```
请求到达
  → 从 enabled provider 池按 weight 加权随机选起点
  → 成功 → 返回结果
  → 失败 →
      auth / quota 错误 → 该 provider 自动 disabled=true（落 DB），从剩余池重选
      其他错误（timeout/network/upstream/rate_limit）→ 从剩余池重选
      所有 provider 耗尽 → 报错 "所有 LLM provider 暂不可用"
```

**无冷却、无降权、无状态缓存。** 一次请求内不重试同一 provider，weight 仅影响选起点概率。

---

## §1 存储方案

`system_settings` 表新增 JSON column `llm_providers`：

```json
[
  {
    "name": "DeepSeek V3",
    "base_url": "https://api.deepseek.com/v1",
    "api_key": "sk-xxx",
    "model": "deepseek-chat",
    "temperature": 0.3,
    "weight": 5,
    "protocol": "openai_chat",
    "enabled": true
  },
  {
    "name": "Claude Opus",
    "base_url": "https://api.anthropic.com",
    "api_key": "sk-ant-xxx",
    "model": "claude-opus-4-8-20251001",
    "temperature": 0.3,
    "weight": 3,
    "protocol": "anthropic_messages",
    "enabled": true
  }
]
```

DB 迁移：

```sql
ALTER TABLE system_settings ADD COLUMN llm_providers JSON;
```

首次启动列为空 → 初始化为 `[]`。用户通过 UI 手动添加第一个 provider。

`.env` 中原有的 `LLM_API_KEY` / `LLM_BASE_URL` / `LLM_MODEL` / `LLM_TEMPERATURE` / `LLM_PROTOCOL` 全部移除，不再读取。

---

## §2 LLM Router（`app/llm/router.py`）

### 选 provider 算法

加权随机：`weight=5` 的 provider 被选中的概率是 `5 / sum(all_weights)`。

### 构造函数

```python
class LLMRouter:
    def __init__(self, providers: list[LLMProviderConfig], usage_key: str | None = None):
        # 为每个 provider 创建一个 LLMClient 实例
        self._clients: list[tuple[LLMProviderConfig, LLMClient]] = ...
        self._usage_key = usage_key

    def chat(self, messages, tools=None, tool_choice="auto",
             temperature=None, max_tokens=None) -> LLMResponse:
        """对 Agent 透明的入口，内部接管 provider 选择与故障转移"""
```

### 故障处理

```
auth / quota → provider.enabled = False（落 DB） → 从剩余重选
其他错误     → 跳过当前 provider → 从剩余重选
```

每次 `chat()` 调用维护 `tried_providers: set[int]`，确保不重试同一 provider。

### 与 Agent 的关系

Agent 持有 `LLMRouter` 替代 `LLMClient`，调用 `router.chat(messages, tools)`。签名与 `LLMClient.chat()` 一致，Agent 代码改动最小化。

---

## §3 协议适配层（`app/llm/protocols.py`）

将当前 `LLMClient` 中混杂的协议逻辑抽成策略模式。

### 接口

```python
class ProtocolAdapter(ABC):
    @property
    @abstractmethod
    def protocol_name(self) -> str: ...

    @abstractmethod
    def build_request(self, base_url, api_key, model, messages,
                      tools, tool_choice, temperature, max_tokens) -> RequestPayload: ...

    @abstractmethod
    def parse_response(self, raw: dict) -> LLMResponse: ...

    @abstractmethod
    def extract_usage(self, raw: dict) -> UsageInfo: ...
```

### 三个实现

| Adapter | 端点 | 输入字段 | 输出字段 | tool 机制 |
|---------|------|---------|---------|----------|
| `OpenAIChatAdapter` | `/v1/chat/completions` | `messages` | `choices[0].message` | `tool_calls` on message |
| `AnthropicMessagesAdapter` | `/v1/messages` | `messages` | `content[]` blocks | `tool_use` blocks |
| `OpenAIResponsesAdapter` | `/v1/responses` | `input` | `output_text` + `output[]` | `function_call` items |

### 统一响应

```python
@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall] | None

@dataclass
class ToolCall:
    id: str
    name: str
    arguments: str  # JSON string
```

三种协议解析后产出相同的 `LLMResponse`，调用方不感知协议差异。

### Responses API 适配要点

- 工具结果回传使用 `role="function_call_output"` 的 input item
- usage 字段：`input_tokens` / `output_tokens`（不是 `prompt_tokens` / `completion_tokens`）
- 多轮状态：不使用服务端 `previous_response_id`，继续保持客户端管理历史（与其他协议一致）

---

## §3.5 重试策略分层

```
单 provider 内（LLMClient）：
  → 不做自动重试（现有 _MAX_RETRIES 改为 0）
  → 失败立即抛异常，由 Router 接管

跨 provider（LLMRouter）：
  → 捕获异常 → 分类 → 禁用/跳过 → 下一个 provider
  → 不冷却、不降权
```

理由：Router 已经提供跨 provider 故障转移，单 provider 内再指数退避重试只会拖慢 failover 速度。请求级超时（现有 `_REQUEST_TIMEOUT=120s`）保留不变。

---

## §4 LLMClient 重构

剥离协议逻辑后，`LLMClient` 职责收窄为：

- HTTP 客户端管理（TLS 降级、超时）
- 错误分类（`_classify_error` 保持不变）
- 将请求委托给 `ProtocolAdapter`
- 不做自动重试（重试由 Router 层通过切换 provider 完成）

构造函数改为接收 `LLMProviderConfig` + `ProtocolAdapter`：

```python
class LLMClient:
    def __init__(self, config: LLMProviderConfig):
        self.config = config
        self.adapter = ADAPTER_REGISTRY[config.protocol]()
        self._insecure_tls = False
        ...

    def chat(self, messages, tools=None, ...) -> LLMResponse:
        # 构建请求 → 发 HTTP → 解析响应 → 提取 usage
        # 不再包含协议分支 if/else
```

移除现有的 `_messages_protocol` / `_messages_chat` / `_convert_messages` 等协议相关方法。

---

## §5 配置与 API

### 新增 API 端点

```
GET    /api/settings/llm-providers               → 列表（密钥脱敏）
POST   /api/settings/llm-providers               → 新增
PUT    /api/settings/llm-providers/{name}         → 修改（含启用/禁用）
DELETE /api/settings/llm-providers/{name}         → 删除
POST   /api/settings/llm-providers/{name}/test    → 连通测试
```

### 连通测试

发送 `say "health check"` 请求到指定 provider，返回：

```json
{
  "ok": true,
  "latency_ms": 342,
  "model": "deepseek-chat",
  "error": ""
}
```

### 密钥安全

- API 返回列表时 `api_key` 脱敏为 `••••••••`
- 前端提交时若 `api_key` 值为脱敏占位符 → 后端不更新该字段，保留原值
- 复用现有 `mask_secret()` / `is_masked_secret()` 逻辑

### collector 降级

collector 评分用的 LLM 调用是可选功能（无 provider 时跳过评分，不影响搜集流程）。保留 `llm_router_for_task_optional()` 函数：无 provider 时返回 None，collector 降级跳过评分。

### 任务级覆盖

现有 `Task.model_config_json` 保持不变。任务级设了 `base_url` + `api_key` → LLMRouter 只用该单 provider，不读全局池。语义：任务覆盖即指定，不合并。

---

## §6 DB 迁移

```sql
ALTER TABLE system_settings ADD COLUMN llm_providers JSON;
```

`SystemSettings` 模型新增：

```python
llm_providers = Column(JSON, nullable=True, default=list)
```

---

## §7 前端面板

设置页面新增 Tab：「LLM 提供商」。

### 列表视图

拖拽排序表格，列：名称、模型、协议、权重、状态（启用/禁用）、操作（编辑/测试/删除）。

顶部显示当前权重分布：`DeepSeek(50%)  Qwen(30%)  Claude(20%)`。

### 表单

| 字段 | 控件 |
|------|------|
| 名称 | text input |
| base_url | text input + 快捷选项下拉（DeepSeek/Qwen/OpenAI/Claude/自定义） |
| API Key | password input，回显脱敏 |
| 模型 | text input + 「拉取模型列表」按钮（调 /v1/models） |
| 协议 | select: OpenAI Chat / Anthropic Messages / OpenAI Responses |
| Temperature | slider 0~2, 步长 0.1 |
| 权重 | number input 1~100 |

### 行内操作

- **测试按钮**：调用连通测试 API，显示延迟 + 状态
- **启用/禁用开关**：手动控制；auth/quota 错误自动禁用后，用户检查 key 后可重新启用

---

## §8 文件改动清单

| 文件 | 操作 | 内容 |
|------|------|------|
| `app/llm/protocols.py` | **新增** | 3 个 ProtocolAdapter 实现 + LLMResponse/ToolCall 数据类 |
| `app/llm/router.py` | **新增** | LLMRouter：provider 管理、加权随机、链式 failover |
| `app/llm/client.py` | **重构** | 剥离协议逻辑，委托给 ProtocolAdapter |
| `app/llm/__init__.py` | **修改** | 导出更新 |
| `app/config.py` | **修改** | `LLMConfig` 替换为 `LLMProviderConfig` |
| `app/settings_service.py` | **修改** | `resolve_llm_providers()`、provider CRUD、连通测试 |
| `app/api/settings.py` | **修改** | 新增 6 个 provider 相关端点 |
| `app/db/models.py` | **修改** | `system_settings.llm_providers` column |
| `app/orchestrator.py` | **修改** | `_llm_for_task()` → `llm_router_for_task()` |
| `app/agents/worker.py` | **修改** | `self.llm` → `self.router` |
| `app/agents/reviewer.py` | **修改** | 同上 |
| `app/agents/killsweep.py` | **修改** | 同上 |
| `app/agents/escalate.py` | **修改** | 同上 |
| `app/agents/collector.py` | **修改** | 同上 |
| `app/api/findings.py` | **修改** | 报告助手 LLM 客户端改用 router |
| `frontend/` | **修改** | 新增 LLM Providers 管理面板 |
| `.env.example` | **修改** | 移除旧的单 LLM 配置项 |

---

## §9 架构总览

```
┌───────────────────────────────────────────────────────────────┐
│  Frontend                                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  设置 → LLM Providers Tab                               │  │
│  │  增删改 / 拖拽排序 / 设权重 / 测试连通 / 启用禁用      │  │
│  └──────────────────────┬──────────────────────────────────┘  │
└─────────────────────────┼─────────────────────────────────────┘
                          │ REST API
┌─────────────────────────┼─────────────────────────────────────┐
│  Backend                ▼                                     │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  settings_service.py                                    │  │
│  │  resolve_llm_providers(task) → list[LLMProviderConfig]   │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  LLMRouter (app/llm/router.py)                          │  │
│  │  ┌───────────────────────────────────────────────────┐  │  │
│  │  │ providers[]                                       │  │  │
│  │  │  ├─ (config, LLMClient + OpenAIChatAdapter)       │  │  │
│  │  │  ├─ (config, LLMClient + AnthropicMessagesAdapter)│  │  │
│  │  │  └─ (config, LLMClient + OpenAIResponsesAdapter)  │  │  │
│  │  │                                                   │  │  │
│  │  │  select() → 加权随机                               │  │  │
│  │  │  chat()  → 失败→切下一个，auth/quota→自动禁用       │  │  │
│  │  └───────────────────────────────────────────────────┘  │  │
│  └──────────────────────┬──────────────────────────────────┘  │
│                         ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  Agent 层 (worker / reviewer / killsweep / escalate)    │  │
│  │  router.chat(messages, tools) → LLMResponse             │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```
