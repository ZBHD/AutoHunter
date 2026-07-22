# LiteLLM 任务模式设计

> 状态：已确认设计，待实现
>
> 日期：2026-07-22

## 背景

AutoHunter 当前以 `src_type` 区分 EduSRC 与企业 SRC，共用任务、资产搜集、目标队列、Worker、Reviewer、原始证据和看板。现有搜集器已经具备多搜索引擎、FOFA 查询演化、探活、目标评分、站点画像、泄露凭据扩展点和持续补充队列，但这些逻辑面向通用网站：根页面、业务入口和普通 Web 攻击面是主要判断依据。

LiteLLM Proxy 的有效资产可能只有 JSON API、公开健康检查或受保护的模型接口。普通网站价值过滤会把根路径 `404`、无 HTML 表单或无前端页面的网关错误降权甚至跳过。LiteLLM 模式需要复用现有 24x7 编排主干，同时使用确定性的产品指纹、鉴权差异和模型调用验证替换通用站点判断。

## 已确认决策

- 新任务类型为 `src_type=litemllm`。
- 同时支持定向发现和全网产品指纹发现，创建任务时选择。
- 任务按现有 24x7 方式持续巡检，不在查询耗尽后自动结束。
- 验证级别固定为完整验证：模型枚举后执行一次最小推理；发现的候选 Key 也执行有效性验证。
- Secret 原值以明文保存并在完整权限和只读权限界面直接返回；观摩权限不接触相关接口。
- 首版只内置 LiteLLM Profile；架构允许后续增加 OneAPI、NewAPI 等网关 Profile。
- 采用“现有流水线 + 专项策略包”，不建立第二套任务调度系统。

## 目标

1. 持续发现和确认 LiteLLM Proxy 实例。
2. 发现 LiteLLM、上游 Provider、数据库及部署环境中的 Secret 暴露。
3. 确认模型列表、管理接口和模型推理是否缺少鉴权。
4. 验证候选 Key 的类别、有效性、权限和可用模型。
5. 保存请求、响应、鉴权对照、Secret 来源和验证结果，形成可复核 Finding。
6. 独立跟踪资产、Secret 和暴露状态的首次出现、最后出现、失效和重新出现。
7. 将确定性逻辑做成 Profile 和 Validator，避免依赖 LLM 临场猜测接口和响应。

## 非目标

- 首版不扫描任意 OpenAI 兼容网关；只有 LiteLLM Profile 参与识别。
- 不创建、更新、删除远端 Key、用户、Team、模型、路由或配置。
- 不调用远端写管理接口。
- 不把公开健康检查本身作为漏洞。
- 不把单一 `200`、统一错误页、SPA fallback 或 WAF 页面作为有效调用证据。
- 不重构 EduSRC 和企业 SRC 的既有采集与 Worker 策略。

## 总体架构

```text
Task / Orchestrator
        |
        +-- edusrc / enterprise -> 现有 Collector -> Worker -> Reviewer
        |
        +-- litemllm
              |
              +-- Gateway Query Planner
              +-- Gateway Fingerprinter
              +-- Exposure Scanner
              +-- Secret Extractor
              +-- Credential Validator Registry
              +-- Inference Validator
              +-- Gateway Classifier
              +-- LiteLLM Reviewer
```

新增 `app/gateway_hunt/`，建议结构如下：

```text
app/gateway_hunt/
  __init__.py
  schemas.py
  registry.py
  query_planner.py
  fingerprinter.py
  exposure_scanner.py
  secret_extractor.py
  auth_diff.py
  inference_validator.py
  credential_validators/
    base.py
    litellm.py
    openai.py
    anthropic.py
    azure_openai.py
    gemini.py
    bedrock.py
  profiles/
    base.py
    litellm.py
  classifier.py
  service.py
```

`service.py` 是 Orchestrator 的唯一入口。Orchestrator 不感知具体路由和 Provider，只调用“扫描一个 GatewayAsset”并接收结构化结果。

## Profile 契约

`GatewayProfile` 定义网关产品差异，至少提供：

```text
profile_id
display_name
search_signatures()
fingerprint_probes()
public_routes()
model_routes()
inference_routes()
management_routes()
secret_patterns()
match_fingerprint(observations)
parse_models(response)
classify_response(probe, response)
```

Profile 中的 Probe 使用结构化定义，不接受任意 shell 字符串：

```text
probe_id
method
path
headers_template
body_template
expected_content_types
success_matcher
public_by_design
request_cost
```

首版 `LiteLLMProfile` 根据官方当前路由登记以下只读或推理接口：

| 类别 | 路由 | 用途 |
|---|---|---|
| 产品指纹 | `/health/liveliness`、`/health/liveness`、`/health/readiness` | 公开基线与产品识别，不单独形成漏洞 |
| 模型列表 | `/v1/models`、`/models` | 鉴权差异与可用模型枚举 |
| 模型详情 | `/model/info`、`/v1/model/info` | 检查部署、Provider 和模型信息暴露 |
| 推理 | `/v1/chat/completions`、`/chat/completions` | 最小推理验证 |
| 管理面 | `/key/info`、`/key/list`、`/routes`、`/config/list`、`/get/config/callbacks` | 只读管理面与敏感配置检查 |

LiteLLM 官方健康存活和就绪接口公开是预期行为。模型、推理、Key 和配置路由使用 `user_api_key_auth`；实例未设置 Master Key、JWT、OAuth 等认证时，该依赖可能放行。因此判断必须来自受保护业务路由的鉴权差异，不能来自健康接口可访问。

## 创建与编辑任务

### 创建页

任务模式增加：

```text
LiteLLM（AI 网关泄露与未鉴权调用）
```

选择后隐藏通用漏洞类型选择器和 SRC 规则描述，显示 LiteLLM 专项区域：

1. `发现范围` 使用分段控件：`定向发现` / `全网发现`。
2. 定向发现显示 `范围锚点` 多行输入，每行一个域名、组织、品牌、证书主体或搜索条件。
3. `资产来源` 支持自动搜索、手动清单、两者；全网发现要求包含自动搜索。
4. `检测项` 使用复选框，默认全选且首版均为必备能力：Key 泄露、环境配置泄露、管理面暴露、无 Key 模型枚举、无 Key 推理。
5. `运行方式` 固定显示持续巡检，不提供单次模式。
6. 高级区域保留搜索引擎、搜索凭据、AutoHunter 内部 LLM Provider 和 Worker 并发。
7. 高级区域增加复查周期和单轮验证上限，默认值由服务端配置提供。

LiteLLM 模式不向用户暴露自由编辑的产品指纹查询。高级区域只显示当前启用的查询族和最近游标；产品指纹来自版本化 Profile，范围锚点由 Query Planner 组合。

### 表单约束

- `scope_mode=targeted` 时，范围锚点或手动目标至少存在一个。
- `scope_mode=global` 时，`target_source` 必须为 `fofa` 或 `both`。
- 手动目标必须是绝对 HTTP(S) URL，不接受 URL 中的凭据和 fragment。
- 修改范围锚点或 Profile 版本后，清理受影响查询族的游标，但不删除已发现资产。
- 任务运行中允许修改复查周期和并发；范围和 Profile 变更需先暂停任务。

## 任务配置契约

`Task` 新增 `mode_config JSON NOT NULL DEFAULT '{}'`。LiteLLM 配置示例：

```json
{
  "scope_mode": "targeted",
  "scope_anchors": ["example.com", "Example Group"],
  "enabled_profiles": ["litellm"],
  "profile_versions": {"litellm": "1"},
  "checks": {
    "key_leak": true,
    "env_leak": true,
    "management_exposure": true,
    "anonymous_models": true,
    "anonymous_inference": true
  },
  "validation": {
    "level": "full",
    "max_tokens": 1,
    "max_provider_validations_per_cycle": 20,
    "max_requests_per_asset_epoch": 24
  },
  "recheck_intervals": {
    "confirmed_seconds": 21600,
    "protected_seconds": 86400,
    "unreachable_seconds": 3600
  },
  "collection_state": {}
}
```

`CreateTaskRequest`、`UpdateTaskRequest` 和 `TaskResponse` 增加对应 DTO。服务端拒绝未知字段、未知 Profile、负数周期和超出边界的请求预算。

LiteLLM 任务的 `vuln_types` 不沿用通用 Web 漏洞列表。服务端根据 `mode_config.checks` 生成固定专项类型，忽略客户端夹带的 SQL 注入、XSS 等通用类型。`normalize_src_type` 明确接受 `litemllm`；未知值仍按现有兼容规则处理，但不得把 `litemllm` 归一化成 `edusrc`。

观摩角色收到空 `mode_config`，不暴露范围锚点、验证预算和查询状态。

## 数据模型

### GatewayAsset

`gateway_assets` 是 `targets` 的一对一扩展，不替代 Target 状态机。

```text
id                       String(32) PK
task_id                  FK tasks.id, indexed
target_id                FK targets.id, unique
profile_id               String(40)
profile_version          String(20)
canonical_base_url       String(700)
origin_key               String(500)
mount_path               String(300)
fingerprint_status       rejected | probable | confirmed
fingerprint_confidence   Float
fingerprint_signals      JSON
detected_version         String(80)
auth_state               unknown | protected | anonymous | mixed
model_names              JSON
model_count              Integer
scan_state               discovered | fingerprinting | auth_baseline |
                         exposure_scanning | secret_extracting |
                         credential_validating | inference_validating |
                         reviewing | scheduled_recheck
scan_epoch               Integer
last_error_kind          String(40)
last_error               String(500)
consecutive_failures     Integer
last_scanned_at          DateTime nullable
next_scan_at             DateTime nullable, indexed
created_at / updated_at  DateTime
```

`origin_key` 由 `scheme + host + explicit_port + normalized_mount_path` 生成。同一任务内唯一。默认端口归一化，路径移除重复斜杠和尾斜杠，但保留反向代理挂载路径。

### GatewaySecret

```text
id                       String(32) PK
task_id                  FK tasks.id, indexed
gateway_asset_id         FK gateway_assets.id, indexed
finding_id               FK findings.id nullable
secret_type              master_key | virtual_key | provider_key |
                         database_dsn | redis_url | jwt_secret | other
provider                 litellm | openai | anthropic | azure_openai |
                         gemini | bedrock | unknown
secret_name              String(160)
secret_value             Text
secret_sha256            String(64)
source_url               String(700)
source_location          String(300)
source_context           Text
credential_group_id      String(64) nullable
validation_context       JSON
validation_status        pending | valid | invalid | expired |
                         quota_exhausted | permission_denied |
                         rate_limited | network_error | unknown
validated_models         JSON
validation_evidence_id   FK raw_evidence.id nullable
first_seen_at / last_seen_at / last_validated_at DateTime
created_at / updated_at  DateTime
```

唯一约束为 `(gateway_asset_id, secret_sha256)`。同一资产多处出现的同一 Secret 更新 `last_seen_at`，每个来源仍由 Observation 保留。

`credential_group_id` 用于组合型凭据，例如 Bedrock 的 Access Key、Secret Key、Session Token 与 Region，或 Azure OpenAI 的 Key、Endpoint 与 Deployment。每个 Secret 仍独立去重，Validator 通过 group 和 `validation_context` 取得完整调用上下文。

`secret_value` 按已确认决策存储原值。Secret 不进入 TaskEvent 消息、错误日志、优先级原因或查询字符串，避免在非专项页面重复扩散。

### GatewayObservation

```text
id                       String(32) PK
task_id                  FK tasks.id, indexed
gateway_asset_id         FK gateway_assets.id, indexed
gateway_secret_id        FK gateway_secrets.id nullable
scan_epoch               Integer
stage                    fingerprint | auth_baseline | exposure |
                         secret | credential_validation | inference
probe_id                 String(120)
auth_variant             none | invalid | candidate
result                   matched | rejected | success | failed | inconclusive
status_code              Integer
content_type             String(120)
evidence_id              FK raw_evidence.id nullable
observed_at              DateTime, indexed
```

Observation 只保存索引字段和 Evidence 引用；完整请求、响应继续进入现有 `raw_evidence`，不重复存储大文本。

唯一约束为 `(gateway_asset_id, scan_epoch, probe_id, auth_variant)`，用于保证服务重启后同一轮已完成 Probe 不会再次发送。`gateway_assets` 另有 `(task_id, origin_key)` 唯一约束。

### 迁移

- `_MIGRATIONS` 为旧 `tasks` 增加 `mode_config`。
- 新表由 SQLAlchemy metadata 创建。
- `_SECONDARY_INDEXES` 增加任务、复查时间、Secret 状态和 Observation 时间索引。
- 迁移可重复执行；旧任务的 `mode_config={}`，行为不变。
- 删除 LiteLLM 任务时通过关系级联删除三张扩展表，RawEvidence 沿用现有任务清理规则。

## 查询规划与游标

每个 Profile 返回版本化 `SearchSignature`：

```text
signature_id
signal_kind
engine_clauses
strength
enabled_by_default
```

Query Planner 的输出键为：

```text
engine:profile_id:profile_version:signature_id:scope_hash
```

`collection_state` 按该键保存 `cursor`、`last_run_at`、`next_run_at`、`empty_streak`、`failure_count` 和 `backoff_until`。一个查询族耗尽、限流或出错不阻断其他查询族。

定向发现使用结构化括号组合：

```text
(product_signature) AND (domain/org/cert/brand anchors)
```

全网发现只轮换高强度产品指纹。LLM 可以把组织名称补充为别名和证书主体，但不能修改 Profile 的产品核心指纹。

## 候选归一化与指纹

搜索结果先转换为 `GatewayCandidate`：

```text
source_engine
source_query_id
discovered_url
host
ip
port
title
server
certificate
organization
body_snippet
```

挂载路径候选只来自搜索结果 URL、同源重定向、OpenAPI server URL 和已命中的静态资源路径，不做无限路径字典遍历。

指纹按低成本到高成本执行：

1. 搜索结果被动特征。
2. 根路径、文档页和静态资源特征。
3. 公开健康接口响应。
4. LiteLLM 特有响应字段、错误结构和跨端点组合。

状态定义：

- `confirmed`：一个产品独有强信号，或两个独立来源的中强信号。
- `probable`：只有一个非独有信号，等待下一轮补证，不进入推理验证。
- `rejected`：响应结构明确属于其他产品，或所有产品信号均不匹配。

根路径 `404` 不触发拒绝。只有指纹探测完成后才能拒绝候选。

## 鉴权差异

对 Profile 标记为受保护的只读或推理路由执行三种请求：

```text
A: 不带 Authorization
B: Authorization: Bearer <本轮随机无效值>
C: Authorization: Bearer <候选 Secret>
```

比较维度包括状态码、Content-Type、结构化错误码、响应 JSON schema、正文相似度和模型数据是否存在。

判定矩阵：

| A | B | C | 结论 |
|---|---|---|---|
| 拒绝 | 拒绝 | 未执行 | 鉴权存在 |
| 成功 | 拒绝 | 未执行 | 可能存在匿名策略，二次确认 |
| 成功 | 成功 | 未执行 | 若返回有效业务结构，则匿名访问 |
| 拒绝 | 拒绝 | 成功 | 候选 Key 有效 |
| 相同 HTML/404/WAF | 相同 | 任意 | 无结论 |

`public_by_design=true` 的健康接口不进入匿名暴露分类。

## 暴露面与 Secret 提取

暴露面扫描只发起 GET、HEAD 和最小推理 POST。检查范围：

- LiteLLM 模型、路由、Key 信息和配置只读接口。
- `/.env`、`/.git/config`、常见部署配置与备份文件。
- 首页、管理 UI、JavaScript、Source Map、runtime config 和错误响应。
- 已暴露配置中引用的同源配置入口。

Secret Extractor 先使用确定性规则解析变量名、JSON/YAML 键、Authorization 和 Provider 格式，再使用上下文判断类型。Secret 必须来自真实响应 Evidence，不能由 LLM 文本生成。

支持的首版类型：LiteLLM Master Key、LiteLLM Virtual Key、OpenAI、Anthropic、Azure OpenAI、Gemini、Bedrock、数据库 DSN、Redis URL、JWT Secret 和未知 Bearer Token。

## 完整有效性验证

### 无 Key 分支

1. 对模型列表执行 A/B 鉴权差异。
2. 由 Profile 解析合法模型列表。
3. 选择一个支持文本生成的模型；不从错误文本猜模型名。
4. 向推理接口发送固定测试内容、唯一 nonce、`stream=false`、`max_tokens=1`。
5. 由 LiteLLM 响应解析器确认 `id`、`model`、`choices` 或对应错误结构。
6. 只有得到合法模型输出才确认 `litellm_unauthenticated_inference`。

### Secret 分支

1. 根据格式、变量名和来源上下文选择 Credential Validator。
2. LiteLLM Master/Virtual Key 优先在原网关验证。
3. Provider Key 在相应 Provider 的标准只读模型接口验证，再执行一次最小推理。
4. 未知 Token 只在发现它的原始服务验证，不跨 Provider 穷举。
5. 保存 `valid`、`invalid`、`expired`、`quota_exhausted`、`permission_denied`、`rate_limited`、`network_error` 或 `unknown`。

限流、超时、上游 5xx 和连接失败不判 Secret 无效，按错误类别设置复查时间。每个 Secret 在一个 scan epoch 内最多完成一次模型枚举和一次最小推理。

## 执行状态机

```text
discovered
  -> fingerprinting
  -> rejected | probable | confirmed
  -> auth_baseline
  -> exposure_scanning
  -> secret_extracting
  -> credential_validating
  -> inference_validating
  -> reviewing
  -> scheduled_recheck
```

每次进入新阶段先持久化 `scan_state` 和 `scan_epoch`。服务重启后从当前阶段恢复；同一个 epoch 已有 Observation 的 Probe 不重复执行。

并发分三层：

- 搜索引擎并发沿用 Collector 配置。
- 指纹与只读探测使用独立低成本信号量。
- Provider 和推理验证使用最小信号量，避免被普通 Worker 并发放大。

每资产每 epoch 默认最多 24 个网络请求；达到预算时保存 `partial` 观察并进入下次复查，不无限追加 Agent 轮次。

## Collector 与 Orchestrator 接入

LiteLLM 使用现有任务循环和 Target 队列，但不进入通用 Worker：

1. `collector.refill()` 在 `src_type=litemllm` 时委托 Gateway Query Planner 搜索。
2. 搜索候选或手动目标统一创建 `Target(status=queued)` 和 `GatewayAsset(scan_state=discovered)`。
3. LiteLLM 候选跳过通用 `prefilter.should_skip_ex`、`scorer.score_target`、`target_filter.evaluate_target`、EduSRC 归属判断和同款站点冷却；改用 Fingerprinter 的产品置信度排序。
4. Orchestrator 从 Target 队列取出目标后，按任务类型调用 `gateway_hunt.service.scan_asset()`，而不是 `Worker.run()`。
5. 专项扫描开始时 Target 进入 `assigned/scanning`；scan_state 保存更细阶段。
6. 本轮完成后 Target 进入 `done`，GatewayAsset 写入 `next_scan_at`。
7. 每轮 Orchestrator 开始前，把 `next_scan_at <= now` 且当前没有活跃扫描的 GatewayAsset 对应 Target 原子更新回 `queued`，`scan_epoch + 1`，再进入正常并发派发。
8. 重新入队使用条件更新，要求 Target 仍为 `done/dead/skipped` 且 `next_scan_at` 到期，防止多个调度循环重复派发。

LiteLLM 任务在暂时没有 queued Target 时仍保持 `running`。Orchestrator 计算所有查询族和 GatewayAsset 中最早的 `next_run_at/next_scan_at`，进入有上限的等待；任务只有被用户暂停或停止时才退出持续巡检。

确定性扫描器产生 `FindingCandidate` 后，继续复用现有 Finding 持久化、RawEvidence、Review 和人工复审流程。`reviewer_system_prompt` 增加 LiteLLM 分支；Reviewer 只审核已结构化证据，不负责决定下一条远端 Probe。

## Finding 分类与严重性

首版固定类型：

| 类型 | 确认条件 | 默认严重性 |
|---|---|---|
| `litellm_unauthenticated_inference` | 无 Key 完成合法模型推理 | 高危 |
| `litellm_unauthenticated_model_list` | 无 Key 返回合法模型列表，推理未确认 | 低危 |
| `litellm_management_api_exposure` | 无 Key 返回 Key、路由、租户或敏感管理数据 | 高危；含完整 Secret 时严重 |
| `litellm_master_key_leak` | Master Key 来源真实且验证有效 | 严重 |
| `litellm_virtual_key_leak` | Virtual Key 来源真实且验证有效 | 高危 |
| `provider_api_key_leak` | Provider Key 来源真实且验证有效 | 严重 |
| `litellm_env_exposure` | 环境配置可读取并含敏感变量 | 高危 |
| `litellm_database_dsn_exposure` | 完整数据库连接信息暴露 | 严重 |
| `litellm_sensitive_config_exposure` | 敏感配置可读取但无有效 Key/DSN | 中危 |

只有产品识别、公开健康检查、字段名、掩码值或无法验证的疑似 Secret 不创建正式 Finding，保留为 GatewayAsset、GatewaySecret 或 Observation 状态。

同一资产、同一漏洞类型和同一影响对象使用稳定 dedup key。复查确认修复时更新 Gateway 状态并写事件，不删除历史 Finding。

## Reviewer

Reviewer 前先执行确定性证据门槛：

- LiteLLM 指纹是否确认。
- 接口是否为公开健康接口。
- A/B/C 鉴权对照是否完整。
- Secret 是否来自真实 Evidence。
- Key 是否由对应 Validator 验证。
- 推理是否返回合法模型结构。
- 原始请求与响应是否来自同一次 capture。

门槛不足但存在明确补证动作时保持 `partial` 并安排复查；没有有效产品信号或只有统一错误页时拒绝。通过门槛后，LiteLLM Reviewer 只负责影响描述、严重性微调和报告组织，不重新发明验证结论。

## API

现有任务接口扩展 `mode_config`。新增路由放入 `app/api/gateway_hunt.py`：

```text
GET  /api/tasks/{task_id}/gateway/summary
GET  /api/tasks/{task_id}/gateway/assets
GET  /api/tasks/{task_id}/gateway/secrets
GET  /api/tasks/{task_id}/gateway/secrets/export?format=json|csv
GET  /api/gateway/assets/{asset_id}
GET  /api/gateway/assets/{asset_id}/observations
POST /api/gateway/assets/{asset_id}/recheck
POST /api/gateway/secrets/{secret_id}/revalidate
```

列表接口支持 `offset`、`limit`、文本搜索和状态过滤，返回 `total` 与 `has_more`。详情接口包含 Evidence 引用，不在列表中传输完整原始响应。

完整权限可以读取和写入；只读权限可以读取包括 Secret 原值在内的数据；观摩权限不允许访问任何 `/api/*/gateway/*` 和 `/api/gateway/*` 路由。导出不进入浏览器缓存，由响应头设置 `Cache-Control: no-store`。

## 看板

LiteLLM 任务在现有 BoardView 增加三个专用标签，普通任务不显示：

### 网关资产

显示 URL、Profile、指纹置信度、鉴权状态、模型数、扫描阶段、最后验证和下次复查。点击资产打开详情，按时间线展示指纹、A/B/C 对照、管理面和推理 Observation。

### Secret

显示类型、Provider、变量名、原值、来源、验证状态、可用模型、首次/最后发现及最后验证。支持状态筛选、文本检索、复制、重新验证和 JSON/CSV 导出。

### 暴露结果

复用现有 Findings/Review/ReportDrawer，仅增加 LiteLLM 类型标签和专项证据段：产品指纹、鉴权对照、Secret 验证、模型调用与持续复查状态。

创建页和任务编辑弹窗共用 `frontend/src/litellmTaskMode.js` 中的默认值、显示条件和 payload 构造，避免两套表单漂移。

## 事件与可观测性

新增低频事件类型：

```text
gateway_query_started / gateway_query_exhausted
gateway_candidate_found
gateway_fingerprint_confirmed / gateway_fingerprint_rejected
gateway_anonymous_models_confirmed
gateway_anonymous_inference_confirmed
gateway_secret_found / gateway_secret_validated
gateway_recheck_scheduled
gateway_probe_deferred
```

事件只记录资产 ID、类型、状态和计数，不记录 Secret 原值、Authorization、完整查询响应或 DSN。相同资产、相同事件签名在一个 scan epoch 内只写一次。

任务看板 summary 增加：确认网关数、匿名推理数、Secret 总数、有效 Secret 数、待验证数和本轮探测阶段。

## 错误处理与复查

错误分为：

- `search_auth`、`search_quota`、`search_rate_limit`：复用现有搜索引擎退避。
- `target_network`、`target_tls`、`target_timeout`：短周期重试，连续失败后指数退避。
- `target_rate_limit`：读取 Retry-After，暂停该资产验证。
- `provider_rate_limit`：只暂停该 Secret Validator，不阻断资产其他检查。
- `provider_quota`、`provider_permission`：保存为有效性细分结果。
- `parse_mismatch`：保存 Observation 为 inconclusive，不生成 Finding。
- `budget_exhausted`：保存检查点并安排下一轮。

默认复查：已确认暴露 6 小时、鉴权正常 24 小时、临时不可达 1 小时；失败按 1、2、4、8、24 小时退避。成功复查清零失败计数。

## 测试设计

### 单元测试

- Profile Registry：注册、重复 ID、未知 Profile、版本变化。
- Query Planner：定向括号组合、全网查询族、scope hash、独立游标和范围外过滤。
- 归一化：默认端口、非标准端口、挂载路径、重定向和 origin 去重。
- Fingerprinter：官方健康响应、Swagger 标题、组合信号、OpenAI 兼容误报、SPA/WAF/404。
- Auth Diff：A/B/C 判定矩阵、公开路由排除、相同错误页和 JSON schema 差异。
- Secret Extractor：各 Provider 格式、变量上下文、重复 Secret、掩码值排除和明文持久化。
- Credential Validator：有效、无效、过期、额度、权限、限流、网络错误和解析失败。
- Inference Validator：合法模型输出、模型列表但推理失败、伪 200、流式响应关闭和 nonce 对照。
- Classifier：Finding 类型、默认严重性、稳定 dedup key 和 partial 门槛。

### 数据与 API 测试

- 老库增加 `mode_config`，新表和索引创建，迁移重复执行无副作用。
- 删除任务级联清理扩展表。
- Asset、Secret、Observation 分页、过滤、详情和 Evidence 引用。
- Secret 同资产哈希去重、last_seen 更新和验证状态迁移。
- full/readonly 可读取，observer 被路由层拒绝。
- 重新验证和复查接口仅 full 可调用。
- Task DTO 拒绝非法范围、未知 Profile 和超限预算。

### 集成测试

使用本地 FastAPI Fixture 模拟：

1. 正常鉴权 LiteLLM。
2. 未配置 Master Key、模型列表和推理均匿名。
3. 只有公开健康检查，其余鉴权正常。
4. `.env` 暴露且含有效/无效 Provider Key。
5. 管理接口返回掩码值。
6. 所有路径返回相同 SPA HTML。
7. Provider 限流、额度不足和临时 5xx。
8. 服务重启后从 scan_state 和 Observation 恢复。

### 前端测试

- 任务模式切换后字段显示、默认值和 payload。
- 定向/全网约束和任务编辑游标重置提示。
- LiteLLM 专用标签只在对应任务显示。
- Asset、Secret 列表分页、筛选、复制、导出和重新验证。
- 长 Secret、长 URL、移动端布局和空/加载/错误状态。
- observer 看不到专用标签，也不发起敏感 API 请求。

## 验收标准

1. 新建定向和全网 LiteLLM 任务均可启动并持续运行。
2. 普通任务行为和测试保持不变。
3. 公开健康接口可识别产品，但不会单独产生漏洞。
4. 本地未鉴权 Fixture 能确认模型枚举和一次 `max_tokens=1` 推理。
5. 正常鉴权 Fixture 不产生匿名调用误报。
6. 暴露 Secret 能保存原值、来源、哈希和验证状态，并可持续复查。
7. WAF、SPA 全 200、普通 OpenAI 兼容接口不会被误认成 LiteLLM。
8. 搜索限流、目标超时和 Provider 限流均按各自粒度退避，不暂停整条任务。
9. 服务重启不会重复执行同一 epoch 已完成的 Probe。
10. full/readonly 能查看完整结果，observer 不接触 Gateway 和 Secret 接口。
11. Python 全量测试、前端单元测试和前端构建通过。

## 部署与回滚

1. 部署前备份 SQLite 数据库或数据卷。
2. 启动时先执行可重入迁移，再启动 Orchestrator。
3. 首次上线默认没有 LiteLLM 任务，旧任务不受影响。
4. 使用本地 Fixture 完成创建、扫描、验证、复查和重启恢复冒烟测试。
5. 若回滚到旧版本，旧代码忽略新增表和 `mode_config`；新表保留，避免丢失结果。
6. 再次升级时通过唯一约束和 scan epoch 继续恢复，不重复创建 Secret 与 Finding。

## 实现边界

主要修改范围：

- 后端：`app/gateway_hunt/`、`app/db/models.py`、`app/db/session.py`、`app/api/dto.py`、`app/api/tasks.py`、`app/api/gateway_hunt.py`、`app/orchestrator.py`、`app/agents/prompts.py`、`app/main.py`。
- 前端：`frontend/src/views/CreateView.vue`、`frontend/src/components/TaskEditModal.vue`、`frontend/src/views/BoardView.vue`、`frontend/src/api.js`，以及新增 LiteLLM 配置与专用面板组件。
- 测试：Profile/验证器单测、数据库与 API 测试、编排恢复集成测试、前端任务表单和面板测试。

实现期间不顺带重构通用 Collector、Worker 或 BoardView 的其他业务逻辑；只提取创建页与编辑弹窗共同需要的 LiteLLM 表单辅助函数。
