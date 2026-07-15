# FOFA 多 Key 运行时轮换设计

日期：2026-07-16
状态：设计已确认，等待文档复核

## 1. 目标与边界

FOFA 全局配置支持多个 API Key，并提供与 LLM Provider 池一致的管理体验：增删改、启停、排序、单项检测和一键检测。运行时采用粘性顺序轮换：当前 Key 持续服务，只有出现可轮换的失败时才切到下一个可用 Key。

任务级 `fofa_config.key` 保持单 Key 显式覆盖。任务使用任务级 Key 时，调用路径绕过全局池；任务未设置覆盖值时，使用全局 FOFA Key 池。现有旧版 `fofa.key`、`FOFA_KEY` 和相关更新接口继续保留兼容行为。

本次范围聚焦 FOFA Key 的配置、检测、运行时选择与错误恢复。其他搜索引擎继续使用当前配置路径。

## 2. 方案决策

采用独立 FOFA Key 池方案，在 `SystemSettings` 增加 `fofa_keys` JSON 列，结构和 LLM 的 `llm_providers` 对齐。FOFA 端点、分页、默认意图模式继续放在现有 `fofa` 配置中。

不采用把 Key 数组混入现有 `fofa` JSON 的方案，避免凭据池、分页参数和运行状态混在一个配置对象内。不扩展为所有搜索引擎的通用凭据池，保持本次改动聚焦。

## 3. 配置与运行状态

### 3.1 持久化结构

`SystemSettings.fofa_keys` 保存按展示顺序排列的对象数组：

```json
[
  {
    "name": "主账号",
    "key": "FOFA_KEY_VALUE",
    "enabled": true,
    "runtime_state": "ready",
    "failure_kind": "",
    "failure_count": 0,
    "cooldown_until": null
  }
]
```

字段约定：

- `name`：大小写不敏感唯一名称，作为 API 路径和轮换日志标识。
- `key`：服务端保存明文，API 和前端只返回统一脱敏占位。
- `enabled`：用户手动开关，表示该 Key 是否加入候选集合。
- `runtime_state`：运行状态，取值为 `ready`、`rate_limited`、`daily_cooldown`、`daily_suspended`、`auth_invalid`。
- `failure_kind`：最近一次结构化失败类型，取值为 `auth`、`rate_limit`、`daily_limit`、`transient` 或空字符串。
- `failure_count`：当前失败类型的连续次数，成功后清零。
- `cooldown_until`：UTC 时间戳；认证失效使用 `null`，由 `runtime_state` 表示持久阻断。

`fofa` 配置增加非敏感的 `active_key_name`，用于记录粘性游标。按名称记录可抵抗 Key 列表排序变化。

### 3.2 状态语义

`enabled` 只表达用户意图。运行时认证失败写入 `runtime_state=auth_invalid`，保持 `enabled` 原值，因此一键检测成功时可以清除运行阻断，同时保留用户手动停用的 Key。

全局候选条件为 `enabled=true`，运行状态未进入 `auth_invalid` 或 `daily_suspended`，并且 `cooldown_until` 已到期。当前游标优先；游标失效时从列表首项开始顺序寻找候选。

## 4. Router 架构

新增 `app/fofa/router.py`，包含以下职责：

- `FofaKeyRouter`：维护共享游标、候选快照、失败状态和并发锁。
- `FofaFailureKind`：统一四类上游错误常量。
- `execute_async` 与 `execute_sync`：为异步 Collector 和同步 Worker/Killsweep 提供一致的重试与状态回写流程。
- `select_candidates`、`mark_success`、`mark_failure`：供测试和少量特殊调用直接使用。

`settings_service.fofa_router_for_task(task)` 根据任务解析结果返回 Router：

1. 任务包含 `fofa_config.key` 时返回单 Key 适配器，不共享全局状态；错误分类与冷却逻辑保持一致，状态写入该任务的 `fofa_config`。
2. 任务使用全局池时，按池配置指纹缓存进程级 Router，跨任务共享粘性游标。
3. 配置 CRUD 或刷新缓存后，旧指纹 Router 失效并按 `active_key_name` 重建。

Collector、Worker 的 `fofa_lookup`、Killsweep 的 FOFA 搜索均通过 Router 发送请求。调用方保留原有业务结果格式，Router 只负责 Key 选择、重试和状态。

## 5. 单次请求流程

1. Router 在锁内读取当前 Key 和候选快照，随后释放锁执行网络请求。
2. 请求成功：推进业务分页游标，清除该 Key 的失败状态，并把该 Key 记录为 `active_key_name`。
3. 请求失败：用 `FofaError.kind/code/retry_after` 分类，更新当前 Key 状态，按列表顺序选择下一个候选。
4. 同一个业务请求中，每个 Key 最多尝试一次，候选数量达到上限后结束本轮。
5. 某个备用 Key 成功时，调用方只接收一次成功结果，业务分页只推进一次。
6. 全部 Key 处于冷却状态时，返回包含最早 `cooldown_until` 的池耗尽结果，任务进入等待；冷却期间静默跳过。
7. 全部候选均为认证失效或 `daily_suspended` 时，任务暂停并记录汇总原因，等待设置更新、检测恢复或任务重启。

运行时状态写回使用 Key 名称和配置指纹做条件校验。检测或编辑期间发生配置变化时，旧请求结果标记 `stale`，当前配置保持原样。

## 6. 错误分类与恢复

`FofaEngine.search` 保持 `FofaError` 兼容，同时补充结构化 `kind`、`code` 和 `retry_after`。上游错误只分为 `auth`、`rate_limit`、`daily_limit`、`transient` 四类，Router 再把错误映射为运行状态：

- `auth`：认证、权限、过期、账号无效等；映射为 `auth_invalid`，持久阻断当前 Key 并立即尝试下一个。
- `rate_limit`：HTTP 429、Q3005、Too Many Requests 等；映射为 `rate_limited`，指数退避 60、120、240、480、600 秒，到期自动回池。
- `daily_limit`：FOFA `820041`、每日上限、每日额度等；先映射为 `daily_cooldown`，每次进入 1 小时冷却并在到期后自动回池。同一 Key 连续 12 次仍返回该错误时转为 `daily_suspended`，检测成功、替换 Key 或任务重启后恢复。
- `transient`：网络错误、5xx、非 JSON、端点瞬时异常；运行状态保持 `ready`，本轮结束，下轮继续使用当前游标。

每日额度匹配优先级高于通用 quota 和账号错误，避免把额度耗尽误判成认证失效。连续次数按 Key 分别统计；池中存在其他可用 Key 时任务继续执行。

日志、事件、API 错误和检测结果全部经过统一脱敏，错误文本不保留明文 Key 或 URL 编码后的 Key。

## 7. API 设计

新增与 LLM Provider 对齐的接口：

| 方法 | 路径 | 语义 |
| --- | --- | --- |
| GET | `/api/settings/fofa-keys` | 返回脱敏 Key 列表和运行状态 |
| POST | `/api/settings/fofa-keys` | 新增 Key |
| PUT | `/api/settings/fofa-keys/{name}` | 编辑名称以外的字段、启停或替换 Key |
| DELETE | `/api/settings/fofa-keys/{name}` | 删除 Key |
| PUT | `/api/settings/fofa-keys/order` | 提交完整顺序 |
| POST | `/api/settings/fofa-keys/{name}/test` | 检测单个 Key |

新增 DTO 校验：名称非空且可寻址、名称大小写不敏感唯一、启用项必须有 Key、Key 脱敏占位只能表示保留原值、顺序请求必须覆盖全部名称。

`GET /api/settings` 增加 `fofa_keys` 脱敏列表。`POST /api/settings/health-check` 增加 `fofa_results[]`，每项包含 `name`、`ok`、`latency_ms`、`enabled`、`runtime_state`、`auto_blocked`、`stale` 和脱敏后的 `error`。旧单 Key 场景继续返回兼容字段 `fofa_result`。

一键检测会并行检测所有已配置 Key，包括手动停用项；成功只清除运行阻断，保留 `enabled=false` 的手动状态。认证类失败写入 `runtime_state=auth_invalid`，每日额度和限流结果写入对应状态。替换 Key 时清空该项的失败次数、冷却和运行阻断；删除或停用当前 Key 时，游标顺序移动到下一个候选；重新排序按名称保留当前 Key。

## 8. 前端设计

新增 `FofaKeysPanel.vue`，直接复用 `LlmProvidersPanel.vue` 的列表行、上下移按钮、启停开关、测试按钮、编辑/删除图标按钮、编辑弹窗和错误提示样式。FOFA 面板增加：

- 当前使用标记和池可用数量。
- `ready`、`rate_limited`、`daily_cooldown`、`daily_suspended`、`auth_invalid`、手动停用徽标。
- 冷却剩余时间、最近检测延迟和自动阻断提示。
- 空池时的只读 Legacy Key 行。

现有 FOFA 端点、最大页数、page_size 和默认意图模式字段保留在同一设置区。页面顶部的一键检测沿用现有健康检查入口，LLM 和 FOFA 结果并列展示。

## 9. 兼容与迁移

数据库迁移为 `system_settings` 增加 `fofa_keys JSON DEFAULT '[]'`，旧行自动使用空数组。池为空时继续解析存储值 `fofa.key`、环境变量 `FOFA_KEY` 和旧引擎配置回退；前端以只读 Legacy Key 展示。

新池产生后，全局运行时使用新池；旧单 Key 值保留在原配置中，便于回滚和已有脚本读取。任务级 `fofa_config.key` 继续优先。旧 `PUT /api/settings` 对 `fofa.key` 的更新语义保持。

## 10. 测试与验收

后端 Router 单测覆盖粘性选择、顺序故障切换、单圈上限、四类失败、冷却到期恢复、全池耗尽、并发幂等、状态指纹竞态和日志脱敏。

设置 API 单测覆盖 CRUD、排序、重复名称、Key 脱敏、启用空 Key 校验、单项检测、一键检测全部 Key、手动停用保留、认证阻断恢复和旧配置回退。

集成测试覆盖 Collector 同页换 Key 后只推进一次、每日额度 `820041` 每小时探测、冷却期静默、全池等待、任务级单 Key 覆盖，以及 Worker/Killsweep 的共享 Router 路径。

前端测试覆盖列表加载、增删改、排序、启停、单项测试状态、健康检查汇总和结果过期标记。数据库迁移测试覆盖旧 `system_settings` 行和空池兼容。

验收命令：后端 `pytest`、前端 Vitest、前端生产构建；所有命令完成后再进入实现计划和分步开发。

## 11. 明确的非目标

本设计不引入所有搜索引擎的通用凭据池，不改变 FOFA 查询语法、分页语义和任务级配置格式，不把手动停用项自动打开，也不在 API 响应中暴露任何 Key 内容。
