# FOFA 与 LiteLLM 可靠性修复设计

> **状态：已确认设计，待实施**

## 目标

修复生产环境中 FOFA 每日额度错误被识别为 transient、调度器高频重复请求和事件刷屏问题；同时修复不同 LiteLLM Provider 的工具调用协议不匹配，并让健康检测能够提前发现协议错误。

## 生产证据

- FOFA Key 池有 4 个启用 Key：3 个返回 `820041` 每日 3000 次上限，1 个返回 `[-200] 今日调用次数已用完`。
- `[-200] 今日调用次数已用完` 当前未命中每日额度标记，被归类为 `transient`，因此保持 `ready` 并持续重试。
- `fofoapi.com` 根地址和 `/api/v1/search/all` 均可连通，问题不是 DNS、TLS 或接口路径不可达。
- LiteLLM Provider LLM-1 使用 `openai_chat` 发送工具时返回 Anthropic `unknown variant custom`；同端点使用 `anthropic_messages` 成功。LLM-2 的兼容矩阵相反，`openai_chat` 成功、`anthropic_messages` 返回不支持模型。

## 架构

### FOFA 错误分类

扩展 `app.fofa.client.classify_fofa_failure` 的每日额度文本匹配，新增“今日调用次数”“调用次数已用完”等中英文表达。`-200` 只有在同时出现额度耗尽语义时才归类为 `daily_limit`，避免把通用错误码误判为额度错误。

### FOFA 运行状态与退避

新增 `transient_cooldown` 运行状态。Router 对 transient 按 Key 记录指数退避 15、30、60、120、300 秒；状态到期后自动回到候选池，成功请求清除失败状态。候选快照继续使用 Key 与端点原子配对；全池不可用时返回最早恢复时间，Collector 在任务级静默等待。

### FOFA 诊断与事件限频

Collector 保存脱敏后的 `kind`、`code`、错误摘要和 `retry_at`，不写入 Key 或其 URL 编码形式。相同任务、相同错误签名 60 秒内最多写一条 `collector_phase` 事件；状态配置仍实时更新。成功后清除错误签名、错误摘要和退避标记。前端设置页为 `transient_cooldown` 提供明确状态文案。

### LiteLLM Provider 协议

Provider 协议继续按配置独立生效，不在正常请求中自动双协议重试：

- LLM-1：生产配置迁移到 `anthropic_messages`。
- LLM-2：保留 `openai_chat`。

健康检测增加最小工具调用，验证当前 Provider 的真实工具协议。配置协议失败时，仅额外尝试另一协议用于诊断，并返回 `recommended_protocol`，不自动持久化切换。`unknown variant custom`、工具反序列化失败和模型不支持等错误归类为 `protocol`，保留脱敏诊断详情。

## 交互与数据流

1. FOFA 返回额度错误。
2. Client 提取错误码和文案，分类为 `daily_limit`。
3. Router 将当前 Key 置为 `daily_cooldown`，记录恢复时间并切换候选。
4. 全部 Key 冷却时，Collector 写一次等待事件；冷却期间不发送网络请求、不刷事件。
5. 未知 transient 错误进入 `transient_cooldown`，到期后按候选规则恢复。
6. LLM 健康检测分别执行当前协议和必要的备用协议诊断，返回协议、端点、状态码和建议，不修改配置。

## 测试设计

- FOFA：覆盖 `820041`、`[-200] 今日调用次数已用完`、中英文额度表达、普通 `-200` 非额度错误。
- Router：覆盖 transient 退避递增、冷却到期重新候选、全池等待、成功清除状态和跨 Key 端点原子性。
- Collector：覆盖脱敏错误字段、游标不推进、重复事件 60 秒限频和成功清理。
- 前端：覆盖 `transient_cooldown` 状态和倒计时文案。
- LiteLLM：覆盖 OpenAI Chat/Anthropic Messages 工具请求矩阵、协议错误分类、备用协议只诊断不写回。
- 回归：运行全部 Python 测试、前端单元测试和生产镜像构建检查。

## 部署与回滚

1. 本地测试全部通过后构建新镜像。
2. 生产部署前备份 `autohunter_ah_data` 数据卷。
3. 通过设置服务把 LLM-1 协议改为 `anthropic_messages`，不直接修改 SQLite。
4. 重启应用容器并执行 FOFA/LLM 健康验证。
5. 若验证失败，恢复旧镜像和旧 Provider 协议；不删除历史事件。

## 非目标

- 不删除已有生产事件。
- 不自动更换或生成 FOFA/LLM Key。
- 不在正常 Worker 请求中进行隐式双协议重试。
- 不修改外部 LiteLLM 服务端配置。
