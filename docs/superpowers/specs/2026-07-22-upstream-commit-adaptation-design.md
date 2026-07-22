# 原项目提交适配改造设计

## 背景

当前仓库基于原项目持续二次开发，已经增加多 Provider 路由、三种 LLM 协议、FOFA 多 Key 轮换、任务队列持久化、单站协作、全局复审和运行状态展示。待适配的十个原项目提交位于两条与当前主分支分叉的历史线上，直接 cherry-pick 会覆盖或绕开上述现有能力。

本次改造按提交表达的行为逐项移植，不以文件内容覆盖为实现手段。涉及的上游行为分为四组：

1. 写入类漏洞必须通过独立读取路径证明状态真实变化。
2. LLM 强制工具选择降级和非标准 ChatCompletion 响应兼容。
3. FOFA 查询翻译、原生语法透传及多个测绘引擎的 API/字段修复。
4. 任务级登录凭据绑定、Worker 启动使用及看板反馈。

## 已确认决策

- 采用按当前架构语义移植的方案，不直接 cherry-pick 原项目提交。
- FOFA 官方地址默认可用；私有部署或代理继续通过现有 `FOFA_ALLOWED_HOSTS` 显式放行，不移除出站安全校验。
- 任务详情和编辑接口返回登录凭据明文；运行事件、日志和看板不展示密码、Cookie 值或 Authorization 值。
- 账号密码启动登录采用保守模式：优先使用明确的 `login_url`；未提供时只检查目标入口页面中真实存在的密码表单，不猜测常见登录页面或 API 路径。

## 目标

- 完整落地十个上游提交中适用于当前项目的行为。
- 保持现有 LLM Provider 池的权重选择、故障转移、协议适配和自动禁用语义。
- 保持现有 FOFA Key 池的轮换、冷却、额度状态、诊断事件和凭据/端点原子绑定。
- 没有登录凭据的旧任务继续沿用原有收集、入队和 Worker 执行路径。
- 用自动化测试覆盖新增行为和现有关键契约。

## 非目标

- 不恢复上游已经被当前项目替代的单 Provider LLM 客户端架构。
- 不以原项目版本覆盖当前任务 API、数据库模型、Collector、Worker 或前端视图。
- 不移除 FOFA `base_url` 的 SSRF 防护。
- 不扩大账号密码的自动登录路径枚举范围。
- 不重构与本次适配无关的模块。

## 总体架构

改造分为四个边界明确的模块：证据规则、LLM 兼容、搜索引擎适配和任务登录凭据。各模块通过现有接口接入，并分别具备独立测试。

### 证据规则

在当前提示词体系中补充统一的写操作证据门槛：

- `update`、`save`、`delete`、`remove`、改密等写操作的自身响应只作为请求执行信息。
- 有效证据必须来自详情、列表、重新登录或其他独立读取路径，形成可核对的 before/after 状态差异。
- Worker 在缺少侧面回读时继续寻找读取路径或以明确线索收尾。
- Reviewer 对只有 `200`、`success` 或相似响应而没有侧面回读的写操作执行忽略或定向深挖。

该规则同步进入当前完整 Worker、精简 Worker、企业 Reviewer 和精简 Reviewer 提示词，并通过现有提示词策略测试固定关键语义。

### LLM 兼容

#### 强制工具选择降级

降级逻辑放在单个 `LLMClient` 内，不放入 `LLMRouter`：

1. Client 按当前协议适配器构造请求。
2. 请求使用具名强制 `tool_choice` 且收到明确的 400/422 工具选择不兼容响应时，使用同一 Provider、同一协议和同一消息将 `tool_choice` 改为 `auto` 后重试一次。
3. 本地降级成功则正常返回 `LLMResponse`。
4. 本地降级仍失败则抛出归一化 `LLMError`，由现有 Router 按稳定顺序切换下一个 Provider。

降级不修改 Provider 配置，不触发 Provider 自动禁用。现有 Router 仍只在 `auth` 或 `quota` 错误时执行自动禁用。

#### 非标准响应归一化

HTTP 返回在进入协议适配器前完成最小归一化：

- 标准对象保持原样。
- JSON 字符串解码为结构化对象。
- OpenAI Chat 协议下的纯文本包装为单条 assistant content。
- OpenAI Chat 协议下的 SSE 残留读取最后一条有效 `data:`，忽略 `[DONE]`。
- `choices[0]` 为字符串、`message` 为字符串、content 为文本块列表、tool arguments 为对象时，转换为当前 `LLMResponse` 和 `ToolCall` 数据结构。
- 明确的网关 `error` 对象转换为 `LLMError`，并继续走 Router 的现有故障转移。

Anthropic Messages 和 OpenAI Responses 保留各自现有请求、响应和 continuation 语义。公共返回类型 `LLMResponse`、`ToolCall` 以及历史消息格式不变。

### 搜索引擎适配

#### 查询翻译

`app/engines/translator.py` 负责把可识别的 FOFA 条件解析为中间 token，再翻译到目标引擎。解析保留 `&&`、`||`、等于、模糊匹配和否定操作。

翻译决策顺序：

1. 目标为 FOFA 时原样返回。
2. 查询符合目标引擎的原生语法特征时原样返回。
3. 查询不符合 FOFA 条件语法时原样返回。
4. 其余情况调用对应翻译器。

`domain=".edu.cn"` 和同类 host 后缀在需要裸域名的引擎中转换为 `edu.cn`。未知字段尽量保留，明确没有对等字段的条件才跳过。

#### 引擎 API 修复

- Hunter：查询按 RFC 4648 URL-safe Base64 编码，调用 `/openApi/search`，使用 `is_web=3`，兼容 `web_title`、`company` 等字段。
- ZoomEye：调用 `api.zoomeye.ai/v2/search`，使用 `qbase64`、`pagesize`、`sub_type=web` 和 v2 字段映射。
- Shodan：使用官方 `/shodan/host/search` 参数，不发送无效的 `limit` 参数，并兼容空列表和错误对象。
- Censys：使用 Search API v2 cursor 翻页，兼容 HTTP title、DNS name、自治系统组织字段并返回 `next_cursor`。
- Quake：保持现有请求和限流异常语义，仅接受统一的可选 cursor 参数。
- FOFA：继续委托当前 `app.fofa.client` 和 `FofaKeyRouter`，不改变凭据轮换及出站地址校验。

`SearchEngine.search()` 增加默认值为 `None` 的可选 `cursor` 参数，现有调用仍可使用原参数集合。`EngineResult` 增加可选 `next_cursor`。

Collector 在调用非 FOFA 引擎前执行翻译，并把翻译后的查询及 Censys cursor 保存在任务现有 `fofa_config` JSON 中。查询发生变化时清理旧引擎 cursor。FOFA 路径继续通过 Router 执行，不使用引擎 cursor。

### 任务登录凭据

#### 数据结构

数据库增加三个向后兼容的 JSON 字段：

- `Task.auth_bindings`：任务级绑定列表，默认空列表。
- `Target.auth_context`：目标入队时解析出的凭据上下文，可空。
- `Target.auth_status`：最近一次使用状态，可空。

单条绑定结构：

```json
{
  "target": "*",
  "username": "",
  "password": "",
  "cookie": "",
  "authorization": "",
  "login_url": "",
  "raw": "",
  "note": ""
}
```

快捷文本可识别 Cookie Header、Authorization Bearer、中文或英文账号密码键值对。解析结果只在目标上下文中保存必要的 cookies、headers、账号密码、登录地址和类型列表。

#### 绑定匹配

匹配按以下优先级选择同一层级的所有绑定并合并：

1. 完整 URL。
2. 手动清单中的完整目标。
3. `host:port`。
4. host。
5. `*` 默认绑定。

显式目标优先于通配符。Cookie 和 Header 按键合并；同一层级存在多组账号密码时使用最后一组完整账号密码。目标入队时生成 `auth_context`，不改变 URL、source、队列优先级或去重键。

#### Worker 启动

Worker 在任何 LLM 轮次之前执行一次凭据启动：

1. Cookie 和 Authorization 通过现有 `session_set` 注入。
2. 存在账号密码和 `login_url` 时，只访问该地址并提交真实页面中的密码表单。
3. 没有 `login_url` 时，只访问目标入口页面并提交其中真实存在的密码表单。
4. 表单保留隐藏字段，填写最符合 username/account/email 和 password/pwd 特征的输入字段。
5. 登录成功依据有效会话 Cookie、离开登录页的同源跳转或明确的结构化成功结果判断。
6. 登录结果写入 `target_meta`，供 Worker 提示词了解已使用的凭据类型和结果。

`login_url` 必须保持与目标同源，防止账号密码被发送到其他主机。凭据启动异常生成脱敏状态事件，然后继续原 Worker 流程。

#### 状态与事件

`Target.auth_status` 和 `auth_status` 事件只保存：

- `used`、`matched`、`status`；
- `kinds`、`matched_by`、`binding_target`；
- `cookie_names`、`header_names`；
- 截断后的原因和展示消息。

状态和事件不包含 username、password、Cookie 值、Authorization 值或快捷粘贴原文。状态持久化失败只记录日志，不中断 Worker。

#### API

`CreateTaskRequest`、`UpdateTaskRequest` 增加 `auth_bindings`。`TaskResponse` 返回任务当前绑定列表。字段默认空列表，使旧客户端和旧任务继续工作。

根据已确认的产品决策，任务详情和任务编辑接口对现有可访问角色返回明文绑定内容。该行为不扩展到运行事件、Board 接口或运行日志。

#### 前端

- 纯 FOFA 自动搜任务隐藏凭据区。
- 手动清单、两者和单站协作显示凭据区。
- 支持 `*` 和手动目标作为绑定选项。
- 支持快捷粘贴与结构化字段。
- 任务编辑加载并保存完整绑定列表。
- Board Worker 卡片显示已注入、登录成功、登录失败或未匹配徽章。
- 活动流显示脱敏的凭据状态消息。

前端改动复用当前表单、按钮、输入框和状态徽章样式，不创建独立页面或新的导航入口。

## 错误处理

- LLM 降级严格限制为一次；后续错误继续使用 Router 现有故障转移。
- 非标准 LLM 响应缺少可解释内容时抛出 `upstream` 类型错误。
- 搜索引擎响应解析失败时保留引擎名称和截断后的服务端消息，不记录 API Key。
- Censys cursor 只在请求成功后推进；失败时保留当前 cursor。
- 登录页面不可达、缺少密码表单、登录响应不明确或遇到验证码时记录 `login_fail`，Worker 主流程继续执行。
- 登录状态判断不把单独的 HTTP 200 作为成功证据。

## 向后兼容约束

- `LLMRouter.chat()` 参数、返回类型、权重起点选择、稳定故障转移和自动禁用规则保持不变。
- 三种协议适配器的公共接口保持不变。
- `FofaKeyRouter` 的执行、冷却、持久化和事件契约保持不变。
- 新数据库列均有空值或空列表默认值，迁移不修改已有列和索引。
- 没有凭据的任务不触发额外 HTTP 请求、状态事件或提示词内容。
- 旧任务 API 请求缺少新字段时继续使用空绑定。
- 当前任务状态筛选、全局复审、疑似信号、通杀和报告流程不在本次修改范围内。

## 测试策略

实现采用测试先行，每个行为先增加能够失败的测试，再编写最小实现。

### 基线验证

改动前和全部改动后执行：

```powershell
pytest -q
npm --prefix frontend test
npm --prefix frontend run build
```

### 新增后端测试

- 提示词测试：完整与精简 Worker/Reviewer 均包含独立侧面回读门槛。
- LLM Client 测试：400/422 降级、同 Provider 重试、失败后 Router 接管、标准响应、JSON 字符串、纯文本和 SSE 残留。
- LLM Router 回归：权重、故障顺序、`auth/quota` 自动禁用及其他错误不禁用。
- 翻译器测试：字段映射、前导点、逻辑连接、否定和各引擎原生语法透传。
- 引擎测试：Hunter、ZoomEye、Shodan、Censys 的 URL、参数、编码、响应字段和 cursor。
- 凭据测试：解析、匹配优先级、合并、会话注入、指定登录地址、入口真实表单、同源限制、零凭据零请求和事件脱敏。
- 数据库迁移测试：旧数据库补列，已有任务和目标可读取。
- 任务 API 测试：创建、修改、读取、明文返回以及空字段兼容。
- Collector/Worker 测试：入队绑定、启动顺序、状态持久化失败不阻断主流程。

### 新增前端测试

- 各任务来源下凭据区的显示规则。
- 绑定导出、编辑加载和空行过滤。
- Board 凭据状态文案和样式映射。
- 现有任务来源、任务状态筛选和操作面板契约回归。

## 实施与提交边界

实现按以下独立提交推进，提交说明使用中文：

1. 提示词证据门槛及测试。
2. LLM 强制工具选择降级及响应归一化测试。
3. 查询翻译、引擎 API 修复及测试。
4. 登录凭据后端模型、迁移、解析和启动测试。
5. 登录凭据 API、前端表单、看板和测试。
6. 全量回归中发现的兼容性修复。

每个提交只包含对应模块，便于定位回归和按模块回滚。
