# AutoHunter 任务挖掘方向设计

> 2026-07-15 | status: approved

## 目标

在新建任务和编辑任务时允许用户填写可选的自由文本“指定挖掘方向”。任务启动后，新派发的 Worker 优先围绕该方向侦察、验证和取证；如果发现方向之外已经确认的高危漏洞，仍允许提交，避免因任务偏好造成漏报。

空方向必须保持现有行为不变。旧任务和旧数据库升级后方向默认为空字符串。

## 非目标

- 不用挖掘方向改变 FOFA 或其他搜索引擎的资产范围。
- 不把方向并入 `vuln_types`、`fofa_query`、`src_rules`、模型配置或 FOFA 配置。
- 不让方向影响 Reviewer 的证据判断、严重性评级或收录结论。
- 不让方向影响 Escalate 对既有 Finding 的危害扩展，或 Killsweep 对通杀真伪的判断。
- 不在 Worker 已经运行后修改其本轮提示上下文。

## 核心语义

方向采用“重点引导”而不是“严格限定”：

1. Worker 优先并深入覆盖用户指定的接口、功能、参数、漏洞类型或业务流程。
2. 方向不预设漏洞一定存在，Worker 仍须完成真实验证。
3. 方向不能降低证据标准、扩大授权范围或覆盖系统安全约束。
4. Worker 遇到方向之外的明确高价值实证时仍可验证并提交。
5. 更具体的目标级指令优先于任务级方向。

运行时优先级固定为：

```text
授权范围、工具约束和真实证据要求
  > 当前目标的定向深挖或单站协作路线
  > 用户指定的任务挖掘方向
  > 自动生成的 playbook 和通用攻击面
```

## 存储与兼容

`tasks` 表新增独立列：

```python
hunt_direction: Mapped[str] = mapped_column(Text, default="")
```

字段规则：

- API 字段名统一为 `hunt_direction`。
- 创建请求缺省值为 `""`。
- 更新请求用 `None` 表示“不修改”，用 `""` 表示“显式清空”。
- 服务端在写入前执行 `strip()`。
- 最大长度为 2000 个字符，超过时返回 HTTP 422。
- `TaskResponse` 对 `full` 和 `readonly` 返回原值，对 `observer` 返回空字符串。
- 任务删除时字段随任务行一起删除，无额外清理资源。

项目使用轻量自动迁移而非 Alembic，因此 `_MIGRATIONS` 增加：

```python
("tasks", "hunt_direction", "TEXT DEFAULT ''")
```

迁移保留所有旧任务，并让旧行的 `hunt_direction` 为 `""`。

## API 数据流

创建任务：

```text
CreateView textarea
  -> POST /api/tasks 请求体中的 hunt_direction
  -> CreateTaskRequest 校验和 trim
  -> Task.hunt_direction
  -> TaskResponse.hunt_direction
```

编辑任务：

```text
TaskEditModal 回填 TaskResponse.hunt_direction
  -> PATCH /api/tasks/{task_id} 请求体中的 hunt_direction
  -> UpdateTaskRequest 区分未传与显式清空
  -> 更新 Task.hunt_direction
```

任务列表、详情、创建、更新、启动、暂停和停止响应继续统一经过 `_task_to_dto()`，由该出口负责权限投影。

## 前端交互

### 新建任务

在“漏洞类型”之后、“目标来源”之前增加全宽多行输入：

```text
指定挖掘方向（可选）
```

建议使用 3 行 textarea、`maxlength="2000"`，占位内容为：

```text
例：重点测试后台 API 的水平/垂直越权、批量导出和敏感写操作；优先关注 object_id、user_id 等对象参数。
```

创建请求始终发送 trim 后的字符串；未填写时发送空字符串。

### 编辑任务

编辑弹窗在“漏洞类型”之后增加同一字段，支持查看、修改和清空。运行中保存后，页面提示语沿用现有“下一轮调度读取新参数”的语义。

现有表单和移动端样式可以直接承载该 textarea，不增加新的页面布局或独立卡片。

## Worker 注入

编排层在每次派发 Worker 前重新读取 `Task`，将当前 `hunt_direction` 放入 Worker 的任务上下文。已经启动的 Worker 使用启动时快照；后续新派发 Worker 自动读取修改后的方向。

方向只进入 Worker 的任务级 user 消息，不修改 `worker_system_prompt()`，以保持系统提示词稳定和缓存友好。空字符串时完全不生成方向块。

方向块格式固定为：

```text
# 用户指定的任务挖掘方向
{hunt_direction}

正常挖掘时优先并深入覆盖此方向；它不预设漏洞一定存在。
若当前目标带有定向回炉或单站协作路线，以更具体的目标级指令为先。
不得因此降低证据标准、越出授权范围或忽略明显的高价值实证。
```

普通 Worker 和定向深挖 Worker 都能看到任务方向；定向深挖块和单站协作路线在提示中明确拥有更高优先级。

## Agent 隔离

- Collector 继续只使用 `fofa_query`、`intent_mode` 和 `vuln_types` 决定资产搜集，不读取 `hunt_direction`。
- Reviewer 继续只依据 Finding、证据和内置 SRC 审核标准判断，不读取 `hunt_direction`。
- Escalate 继续沿既有 Finding 扩大真实危害，不读取 `hunt_direction`。
- Killsweep 继续依据已确认漏洞判断产品级通杀，不读取 `hunt_direction`。

这种隔离避免把任务偏好误当成资产授权范围，也避免审核确认偏差。

## 错误与边界处理

- 只有空白的输入在 trim 后保存为 `""`。
- 超过 2000 字符由 DTO 返回 422，前端同时用 `maxlength` 阻止普通超长输入。
- 旧数据库迁移失败时沿用现有启动失败机制，不静默忽略缺列。
- Observer 无论通过任务列表还是详情接口都看不到方向内容。
- 修改方向不重置 FOFA cursor/history，不重新排队目标，也不中断运行中的 Worker。

## 验证标准

### 后端

- 创建任务未传方向时持久化并返回空字符串。
- 创建任务传入方向时 trim、持久化并返回原内容。
- PATCH 可修改并可显式清空方向。
- 超过 2000 字符返回 422。
- Observer 的任务列表和详情方向均为空。
- 旧 `tasks` 表自动新增列，旧行方向为空。

### Worker 与编排

- 非空方向只在 Worker 的任务级 user 消息中出现一次。
- 空方向不产生标题或空方向块。
- Worker system prompt 保持不变。
- 同时存在 `deepen_context` 或单站协作路线时，提示明确目标级指令优先。
- 运行中编辑只影响之后新派发的 Worker。
- 唯一哨兵方向文本不进入 Collector、Reviewer、Escalate 或 Killsweep 消息。

### 前端

- 新建页渲染可选 textarea 并把 trim 后字段加入创建 payload。
- 编辑页正确回填、保存和清空方向。
- 两处输入均限制 2000 字符。
- 移动端宽度下文本和输入控件不溢出。

### 回归

- 后端全量测试通过。
- 前端全量测试通过。
- Vite 生产构建通过。
- `git diff --check` 无空白错误。
