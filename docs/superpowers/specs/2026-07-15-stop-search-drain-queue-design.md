# AutoHunter 停止搜索并排空队列设计

> 2026-07-15 | status: approved

## 目标

在任务详情右侧控制区新增“停止搜索”按钮。用户点击后，Collector 不再通过 FOFA 或当前配置的资产搜索引擎补充目标；已经进入队列和正在处理的目标继续执行。待目标队列、在途 Worker 和由这些目标触发的后台处理全部完成后，任务自动进入 `stopped`。用户下一次点击“启动”时，资产搜索自动恢复。

## 非目标

- 不删除、跳过或取消已经入队的目标。
- 不取消正在运行的 Worker、Reviewer、Killsweep 或 Escalation 任务。
- 不改变现有“暂停”和“停止任务”的语义。
- 不阻止 Worker 在分析单个目标时使用只读的 `fofa_lookup` 等辅助工具；本功能只关闭 Collector 的资产补充。
- 不新增 `draining` 任务状态，也不重构现有任务状态机。
- 不提供单独的“恢复搜索”按钮；再次点击现有“启动”即恢复搜索。

## 核心语义

“停止搜索”是一个持久化的任务级开关，而不是强制终止命令：

1. 仅 `target_source` 为 `fofa` 或 `both` 的任务显示该操作。
2. 任务为 `running` 或 `idle` 且搜索开关开启时，按钮可点击。
3. 点击后，搜索开关立即关闭，按钮锁定为“搜索已停止”，任务继续派发既有队列。
4. 已经发出的当前资产搜索请求不强制取消；该批次可以完成筛选和入队，但后续 tick 不再发起新的搜索请求。
5. 当 queued、assigned、scanning、活跃 Worker、Reviewer、Killsweep 和 Escalation 均为空时，任务自动变为 `stopped`，并结束对应 TaskRunner。
6. `start` 接口总是重新打开搜索开关，因此从手动停止、自动排空停止或暂停状态再次启动时都恢复资产搜索。
7. 重复调用“停止搜索”保持幂等，不重复创建状态变化，也不影响队列。

## 持久化模型

在 `Task` 增加独立布尔列：

```python
search_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
```

选择独立列而不是把开关写入 `fofa_config`，仍属于已确认的“持久化搜索开关”方案，但规避一个现有并发风险：Collector 会在长流程中多次整体写回 `fofa_config` JSON；如果控制接口同时修改同一 JSON，Collector 的旧快照可能覆盖刚写入的停止状态。独立列由控制接口单独更新，Collector 继续只更新 `fofa_config`，两者不会互相覆盖。

项目使用轻量自动迁移，因此 `_MIGRATIONS` 增加：

```python
("tasks", "search_enabled", "BOOLEAN DEFAULT 1")
```

旧任务迁移后默认开启搜索。创建任务无需新增用户输入，默认值为 `true`。

`TaskResponse` 增加顶层字段 `search_enabled: bool`。该字段不包含敏感信息，对所有现有角色均可返回，前端不需要从经过脱敏投影的 `fofa_config` 推断状态。

## API

新增接口：

```text
POST /api/tasks/{task_id}/stop-search
```

处理流程：

1. 查询任务，不存在时返回 HTTP 404。
2. 如果 `search_enabled` 已为 `false`，直接返回当前 `TaskResponse`，保证重试幂等。
3. 将 `search_enabled` 设为 `false` 并提交。
4. 写入一条任务事件，说明新的资产搜索已停止，剩余队列将继续处理。
5. 返回更新后的 `TaskResponse`。

该接口不调用 `manager.pause()` 或 `manager.stop()`，也不修改任务状态。TaskRunner 下一次循环从数据库读取到关闭状态后，Collector 只停止后续 FOFA/资产搜索；`both` 任务中尚未消费的手动目标仍可入队，单站路线也保持现有行为。

现有 `POST /api/tasks/{task_id}/start` 在设置 `status = "running"` 的同时设置 `search_enabled = true`。现有 pause/stop 接口不修改该字段；无论之前为何停止，下一次启动都按用户确认的方案 A 恢复搜索。

## TaskRunner 数据流

每次 `_tick()` 的调度顺序保持现有结构，Collector 内部按开关选择资产搜索分支：

```text
读取 Task
  -> collector.refill：继续消费手动目标/单站路线
  -> search_enabled=true：执行 FOFA/资产搜索补充分支
  -> search_enabled=false：跳过 FOFA/资产搜索补充分支
  -> 回收僵尸目标
  -> 派发已有 queued 目标
  -> 派发 Reviewer / Escalation / Killsweep
  -> 统计 queued、assigned、scanning 和内存后台任务
  -> 搜索关闭且全部清空：记录排空事件，status=stopped，结束 runner
  -> 搜索开启：沿用现有 running/idle 判定
```

排空判定在派发各类后台任务之后执行，并把 `_review_tasks` 纳入排空 busy 集合，避免最后一个 Worker 刚产出 Finding 时提前停止并取消 Reviewer。Killsweep 与 Escalation 已在现有 busy 判定中，继续沿用。

自动排空停止只在 `search_enabled == false` 时触发。正常搜索开启时仍沿用当前 `idle` 行为，避免改变已有任务的持续补充机制。

自动停止时先持久化 `status = "stopped"` 和任务事件，再设置 runner 的停止事件。此时排空条件已经确认没有活跃子任务，因此不需要走会取消并回队 Worker 的强制停止流程。

## 前端交互

按钮插入任务详情右侧控制区，位于“暂停”和现有“停止”之间：

```text
编辑参数
启动
暂停
停止搜索
停止任务
```

为避免两个“停止”产生歧义，现有“停止”按钮文案调整为“停止任务”。“停止搜索”使用琥珀色描边和浅色背景，表达“停止补充但继续收尾”；“停止任务”保留现有中性/危险操作层级。

交互状态：

- 可点击：显示“停止搜索”。
- 请求中：显示“正在停止”，禁用按钮，防止重复提交。
- 已关闭且仍在处理：显示“搜索已停止”，禁用按钮；任务元信息增加“FOFA 已停止 · 正在排空队列”。
- 排空完成：任务状态显示“已停止”；“启动”重新可用，“搜索已停止”保持只读状态，提示下一次启动会恢复。
- 接口成功 toast：`已停止继续搜索，剩余队列将继续处理`。
- 接口失败 toast：`停止搜索失败：<错误摘要>`，并恢复按钮可用状态。

不增加确认弹窗。该操作不丢弃数据、不取消既有工作，且下一次启动会恢复搜索；额外确认会拖慢高频控制操作。

移动端沿用 `.mission-actions` 的三列网格，五个操作自然换成两行。按钮使用稳定最小高度，并允许四字文案完整显示，不压缩或遮挡相邻控件。

## 错误与并发处理

- 当前 Collector 批次不做协程强制取消，避免中途取消探活、评分或数据库写入造成半批数据。按钮语义明确为“停止后续搜索”。
- 独立 `search_enabled` 列避免与 Collector 对 `fofa_config` 的整体写回互相覆盖。
- API 幂等使前端超时重试不会反复修改状态。
- TaskRunner 每个 tick 都从新 session 读取 Task，服务端无需依赖仅存在于内存的停止标记。
- 服务重启仍保留 `search_enabled = false`。项目现有启动恢复逻辑可能先把运行任务置为暂停；用户再次启动时按既定语义恢复搜索。
- 任务被手动强制停止时仍沿用现有取消和回队逻辑，不与排空停止混用。

## 测试策略

### 后端 API

- 停止搜索接口将开关持久化为 `false`，返回 DTO 同步反映状态。
- 重复请求保持 200 和 `false`，不改变 queued/scanning 目标。
- 不存在任务返回 404。
- `start` 将开关恢复为 `true`。
- 数据库迁移为旧任务补充默认值 `true`。

### TaskRunner

- 搜索开启时 `collector.refill()` 继续执行资产搜索分支。
- 搜索关闭时 `collector.refill()` 跳过 `_fofa_collect()`，但仍可消费 `both` 任务的手动目标，并继续从 queued 目标派发 Worker。
- 队列或任一在途/后台任务仍存在时不自动停止。
- 最后一个 Reviewer 完成前不自动停止。
- 所有工作清空后持久化 `stopped`、记录排空事件并结束 runner。
- 正常搜索开启且无任务时仍进入既有 `idle`，不误触发自动停止。

### 前端

- `api.stopSearch()` 请求正确路由。
- 仅 FOFA/混合来源任务显示按钮。
- 运行中开关开启时可点击；请求中和已关闭时禁用。
- 成功后更新任务状态、展示排空提示和成功 toast。
- “停止任务”仍调用原有 stop 接口。
- 桌面与移动端按钮无溢出或重叠。

## 验收标准

1. 点击“停止搜索”后不再出现新的 Collector 搜索批次。
2. 点击前已经 queued、assigned 或 scanning 的目标继续完成。
3. 最后一个目标及其后台处理完成后，任务自动显示“已停止”。
4. 服务刷新或重启不会把关闭状态误恢复为开启。
5. 再次点击“启动”后搜索开关恢复，Collector 可以继续补充新目标。
6. 原有启动、暂停、停止任务、队列排序和删除功能保持可用。
