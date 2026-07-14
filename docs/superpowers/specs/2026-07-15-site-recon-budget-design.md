# 单站轻量入口盘点设计

> 2026-07-15 | status: proposed

## 目标

为单站协作增加一个显式的“轻量入口盘点”模式。开启后仍然派发 `site_map`，但将该路线限制为最多 18 个 Worker 轮次，并要求优先完成高价值入口覆盖；`site_js` 和五条主题深挖路线保持现有调度与预算。

默认使用完整模式。用户必须在创建或编辑单站任务时主动选择轻量模式；检测到账号、密码、Cookie 或 Token 时只显示提示，不自动改变任务配置。

## 非目标

- 不删除或跳过 `site_map` 路线。
- 不改变 `site_js`、认证越权、未授权配置、文件、注入和业务逻辑路线的预算。
- 不新增登录自动化、凭据提取或会话注入能力；继续复用现有 Worker 工具链。
- 不改变 Reviewer 的证据标准、Finding 结论或任务授权范围。
- 不让编辑配置回溯修改已经运行中的 Worker；新配置只影响尚未启动的 Worker 和后续补派目标。
- 不增加数据库列；继续使用现有任务 JSON 配置承载该任务级选项。

## 核心语义

### 模式

任务配置新增 `site_recon_mode`，取值为 `full` 或 `light`：

```text
full  -> site_map 使用现有 Worker 预算和提示词
light -> site_map 最多 18 轮，软收敛目标为第 12 轮
```

只有 `target_source == "site"` 且路线来源为 `site_map` 时读取该模式。其它任务和其它单站路线即使配置中存在该键也保持原行为。

### 轻量入口盘点的最低覆盖

`light` 模式的提示词要求按以下顺序行动：

1. 首页、跳转链、`robots.txt`、`sitemap.xml`。
2. API 文档和前端主资源中的 API base、路由、权限入口。
3. 一次登录后的内部菜单或高价值 API 入口盘点（已有登录态时优先）。
4. 对高价值入口做最小只读验证，并通过 `report_coverage` 写入共享覆盖摘要。

达到 18 轮前发现明确漏洞仍可提交；完成上述覆盖且没有可继续验证的高价值入口时，应主动 `finish`，不继续泛扫。

## 存储与兼容

任务 JSON 配置继续存放在 `Task.fofa_config`，字段规则如下：

```python
site_recon_mode: Literal["full", "light"] = "full"
```

- `CreateTaskRequest` 缺省为 `full`。
- `UpdateTaskRequest` 使用 `None` 表示不修改，`"full"` 表示显式恢复完整模式。
- API 服务端只接受 `full` 或 `light`，其它值返回 HTTP 422。
- `_public_fofa_config()` 对普通任务返回实际模式；observer 响应统一返回 `full`。
- 为兼容可能存在的旧实验配置，读取时若发现 `skip_site_recon == true` 且没有 `site_recon_mode`，按 `light` 解释；写入和响应统一使用 `site_recon_mode`。
- 创建与编辑必须都经过同一套字段白名单，保证 `light -> full` 和 `full -> light` 可以往返保存。

模式读取统一经过 `site_collab.recon_mode_for(task)`，由该函数处理缺省值、合法值和旧 `skip_site_recon` 兼容。API 输出、提示词构造和 Worker 元数据都复用这一入口，避免各层分别解释配置。

## 组件职责

- `app/api/dto.py`：声明创建和部分更新请求中的 `site_recon_mode` 枚举。
- `app/api/tasks.py`：完成创建、编辑、公开响应和旧配置兼容的持久化闭环。
- `app/agents/site_collab.py`：集中解析模式，并渲染完整或轻量的路线提示词。
- `app/orchestrator.py`：在 Worker 启动前把最新模式写入 `target_meta.site_collab_route`。
- `app/agents/worker.py`：只负责根据已解析的路线元数据应用 18/12 轮预算，不直接读取数据库任务配置。
- `frontend/src/views/CreateView.vue`：创建任务时显式选择并提交模式。
- `frontend/src/components/TaskEditModal.vue`：回填、编辑并显式保存模式。
- 后端与前端测试：覆盖配置往返、预算隔离、提示词分支和 UI 请求体。

## API 数据流

```text
CreateView / TaskEditModal
  -> fofa_config.site_recon_mode
  -> FofaConfigDTO / PartialFofaConfigDTO 校验
  -> Task.fofa_config JSON
  -> _public_fofa_config() 返回模式
  -> TaskRunner 为新 Worker 构造 site_collab_route.recon_mode
```

更新配置时：

1. 先复制现有 `task.fofa_config`。
2. 仅当请求显式包含 `site_recon_mode` 时写入该键。
3. 保留 `current_query`、FOFA 游标和其它运行态字段。
4. 提交事务后从 `_task_to_dto()` 返回实际保存值。

## 调度与 Worker 设计

### 路线入队

`collector._site_collect()` 继续使用完整的 `INITIAL_ROUTES`，不因轻量模式删除目标。这样共享 coverage、路线卡片和队列统计仍然完整，模式只改变 `site_map` Worker 的预算。

### 路线元数据

`TaskRunner` 构造单站路线元数据时增加：

```python
{
    "source": "site_map",
    "recon_mode": "full" | "light",
}
```

`site_js` 和主题路线使用 `recon_mode = "full"` 或省略该键。`site_focus` 定向追打不继承 `site_map` 的 18 轮限制。

### Worker 预算

在现有 `Worker._route_rounds()` 完成通用 playbook、企业模式和深挖策略计算后，读取 `target_meta.site_collab_route.source`，最后应用轻量入口盘点上限：

```python
site_route = (self.target_meta or {}).get("site_collab_route") or {}
if site_route.get("source") == "site_map" and site_route.get("recon_mode") == "light":
    max_rounds = min(max_rounds, 18)
    soft_rounds = min(soft_rounds, 12)
```

这样不会被 `deep` playbook 或任务级预算策略重新放大；完整模式的现有结果保持不变。

### 提示词

`site_collab.render_context()` 接收 `recon_mode`：

- `full` 保留当前“入口盘点与前端资源并行、持续上报 coverage”的说明。
- `light` 明确说明 18 轮硬上限、12 轮软收敛、四步最低覆盖和“完成覆盖后主动结束”。
- 主题路线仍说明 `site_map/site_js` 会并发运行，但不声称 `site_map` 使用完整预算。

### 运行中编辑

- 已经进入运行状态的 `site_map` Worker 使用启动时读取的预算，不中途改变。
- 尚未启动的队列目标在构造 `target_meta` 时读取最新模式。
- 将模式从 `full` 改为 `light` 不会取消已存在的 Worker；将模式从 `light` 改回 `full` 也不会重跑已经结束的路线。
- 编辑接口成功后，下一条新 Worker 的事件和详情应显示实际模式，避免只更新表单不更新运行时。

## 前端交互

仅在 `target_source == "site"` 时显示一个二选一 segmented control：

```text
完整入口盘点（默认） | 轻量入口盘点（最多 18 轮）
```

轻量选项下显示简短说明：会保留 `site_map`、`site_js` 和主题深挖路线，只压缩入口地图路线预算；已有凭据时更适合使用。说明只提供决策信息，不代替用户切换开关。

创建页：默认 `full`，创建请求始终发送当前模式，避免默认值和服务端继承配置混淆。

编辑页：从 `TaskResponse.fofa_config.site_recon_mode` 回填，保存时始终发送当前模式，支持显式恢复 `full`。

任务从非 site 模式切换到 site 模式时默认回到 `full`，不沿用其它任务类型残留的配置。

## 可观测性

- Worker 启动事件的 `target_meta.site_collab_route` 包含 `recon_mode`。
- Worker 结束事件继续记录实际 `rounds`，前端路线卡片可显示“轻量 / 完整”和轮次。
- 不新增敏感信息；任务配置响应沿用现有密钥脱敏规则。

## 错误处理

- API 收到未知 `site_recon_mode` 时由 Pydantic 返回 422，不静默回退。
- 配置缺失、旧任务或值为空时按 `full` 处理。
- Worker 元数据缺失或模式未知时按 `full` 处理，并记录一次调试日志，避免错误配置意外压缩扫描预算。
- `site_map` 达到 18 轮但没有主动结束时，沿用现有 Worker 超预算收敛结果，记录达到轻量上限的状态；不自动判定无漏洞。

## 测试设计

### 后端单元测试

- `FofaConfigDTO` 默认 `site_recon_mode == "full"`，只接受 `full/light`。
- 创建任务保存 `light`，详情响应返回 `light`；编辑可从 `light` 切回 `full`，并保留其它 `fofa_config` 运行态字段。
- 旧配置只有 `skip_site_recon: true` 时读取为 `light`。
- `initial_routes_for` 或等价路线构造始终返回 7 条路线，不再删除 `site_map`。
- `Worker._route_rounds()` 对 `site_map + light` 返回最大 18、软收敛不超过 12；对 `site_map + full`、`site_js + light` 和 `site_focus + light` 保持原上限。
- `render_context()` 的 `light` 文本包含 18 轮和最低覆盖要求，`full` 文本保持原语义。

### API/集成测试

- PATCH 任务后立即 GET，确认前端可见的配置与 Worker 下一轮读取的配置一致。
- 运行中的已有 `site_map` 不因 PATCH 被取消；下一个新 Worker 使用新模式。
- observer 响应不泄漏任务的轻量模式细节以外的敏感配置，并继续隐藏密钥。

### 前端测试

- 创建页只在 site 模式显示控制，默认选择完整模式。
- 切换到轻量模式后请求体携带 `site_recon_mode: "light"`；切回完整模式携带 `"full"`。
- 编辑页能够回填、切换和提交两个模式；不再使用关键词自动勾选。

## 验收标准

1. 新建单站任务默认行为与当前版本一致：7 条路线、完整 `site_map` 预算。
2. 用户显式选择轻量模式后，仍有 7 条路线，但 `site_map` 的 Worker 最多执行 18 轮，软收敛不超过 12 轮。
3. `site_js` 和五条主题路线不受影响，coverage 仍能被后续路线读取。
4. 轻量模式创建、编辑、刷新详情和运行时读取形成完整闭环。
5. 所有新增后端和前端测试通过；现有测试无回归。
