# SRC 工具链闭环整合设计

> 2026-07-15 | status: proposed

## 目标

把已经接入的 SRC CLI 工具从“模型可以单独调用”整合为可追踪的工作流：

```text
侦察 -> 定位 -> 验证 -> 取证 -> 评级/升级
```

HTTPX、Katana、FFUF、Arjun、wafw00f 和受限端口探测负责补全攻击面；`http_request`、响应对比和现有证据工具负责验证；Worker 只在高价值线索已经复核或明确失败后结束。完整 CLI 输出进入私有 `RawEvidence`，模型上下文只接收有界摘要。

本期采用内存线索状态，不增加数据库表或迁移；现有 `RawEvidence` 作为跨事件的事实来源。后续需要跨 Worker、跨重启复用时，再单独设计持久化 `TargetArtifact`。

## 非目标

- 不新增 Nuclei、Dalfox 或其它漏洞扫描器到企业 SRC 路径。
- 不把 CLI 结果直接当作漏洞 Finding；任何结论仍需真实请求/响应证据和现有 Reviewer 流程。
- 任务授权范围、目标 host 约束、速率上限和现有 RawEvidence 保留策略均保持现状。
- 不在本期引入 `TargetArtifact` 数据表、迁移、跨任务资产图或新的队列服务。
- 不让 Escalate 重新执行泛侦察；扩大危害只从已有 Finding 和验证证据开始。
- 不把提示词中的自然语言顺序当成唯一控制面；工具可见性、执行器和 Worker 状态共同决定可执行动作。

## 设计不变量

1. **企业默认拒绝**：工具目录中未明确标记 `enterprise_allowed=True` 的工具不进入企业 schema，也不得由 executor 执行。Nuclei、Dalfox 和同类漏洞扫描能力显式标记为关闭。
2. **线索不是结论**：CLI 命中只产生 `pending` 线索；只有匹配的 `http_request`/响应对比证据才能转为 `verified`。
3. **范围先于复用**：所有由 CLI 产生的 URL、host 和参数继续经过当前目标 scope 校验，授权边界始终以任务配置为准。
4. **私有原文、公开摘要**：完整的合并 output 只写入私有捕获；事件总线、LLM 历史和看板只携带脱敏、截断后的摘要。
5. **失败不造假**：缺少二进制、超时、解析失败或范围拒绝均记录明确失败状态，不生成虚构命中。
6. **终态可解释**：Worker 结束时必须能说明剩余线索是已验证、明确失败、证据不足，还是因预算/策略未处理。

## 术语与状态

### ToolSpec 与目录边界

本期分开管理两类能力，避免把 `finish`、会话工具和证据工具误当成外部 CLI：

- `SRC_TOOL_CATALOG` 位于 `app/tools/src_toolkit.py`，只登记 HTTPX、Katana、FFUF、Arjun、wafw00f、Nmap、Nuclei、Dalfox 等外部 CLI。
- `WORKFLOW_TOOL_STAGES` 位于 `app/tools/schemas.py`，登记已有 schema 工具的阶段和角色；控制工具（`finish`、`submit_finding`、`check_duplicate_finding`、`report_coverage` 等）通过 `ALWAYS_VISIBLE_TOOLS` 单独保留。

统一目录项描述外部 CLI 的能力边界，由 schema、executor、Worker 和文档共同读取：

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str
    stage: Literal["recon", "locate", "verify", "evidence"]
    roles: tuple[str, ...]
    routes: tuple[str, ...]
    enterprise_allowed: bool
    requires: tuple[str, ...]
    produces: tuple[str, ...]
    max_rate: int
    timeout: int
    summary_kind: str
```

`routes=()` 表示所有路线；非空值必须使用现有 `RoutePlan` 的精确 ID。目录不替代现有命令构造函数；`run_src_tool()` 先检查 `SRC_TOOL_CATALOG` 和企业策略，`build_src_plan()` 继续负责名称、参数和目标范围校验。未登记的 SRC CLI 默认关闭；已有核心 schema 必须通过阶段映射或 `ALWAYS_VISIBLE_TOOLS` 登记后才能被阶段过滤器返回。

首期目录映射：

| 工具 | 阶段 | 角色 | 主要产出 | 企业 |
| --- | --- | --- | --- | --- |
| `probe_http` | recon | worker | `fingerprint`、`http_baseline` | 是 |
| `fingerprint_waf` | recon | worker | `waf_fingerprint` | 是 |
| `scan_web_ports` | recon | worker | `service` | 是（仅 Web/管理端口白名单） |
| `crawl_endpoints` | locate | worker | `endpoint`、`parameter`、`js_asset` | 是 |
| `discover_content` | locate | worker | `endpoint`、`path_candidate` | 是（内置小字典） |
| `discover_parameters` | locate | worker | `parameter` | 是（已知端点） |
| `scan_nuclei` | verify | worker | `scanner_candidate` | 否 |
| `verify_xss` | verify | worker | `xss_candidate` | 否 |

`http_request`、`compare_http_responses`、`analyze_javascript`、会话和证据工具由 `WORKFLOW_TOOL_STAGES` 登记，不属于 `SRC_TOOL_CATALOG`。`scan_nuclei`/`verify_xss` 即使在普通模式也不进入 Escalate，因为它们是 Worker 的定向候选验证，不是既有 Finding 的危害扩大工具。

### Lead

`SrcCandidate` 是解析器输出的规范化候选，不携带完整响应或敏感 query 值：

```python
@dataclass(frozen=True)
class SrcCandidate:
    kind: Literal["endpoint", "parameter", "fingerprint", "service", "hypothesis"]
    endpoint_key: str
    value: str
    method: str
    parameter: str
    location: str
    status_code: int | None
    confidence: float
    priority: int
    reason: str
```

`Lead` 是 Worker 运行期的记录，状态通过受控转换更新，字段如下：

```python
@dataclass
class Lead:
    id: str
    kind: str
    endpoint_key: str
    value: str
    method: str
    parameter: str
    location: str
    sources: tuple[str, ...]
    capture_ids: tuple[str, ...]
    confidence: float
    priority: int
    status: Literal["pending", "verified", "failed", "inconclusive", "skipped"]
    verify_action: str
    attempt_count: int
    created_round: int
    last_attempt_round: int | None
    resolution_reason: str
    evidence_ids: tuple[str, ...]
```

`value` 只保存 URL/path/参数名等必要信息，不保存令牌、Cookie 或完整响应体。以 `(kind, endpoint_key, method, parameter, location)` 去重；同一线索再次出现时合并 `sources`、`capture_ids`，并取最高置信度和优先级。重复来源保持同一 Lead，不通过人为的 `expired` 状态掩盖重复。

## 组件职责与接口

### `app/tools/src_toolkit.py`

- 定义 `SRC_TOOL_NAMES`、`ENTERPRISE_BLOCKED_SRC_TOOLS` 和 `SRC_TOOL_CATALOG`。
- 保留现有 `_probe_http` 等计划构造函数；`run_src_tool()` 先检查目录和企业策略，`build_src_plan()` 继续负责名称、参数和目标范围校验。
- 增加纯函数 `parse_src_output(tool: str, output: str) -> SrcParseResult`，供单元测试和有界预览使用；生产路径另加 `parse_src_capture(tool: str, capture: Mapping[str, Any], scope_target: str) -> SrcParseResult`，从私有 capture 的 `output` 通道流式读取完整字节后解析并做 scope 过滤。

`SrcParseResult` 至少包含：

```python
@dataclass(frozen=True)
class SrcParseResult:
    tool: str
    parse_ok: bool
    count: int
    head_candidates: tuple[SrcCandidate, ...]
    tail_candidates: tuple[SrcCandidate, ...]
    priority_candidates: tuple[SrcCandidate, ...]
    omitted: int
    parse_errors: tuple[str, ...]
    next_actions: tuple[str, ...]
    partial: bool
    remaining_unknown: bool
    failure_kind: str
```

解析器按工具处理 JSONL、JSON 和纯文本三类输出；每类候选限制字段长度并规范化 endpoint、parameter、method 和状态码，遇到坏行计入 `parse_errors` 后继续解析。生产解析读取 `_run_process()` 当前已经生成的私有 `output` 通道（stdout/stderr 已按现有契约合并），不依赖被截断的公开 `result.output`。流式解析最多扫描 64 MiB/50,000 行，内存中只保留首 3、尾 3 和优先级前 3；超过扫描上限时停止读取并标记 `partial=True, remaining_unknown=True`，此时 `count` 只代表已扫描窗口，`omitted` 只代表窗口内未保留的候选。完整扫描时 `remaining_unknown=False`，`count` 与 `omitted` 精确。没有有效候选时返回 `count=0`，不把进程成功退出码解释成命中；候选 URL 在 `parse_src_capture(..., scope_target)` 阶段重新执行当前目标 scope 校验，跨 host 候选被丢弃并计入解析错误。

解析层只产生 `parse_ok`、`parse_errors`、`empty` 或 `parse_error`；其中 `empty` 固定表示 `parse_ok=False, failure_kind="empty"`，代表进程完成但没有可解析候选。进程层产生以下固定 `failure_kind`：`unknown_tool`、`enterprise_policy`、`scope`、`arg`、`missing_resource`、`missing_binary`、`command_policy`、`timeout`、`cancelled`、`nonzero_exit`、`capture_unavailable`。公开字段的 `failure_kind` 是这两组值的并集，成功时为空字符串。`run_src_tool()` 将两层结果合并为公开 envelope；无 capture 时可退回解析有界 `result.output`，同时设置 `partial=True, remaining_unknown=True, failure_kind="capture_unavailable"`，禁止把该结果当作完整覆盖。

公开 envelope 的关键字段固定为：

```python
{
    "ok": process_ok and parse_ok and not remaining_unknown,
    "process_ok": bool,
    "parse_ok": bool,
    "failure_kind": str,
    "summary": SrcParseResult,
}
```

`empty` 表示进程成功但没有可解析候选，且按失败结果参与 Worker 工具失败计数；`nonzero_exit`/`timeout`/`cancelled` 表示进程层状态；它们不会被混写成“目标无漏洞”。

### `app/tools/executor.py`

- `run_src_tool()` 继续执行受限计划，在 capture 尚未 detach 前调用 `parse_src_capture()`，把 `SrcParseResult` 转成公开的有界 `summary`。
- 私有 `_capture` 保留合并后的 `output`、argv、退出码、超时和工具名；工具版本仅在命令自身明确返回时记录，不额外启动版本探测。
- 对企业模式先执行目录允许列表，再执行现有命令守卫；任意 `run_shell` 不作为 SRC CLI 的替代入口。
- 缺少二进制、超时、非零退出码分别返回 `failure_kind`，不返回空的成功结果；超时仍可携带已解析的部分候选和 `partial=True`。进程状态和解析状态分开返回：`process_ok`、`parse_ok`、`failure_kind`，顶层 `ok` 仅在两者均成功且有可用输出时为真。
- 所有 `http_request` 在发送前调用 `_enforce_scope(url, self.scope_target)`；redirect 由 executor 逐跳处理，最多 3 跳，每个 Location 先做同 host 校验。跨 host Location 只作为 `redirect_blocked` 元数据返回，不发送下一跳请求。
- `probe_http` schema 的 `follow_redirects` 默认改为 `false`，CLI 计划不传自动跟随参数；显式开启时由 executor 读取 Location 后逐跳重跑单 URL probe。Katana 使用基于当前 canonical host 的锚定 crawl scope；其它 SRC CLI 同样不启用工具自身的跨 host 自动跳转。

### `app/tools/guard.py` 与 `app/api/tasks.py`

- `guard.py` 增加 `check_enterprise_command(command: str, *, scope_target: str, allowed_parsers: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]`，返回校验后的 argv；executor 在企业模式用该 argv 和 `shell=False` 执行。允许的外部可执行文件只有 `curl`/`curl.exe`；允许参数为 `-s/-S/-i/-I/-X/-H/--data/--data-raw/--max-time/--connect-timeout`，URL 参数必须恰好一个且 host 与 `scope_target` 相同，`--max-time <= 30`、请求体 <= 16 KiB；`Host`/代理/解析覆盖类 Header 和 `--connect-to/--resolve` 均拒绝；`-L/--location`、配置文件、输出文件、shell 链接和命令替换均拒绝。解析器命令格式固定为 `python -m app.tools.local_parsers <json|headers|urlencode> --value <TEXT>`，`TEXT` 上限 16 KiB；`allowed_parsers` 保存三个固定模块前缀，用户不得传入脚本路径、文件路径或其它解释器参数。保留现有危险命令黑名单作为兜底。
- `tasks.py` 在任务 `running` 时拒绝 `src_type` 变更并返回 409；暂停后变更仍沿现有控制面取消和重新派发流程。

### `app/agents/worker.py`

- 初始化 `self._pending_leads: dict[str, Lead]`，保持现有 `target_meta` 和并发调用接口稳定。
- 维护 `self._workflow_stage`：普通路线初始为 `recon`，完成基线后进入 `locate`，出现高价值 pending lead 后进入 `verify`；带 `deepen_context` 或 `route_id="directed_deepen"` 的 Worker 直接从 `verify` 开始，初始 schema 不出现 recon/locate CLI。
- 在 `tool_src_cli_result` 返回后调用 `register_src_leads(result, scope_target, capture_id, round)`，把三个候选集合去重后转成 Lead；绝对 URL、重定向 URL 和 query 参数在登记前再次规范化、脱敏并检查 scope。
- 在 `http_request` 和 `compare_http_responses` 返回后调用 `resolve_leads()`；只结算与请求 endpoint、方法、参数和位置相符的线索，并记录对应捕获 ID。
- `_premature_finish_reason()` 增加高优先级 pending 线索检查：存在可验证的高价值线索时，返回具体下一动作；只有没有线索、线索已验证或明确失败时允许 `finish(no_vuln)`。
- 所有终止路径统一调用 `finalize_leads(reason, round)`，覆盖主动 `finish`、`_auto_finish`、最大轮数、连续无工具、连续失败、LLM error 和 cancel。高价值未结算线索进入可执行 `deepen_lead`；其余线索以带原因的 `skipped` 结算，终态不静默丢弃 pending。
- `evidence` 是提交单个 Finding 时的瞬时阶段：保存进入前的阶段，完成 `submit_finding` 后若仍有可验证线索回到 `verify`，否则回到 `locate`；因此同一 Worker 可继续发现并提交多个独立 Finding。

阶段回退规则固定为：

```python
if route_id == "directed_deepen" or deepen_context:
    initial_stage = "verify"
elif not baseline_done:
    initial_stage = "recon"
else:
    initial_stage = "locate"

after_submit = "verify" if actionable_leads() else "locate"
```
- WorkerResult 摘要增加有限的 `lead_summary`（pending/verified/failed/inconclusive/skipped 数量和最多 3 个值），不带敏感原文。

### `app/schemas.py`

给 `WorkerResult` 增加默认空值的 `lead_summary: dict`，只承载状态计数、最高优先级线索的脱敏值和结算原因；Finding、Reviewer 和数据库模型不增加字段。

线索状态转换：

```text
CLI candidate -> pending
pending --响应证明端点/参数/服务存在--> verified
pending --网络错误/超时/证据不足--> inconclusive
inconclusive --重试仍无结论且预算结束--> skipped
pending --404/410 且排除 soft-404，或参数基线确认无差异--> failed
pending --预算结束或策略关闭--> skipped
```

`verified` 只表示线索成立，不代表漏洞成立。401/403/405 证明端点存在时结算为 `verified` 并保留鉴权要求；404/410 只有在与 soft-404 基线比较后才结算为 `failed`；timeout/network 先进入 `inconclusive`，最多按 `MAX_VERIFY_ATTEMPTS=2` 重试。参数线索必须通过 baseline/candidate 的 `material_difference` 结算。所有终态写入 `resolution_reason`；“工具进程成功但没有候选”不进入 pending。高价值阈值固定为 `priority >= 8`，避免提示词与代码各自解释。

### `app/agents/playbook_router.py`

扩展 `RoutePlan`（序列可包含 SRC CLI、`analyze_javascript`、`http_request` 等已注册工作流工具）：

```python
tool_sequence: tuple[str, ...] = ()
```

每条现有路线只声明推荐顺序，不强制执行；空序列使用默认链路，未知 route ID 不自动扩大工具集合。例如：

- `spa_js_api`：`probe_http -> crawl_endpoints -> analyze_javascript -> http_request -> compare_http_responses`
- `generic_admin_api`：`probe_http -> discover_content -> http_request`
- `upload_business_idor`：`crawl_endpoints -> discover_parameters -> http_request -> compare_http_responses`
- `directed_deepen`：`http_request -> compare_http_responses`（不再回到泛发现）

`render_playbook_block()` 同时渲染“下一阶段工具”和每个工具的前置条件；Worker 仍保留自主选择权，但系统能在提示、测试和看板中解释推荐序列。`routes=()` 表示全路线，非空值只匹配上述精确 ID。

### `app/agents/history.py`

增加 SRC 专用摘要函数，保留：工具名、`process_ok`、`parse_ok`、`failure_kind`、`remaining_unknown`、候选总数、首 3 个候选、末 3 个候选、最高优先级候选、解析错误数和下一动作。旧响应截断时同时保留首尾候选，避免尾部 sentinel endpoint/parameter 丢失。

### `app/orchestrator.py`

- `_persist_worker_tool_event()` 在导入 `RawEvidence` 后，把 `SrcParseResult` 的有界摘要作为 capture preview 元数据保留，不新增表；Worker 结果中的 lead 结算由 `WorkerResult` 字段传递。
- Worker 在 CLI 执行前发 `tool_src_cli_started`，完成解析后发 `tool_src_cli_result`；`_update_live()` 分别展示“执行中”和阶段、工具名、候选数量、当前首要线索，不展示命令中的 Header、Cookie 或响应正文。
- Worker 完成事件带上 `lead_summary`，供路线卡片和深挖队列决定是否需要回炉。
- `public_worker_event()` 与 `_private_tool_preview()` 的 SRC 白名单包含 `summary`、`process_ok`、`parse_ok`、`failure_kind` 和脱敏候选；不把 `_capture`、Cookie、Header 或完整 output 放进公开事件。

### `app/tools/schemas.py` 与 Agent 可见性

schema 不再通过“整组追加”表达阶段权限。由 `tool_schemas_for(stage, role, enterprise, route_id)` 读取 `WORKFLOW_TOOL_STAGES` 和 `SRC_TOOL_CATALOG` 过滤；核心控制工具始终从 `ALWAYS_VISIBLE_TOOLS` 注入：

- `recon` 初始开放基线工具，同时保留 `http_request`、结束和报告类基础工具；
- `locate` 开放当前路线登记的发现工具；
- `verify` 暂时隐藏宽侦察工具，直到最高优先级 pending lead 结算；队列清空且预算允许时可回到 `locate`；
- `evidence` 只开放证据、查重、提交和结束所需工具；
- Escalate 只拿 `verify`/`evidence`，且只返回 `roles` 包含 `escalate` 的工具；`scan_nuclei`、`verify_xss` 的角色只有 `worker`，因此普通模式下也不会进入扩大危害阶段；
- 企业过滤先看 `enterprise_allowed`，再应用现有 `ENTERPRISE_BLOCKED_SRC_TOOLS` 兼容集合。

现有调用方仍可使用 `worker_tool_schemas()` 和 `escalate_tool_schemas()`；新增 `stage`、`role`、`route_id` 参数均有默认值，保持旧测试和外部调用兼容。schema 一致性测试要求每个 `SRC_TOOL_NAMES` 都有目录项、每个公开 schema 名称唯一，且 route sequence 中的名称可解析。

## 数据流

```text
RoutePlan.tool_sequence
        |
        v
Worker 选择 SRC CLI
        |
        +--> tool_src_cli_started -------> 看板执行中
        |
        +--> 私有 output capture --------> RawEvidence
        |
        +--> parse_src_capture -----------> Lead(pending)
        |                                   |
        +--> tool_src_cli_result ----------> LLM 历史/看板摘要
                                      |
                                      v
                         http_request / compare_http_responses
                                      |
                                      +--> Lead(verified/failed/inconclusive)
                                      +--> RawEvidence 关联
                                      +--> Finding / Reviewer / Escalate
```

线索只在当前 Worker 内存中流转；Worker 结束时把有界摘要写入 `WorkerResult.lead_summary`，并通过既有 coverage/事件交给后续 Worker。完整原文和 capture ID 继续保存在 `RawEvidence`，供证据 API、人工复核和审计读取；本期后续 Worker 不直接解析 RawEvidence 原文。

## 企业 SRC 策略

企业策略必须是三层一致的允许列表：

1. **schema 层**：隐藏 `enterprise_allowed=False` 工具。
2. **executor 层**：即使模型伪造工具名，也在 `run_src_tool()` 入口返回 `blocked`，不启动子进程。
3. **route 层**：企业路线的 `tool_sequence` 只产生允许工具；推荐序列里不出现 Nuclei、Dalfox 或同类扫描器。

企业可用链路示例：

```text
probe_http -> crawl_endpoints -> discover_parameters
           -> http_request -> compare_http_responses -> evidence
```

企业模式继续使用当前目标 scope；CLI 发现的绝对 URL 必须重新通过 `_enforce_scope()`。本期不放大 Killsweep 的全网资产范围，Escalate 也只接收已有 Finding 的验证上下文。

### `run_shell` 边界

`run_shell` 不属于 ToolSpec 的 SRC CLI 目录。企业 Worker 仍可使用它完成单请求或本地解析，但 executor 增加正向命令策略：只允许 `curl`/等价单请求命令和项目登记的解析脚本，禁止 shell 链接、重定向、后台驻留及任何未登记扫描器；现有危险命令守卫继续作为第二道防线。普通 EduSRC/靶场模式保持现有行为。

### 运行中策略切换

`src_type` 决定 schema 和 executor 权限，因此运行中的任务不接受 `src_type` 变更。更新接口在任务为 `running` 时返回 HTTP 409；用户暂停任务后再切换类型，旧 Worker 已由现有控制面取消，恢复时创建的新 Worker、Reviewer、Killsweep 和 Escalate 全部读取新策略。这样避免 EduSRC 启动快照在切换为企业模式后继续存活。

## 错误、预算与收敛

- `parse_src_output`/`parse_src_capture` 的格式错误只影响该次候选，私有原文仍可供人工复查。
- 二进制不存在时公开结果为 `ok=False, failure_kind="missing_binary"`，Worker 可切换到现有 HTTP 工具；不生成候选。
- 超时结果标为 `timeout`，保留已解析的部分候选，未完成的枚举不计为覆盖完成。
- 速率、线程、深度和字典限制继续由 `build_src_plan()` 强制；ToolSpec 的上限是第二道校验。
- Worker 达到 soft budget 时优先处理最高 `priority` 的 pending lead；没有预算或策略允许的验证动作时以 `skipped` 结算并在结果中说明。
- 工具连续失败仍沿用现有自动收敛计数，但“无候选失败”和“有候选未复核”分开统计，避免误把发现阶段失败当作无漏洞。
- `finalize_leads()` 在主动结束、自动收敛、最大轮数、LLM error 和 cancel 路径均执行；高价值 pending 生成 `deepen_lead` 或明确的 `skipped` 原因。

## 兼容与迁移

- `Task`、`Target`、`Finding`、`RawEvidence` 表结构保持现状。
- `RoutePlan.as_dict()` 新增 `tool_sequence`，旧消费者读取未知字段时保持兼容。
- `WorkerResult` 新增可选 `lead_summary` 字段；编排层只持久化计数、状态和最多 3 个脱敏值。
- `worker_tool_schemas()`、`escalate_tool_schemas()` 保留原签名，阶段过滤为可选参数。
- 没有 `summary` 的旧 CLI 结果按 `count=0` 处理；没有 `_capture` 的旧工具事件仍可进入历史摘要。
- 现有用户未启用 SRC CLI 时，Worker 的 HTTP/JS/证据流程和预算不变。
- 采用窄补丁保留并行改动：Worker 继续通过 `render_deepen_brief` 传递深挖上下文，executor 保留当前 Cookie/session 与 redirect 处理，orchestrator 保留 stop/drain 和私有证据任务的等待语义。

## 测试设计

### 解析与工具目录

- HTTPX JSON、Katana JSONL、FFUF JSON、Arjun 文本、wafw00f JSON 和 Nmap 服务输出均能得到候选、计数和下一动作。
- 尾部 sentinel 命中在历史压缩后仍可见；超出上限的候选正确计入 `omitted`。
- 坏 JSON 行、空 output、非零退出码、超时和缺少二进制都返回可区分的失败结果；超时部分候选保留 `partial=True`。
- 扫描上限内 `count/omitted` 精确；超过 64 MiB/50,000 行时 `remaining_unknown=True`，测试不对未扫描尾部候选数量作假设。
- `process_ok`、`parse_ok`、顶层 `ok` 和全部固定 `failure_kind` 有矩阵测试；合法零候选固定断言 `process_ok=True, parse_ok=False, ok=False, failure_kind="empty"`；缺少 capture 的回退结果标记 `capture_unavailable` 和不完整覆盖。
- 新增未登记 SRC CLI 默认不在任何 schema，executor 不启动它。
- 所有 `SRC_TOOL_NAMES` 均有目录项、所有公开 schema 名称唯一，route sequence 中的名称均能解析；伪造未知/禁用工具不会启动进程。
- 企业 `run_shell` 的正向命令策略拒绝 shell 链接、重定向、后台命令和未登记扫描器；普通模式回归行为保持不变。
- 企业 shell 允许的 curl 参数、单 host URL、请求体/超时上限和固定本地 parser argv 均有正反例测试；跨 host curl、`-L`、`-K`、输出文件和命令替换均在进程启动前被拒绝。
- 企业 schema、route 和 executor 三层都排除 `scan_nuclei`、`verify_xss` 及目录中标记为关闭的工具。
- 企业 Worker、Escalate、Killsweep 的间接调用和运行中 `src_type` 修改都覆盖允许列表与 HTTP 409 测试。

### Worker 生命周期

- 脚本化链路：SRC CLI 产生 endpoint/parameter -> `http_request` -> 响应对比 -> pending 清空 -> `finish(no_vuln)` 可通过。
- 高价值 pending 未验证时调用 finish 会返回 `premature_finish`，并给出具体验证动作。
- 范围外候选、重复候选和无效候选不进入 pending；失败工具不产生 synthetic lead；参数候选按 endpoint+location 去重。
- 401/403/405、soft-404、参数无差异、timeout/network 重试和 `MAX_VERIFY_ATTEMPTS=2` 的状态结算符合定义。
- 输入 URL 和每个 redirect Location 均经过 scope 校验；外部 Location 被记录但没有产生下一次网络请求，probe/crawler 不启用跨 host 自动跟随。
- 主动结束、自动收敛、最大轮数、LLM error、cancel 都执行 `finalize_leads()`，高价值未结算线索生成 deepen 或 skipped 原因。
- `directed_deepen` 从 verify 阶段启动且看不到 recon/locate 工具；提交一个 Finding 后阶段正确回退，同一 Worker 可继续提交第二个独立 Finding。
- verified lead 关联私有 capture ID，WorkerResult 只输出计数和短摘要。

### 历史、证据与看板

- CLI 合并 output 完整进入 `RawEvidence`，公开事件不含 Header、Cookie、敏感 query 值和响应正文；capture 导入失败仍保留可观察的失败事件。
- `tool_src_cli_started`/`tool_src_cli_result` 更新 live 状态，任务完成后状态可显示候选数量和 lead 结算。
- 旧 history compaction 对 SRC 输出保留首尾和最高优先级候选。
- 重定向/跨 host 候选被拒绝，公开 URL/query 经过脱敏；`_private_tool_preview` 保留 `summary` 与 `failure_kind`，不泄露私有字段。
- 现有 HTTP signal、Finding persistence、deepening 和 stop-search 队列测试保持通过。

### 回归

- 后端全量 `pytest` 通过。
- 前端既有单元测试和生产构建通过。
- `git diff --check` 通过。
- 不依赖本机安装 HTTPX/Katana/FFUF/Arjun 等二进制；缺失二进制路径使用固定 executor 测试替身验证失败语义。

## 分阶段交付

### 第一阶段（本期）

实现 ToolSpec、解析器、Worker pending lead、RoutePlan 工具序列、历史摘要、阶段 schema 过滤、企业三层一致性和端到端测试；首期数据库表结构保持现状。

### 第二阶段（后续）

根据第一阶段事件数据设计 `TargetArtifact` 持久化模型，将 endpoint、parameter、fingerprint、hypothesis 和 response_pair 关联到 `RawEvidence`，支持跨 Worker/重启复用，并补充清理、权限投影和迁移回滚策略。

## 验收标准

1. 至少一条现有 playbook 路线能按 `tool_sequence` 完成“CLI 发现 -> HTTP 复核 -> 证据结算”。
2. CLI 输出中的高价值尾部命中不会因历史压缩丢失。
3. Worker 不会在高价值线索未复核时静默 `finish(no_vuln)`。
4. 企业模式只暴露并执行允许列表工具，Nuclei/Dalfox 类工具三层均不可达。
5. 缺少二进制、超时、解析错误和范围拒绝都有可观察且不造假的结果。
6. 现有后端、前端和构建回归全部通过，工作区其他并发改动不被覆盖。
