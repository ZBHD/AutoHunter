# Prompt Release 灰度治理 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 建立代码内不可变 Prompt Release、脱敏离线行为回放、目标级 10% 实时灰度、硬门槛自动晋升和回滚，并保持旧 profile/API 兼容。

**Architecture:** `app/agents/prompt_releases.py` 是唯一 release 注册表和渲染入口；`app/prompt_experiments.py` 负责分组、样本、指标与状态机；`app/prompt_replay.py` 使用脚本化工具结果执行真实 LLM 行为回放。目标在 `_pop_queued()` 的领取事务中固定 release，LLM usage context 同时累计原任务看板和目标样本，Stable 指针通过 `SystemSettings.defaults` compare-and-set 切换。

**Tech Stack:** Python 3.11+、SQLAlchemy async、SQLite、FastAPI、pytest、Vue 3、Node test runner、Vite。

---

### Task 1: 不可变 Prompt Release 注册表与控制面指纹

**Files:**
- Create: `app/agents/prompt_releases.py`
- Create: `tests/test_prompt_releases.py`
- Modify: `app/agents/prompts.py`

- [ ] **Step 1: 写 release 解析、不可变性和指纹失败测试**

测试必须断言：四个 release ID 唯一且符合 `worker-YYYY-MM-DD-rN`；dataclass 不可修改；`current`/空值解析调用方提供的 Stable；`legacy`/`modern` 固定解析；未知 alias 只回 Stable；不可晋升兼容 release 被拒绝；同一 release 指纹稳定，prompt、policy、playbook 或 schema 任一控制面变化都会改变指纹。

```python
def test_current_and_unknown_alias_resolve_only_to_stable() -> None:
    stable = "worker-2026-07-15-r1"
    assert resolve_prompt_release("current", stable_release_id=stable).release_id == stable
    assert resolve_prompt_release("unknown", stable_release_id=stable).release_id == stable


def test_compatibility_aliases_are_fixed() -> None:
    assert resolve_prompt_release("legacy", stable_release_id=CANDIDATE_RELEASE_ID).base_profile == "legacy"
    assert resolve_prompt_release("modern", stable_release_id=CANDIDATE_RELEASE_ID).base_profile == "modern"


def test_fingerprint_covers_rendered_prompt_playbook_and_tool_schema(monkeypatch) -> None:
    release = get_prompt_release(COMPILED_STABLE_RELEASE_ID)
    baseline = prompt_release_fingerprint(release)
    monkeypatch.setattr(prompt_releases, "CONTROL_SURFACE_VERSION", "worker-control-v2-test")
    assert prompt_release_fingerprint(release) != baseline
```

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_releases.py`

Expected: collection fails with `ModuleNotFoundError: app.agents.prompt_releases`。

- [ ] **Step 3: 实现注册表和唯一渲染入口**

定义并注册以下常量：

```python
LEGACY_RELEASE_ID = "worker-2026-06-25-r1"
COMPILED_STABLE_RELEASE_ID = "worker-2026-07-15-r1"
MODERN_RELEASE_ID = "worker-2026-07-15-r2"
CANDIDATE_RELEASE_ID = "worker-2026-07-27-r1"
CONTROL_SURFACE_VERSION = "worker-control-v1"

@dataclass(frozen=True)
class PromptRelease:
    release_id: str
    label: str
    base_profile: str
    prompt_revision: str
    policy_revision: str
    playbook_revision: str
    tool_schema_revision: str
    promotable: bool
```

`prompt_release_fingerprint()` 对以下规范化 JSON 做 SHA-256：release 字段、edusrc/enterprise 两类 `worker_system_prompt()` 渲染结果、候选条件策略常量、`worker_tool_schemas()` 在 recon/verify 与 JS on/off 下的 schema、`CONTROL_SURFACE_VERSION`。序列化使用 `sort_keys=True, separators=(",", ":")`。

`get_prompt_release()` 对缺失具体 ID 抛 `UnknownPromptReleaseError`；`resolve_prompt_release()` 的 alias 规则严格为：`legacy/old/20260625/2026-06-25 -> LEGACY`，`modern/full -> MODERN`，具体 release ID 原样解析，其余值包括 `current/compact/now/空/未知 -> stable_release_id`。

- [ ] **Step 4: 运行 release 与现有 profile 回归**

Run: `python -m pytest -q tests/test_prompt_releases.py tests/test_prompt_profiles.py tests/test_prompt_eval_script.py`

Expected: PASS。

- [ ] **Step 5: 提交注册表**

```powershell
git add app/agents/prompt_releases.py app/agents/prompts.py tests/test_prompt_releases.py
git commit -m "功能：建立不可变提示词 Release 注册表"
```

### Task 2: Candidate 条件化 SSRF/XXE/反序列化/JWT 路线

**Files:**
- Modify: `app/agents/prompt_releases.py`
- Modify: `app/agents/worker.py`
- Create: `tests/test_prompt_candidate_routes.py`

- [ ] **Step 1: 写信号命中和无信号不注入测试**

```python
@pytest.mark.parametrize(("signal", "heading"), [
    ("callback_url webhook preview image import proxy", "SSRF"),
    ("SOAP XML Office 富文本导入", "XXE"),
    ("Shiro Fastjson ViewState Dubbo Java serialization", "反序列化"),
    ("JWT Authorization Bearer", "Token/身份边界"),
])
def test_candidate_injects_only_matching_short_route(signal: str, heading: str) -> None:
    block = render_candidate_route_block(get_prompt_release(CANDIDATE_RELEASE_ID), signal)
    assert heading in block
    assert len(block) < 1800


def test_stable_and_signal_free_candidate_add_no_route() -> None:
    assert render_candidate_route_block(get_prompt_release(COMPILED_STABLE_RELEASE_ID), "web home") == ""
    assert render_candidate_route_block(get_prompt_release(CANDIDATE_RELEASE_ID), "web home") == ""
```

增加 Worker 测试，断言 release ID 为 Candidate 时 `_playbook_block()` 包含命中的短路线；Stable 与兼容 release 不包含。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_candidate_routes.py`

Expected: FAIL because `render_candidate_route_block` and Worker release wiring are absent。

- [ ] **Step 3: 实现四条短路线和 Worker 注入**

`render_candidate_route_block(release, signal_text)` 仅在 `release.release_id == CANDIDATE_RELEASE_ID` 时匹配大小写不敏感信号并渲染。四条路线分别包含设计中的最低证据要求，并明确报错、仅接收 XML、指纹/报错、仅解码 JWT 均不构成漏洞。

Worker 新增参数并保持旧调用兼容：

```python
prompt_release_id: str | None = None,
prompt_cohort: str = "",
```

构造时具体 ID 优先；缺失时从旧 `prompt_version` 经编译期 Stable 解析。`_playbook_block()` 合并现有 playbook 和 Candidate 条件块，signal text 由 target URL、title、priority_reason、route ID/tags、现有 playbook、deepen context 构成。

- [ ] **Step 4: 运行 Candidate、Worker 与企业策略测试**

Run: `python -m pytest -q tests/test_prompt_candidate_routes.py tests/test_edusrc_prompt_policy.py tests/test_enterprise_prompt_policy.py tests/test_backdoor_prompt_policy.py`

Expected: PASS。

- [ ] **Step 5: 提交 Candidate 路线**

```powershell
git add app/agents/prompt_releases.py app/agents/worker.py tests/test_prompt_candidate_routes.py
git commit -m "功能：增加候选提示词条件化深挖路线"
```

### Task 3: 实验数据模型与老库迁移

**Files:**
- Modify: `app/db/models.py`
- Modify: `app/db/session.py`
- Modify: `tests/test_db_migrations.py`
- Create: `tests/test_prompt_experiment_models.py`

- [ ] **Step 1: 写模型约束和迁移失败测试**

测试新库创建 `prompt_experiments`、`prompt_experiment_samples`；Target 有三个 nullable 字段；实时样本 `(experiment_id,target_id)` 唯一；离线样本 `(experiment_id,case_id,release_id,run_number)` 唯一。老 `targets` 表执行 `init_db()` 后补齐：

```text
prompt_release_id VARCHAR(80)
prompt_experiment_id VARCHAR(32)
prompt_cohort VARCHAR(20)
```

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_experiment_models.py tests/test_db_migrations.py -k prompt`

Expected: FAIL due absent ORM classes and columns。

- [ ] **Step 3: 增加模型、关系和索引**

按设计文档逐字段实现 `PromptExperiment` 与 `PromptExperimentSample`。样本表使用两个 SQLite partial unique indexes：

```python
Index(
    "ux_prompt_samples_live_target", "experiment_id", "target_id",
    unique=True, sqlite_where=text("target_id IS NOT NULL"),
)
Index(
    "ux_prompt_samples_offline_run", "experiment_id", "case_id", "release_id", "run_number",
    unique=True, sqlite_where=text("case_id != '' AND run_number IS NOT NULL"),
)
```

在 `_MIGRATIONS` 增加三个 Target 字段，在 `_SECONDARY_INDEXES` 增加 release、experiment 索引。历史行不回填。

- [ ] **Step 4: 运行模型与完整迁移测试**

Run: `python -m pytest -q tests/test_prompt_experiment_models.py tests/test_db_migrations.py`

Expected: PASS。

- [ ] **Step 5: 提交模型**

```powershell
git add app/db/models.py app/db/session.py tests/test_db_migrations.py tests/test_prompt_experiment_models.py
git commit -m "功能：持久化提示词实验与目标 Release"
```

### Task 4: Stable 指针、兼容解析与缺失 release 诊断

**Files:**
- Modify: `app/settings_service.py`
- Create: `tests/test_prompt_release_settings.py`

- [ ] **Step 1: 写设置解析和回退失败测试**

覆盖：默认 Stable 为 `COMPILED_STABLE_RELEASE_ID`；可解析数据库具体 ID 优先；缺失数据库 ID 记录 error 后回编译期 Stable；旧任务 `legacy/modern` 固定；旧 `current` 任务跟随 Stable；public settings 返回 channel 和具体 Stable ID，但继续返回旧 `worker_prompt_version` 兼容字段。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_release_settings.py`

Expected: FAIL because stable release helpers are absent。

- [ ] **Step 3: 实现设置读取函数**

增加公开函数 `resolve_stable_prompt_release_id(defaults: dict[str, Any] | None = None) -> str` 和 `resolve_worker_prompt_release(task: Task | None = None) -> PromptRelease`。

`resolve_stable_prompt_release_id` 验证 registry；缺失时 `logger.error` 并返回编译期 Stable。`resolve_worker_prompt_version()` 保持兼容 facade，返回 release 的 `base_profile`。`public_settings_view().defaults` 增加 `worker_prompt_channel="stable"` 和 `stable_prompt_release_id`。

- [ ] **Step 4: 运行设置回归**

Run: `python -m pytest -q tests/test_prompt_release_settings.py tests/test_settings_service.py tests/test_prompt_profiles.py`

Expected: PASS。

- [ ] **Step 5: 提交 Stable 解析**

```powershell
git add app/settings_service.py tests/test_prompt_release_settings.py
git commit -m "功能：增加 Stable 提示词指针与兼容解析"
```

### Task 5: 目标级稳定分组与领取事务固定

**Files:**
- Create: `app/prompt_experiments.py`
- Modify: `app/orchestrator.py`
- Modify: `app/agents/worker.py`
- Modify: `tests/test_task_queue.py`
- Create: `tests/test_prompt_experiment_assignment.py`

- [ ] **Step 1: 写纯分组和领取固定失败测试**

定义测试矩阵：相同 seed/target 永远相同；`bucket = int.from_bytes(sha256(f"{seed}:{target_id}").digest()[:8], "big") % 10000`；`bucket < round(canary_percent * 100)` 进入 Candidate；已有 Target 三字段不改；固定 legacy/modern 任务为 `manual`；live 按 10% 分组；promoted 的 48 小时内新 Stable 90%、旧 Stable holdback 10%；无活动实验全部 Stable。

并发领取测试启动两个 session 调 `_pop_queued()`，断言仅一个领取成功且三字段只写一次。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_experiment_assignment.py tests/test_task_queue.py -k "prompt or concurrent"`

Expected: FAIL because assignment service and Target writes are absent。

- [ ] **Step 3: 实现 PromptAssignment 和领取接入**

```python
@dataclass(frozen=True)
class PromptAssignment:
    release_id: str
    experiment_id: str = ""
    cohort: str = "stable"
```

公开接口固定为 `cohort_bucket(seed: str, target_id: str) -> int` 和 `assignment_for_target(session, task, target, *, now=None) -> PromptAssignment`。

`_pop_queued()` 在构造原子 `update(Target).values(...)` 前计算 assignment，并把三字段放进同一 values。`_run_worker()` 对升级前遗留 assigned/scanning 且未固定的 Target 调同一函数并 commit；随后将固定的 `prompt_release_id/prompt_cohort` 传给 Worker。Worker start event 增加两字段。

- [ ] **Step 4: 运行领取、Worker 和重启恢复测试**

Run: `python -m pytest -q tests/test_prompt_experiment_assignment.py tests/test_task_queue.py tests/test_src_workflow.py`

Expected: PASS。

- [ ] **Step 5: 提交目标固定**

```powershell
git add app/prompt_experiments.py app/orchestrator.py app/agents/worker.py tests/test_prompt_experiment_assignment.py tests/test_task_queue.py
git commit -m "功能：在目标领取事务固定提示词灰度分组"
```

### Task 6: 不可变 UsageContext 与实时样本落库

**Files:**
- Modify: `app/llm/usage.py`
- Modify: `app/llm/client.py`
- Modify: `app/llm/router.py`
- Modify: `app/settings_service.py`
- Modify: `app/orchestrator.py`
- Modify: `app/prompt_experiments.py`
- Create: `tests/test_prompt_experiment_usage.py`

- [ ] **Step 1: 写双层 usage 与终态样本失败测试**

```python
context = UsageContext(
    task_id="task-1", target_id="target-1", experiment_id="exp-1",
    release_id=CANDIDATE_RELEASE_ID, cohort="candidate",
)
record_usage(context, "model", prompt_tokens=10, completion_tokens=5, total_tokens=15)
assert usage_snapshot("task-1")["total_tokens"] == 15
assert target_usage_snapshot("target-1")["total_tokens"] == 15
```

测试 `finalize_live_sample()` 幂等创建实时样本，持久化 verdict、rounds、tool exception/协议错误计数、route、finding 数和 usage；`pop_target_usage()` 释放目标计数且不清任务聚合；usage 缺失时 `usage_complete=false`。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_experiment_usage.py`

Expected: FAIL because UsageContext and sample finalization do not exist。

- [ ] **Step 3: 实现 usage context 与目标终态 hook**

在 `app/llm/usage.py` 增加 frozen `UsageContext`、独立 `_TARGET_USAGE`、`target_usage_snapshot()`、`pop_target_usage()`；`record_usage()` 对字符串保持旧任务行为，对 context 同时写 task/target。

`llm_router_for_task(task, *, usage_context=None)` 将 context 传给 `LLMRouter/LLMClient`。`_run_worker()` 使用 Target 固定字段构造 context。目标持久化为 done/skipped/dead 后调用 `finalize_live_sample(session, target, result, usage)`，只在 target 有实验 ID 时写样本，且不存 raw request/response、Cookie、Authorization 或 prompt 正文。

- [ ] **Step 4: 运行 usage、LLM 和 orchestrator 回归**

Run: `python -m pytest -q tests/test_prompt_experiment_usage.py tests/test_llm_consumers.py tests/test_task_operations_api.py`

Expected: PASS。

- [ ] **Step 5: 提交样本采集**

```powershell
git add app/llm/usage.py app/llm/client.py app/llm/router.py app/settings_service.py app/orchestrator.py app/prompt_experiments.py tests/test_prompt_experiment_usage.py
git commit -m "功能：采集目标级提示词实验用量与结果"
```

### Task 7: 指标聚合、硬门槛和自动状态机

**Files:**
- Modify: `app/prompt_experiments.py`
- Create: `tests/test_prompt_experiment_metrics.py`
- Create: `tests/test_prompt_experiment_state_machine.py`

- [ ] **Step 1: 写指标边界和状态转换失败测试**

覆盖全部边界：7 天、每臂 100 终态、Candidate 5 task/3 route/20 人工样本；分母 0 为 insufficient；`usage_complete=false` 不计成本；3 个连续完整日才晋升；非连续日不晋升；即时禁止行为/证据串线/协议错误令 live failed、promoted rollback；连续 2 窗口终止率 +2pp、驳回率 +5pp、证据闭环 -2pp 回滚；48 小时无回归 completed。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_experiment_metrics.py tests/test_prompt_experiment_state_machine.py`

Expected: FAIL because metric/window/state functions are absent。

- [ ] **Step 3: 实现纯指标函数和 PromptExperimentService**

实现纯函数 `aggregate_samples(samples) -> dict[str, Any]`、`evaluate_offline_gate(stable, candidate) -> GateDecision`、`evaluate_live_eligibility(experiment, samples, *, now) -> GateDecision`、`evaluate_daily_window(stable, candidate) -> GateDecision`。`PromptExperimentService` 提供 async `recompute(session, *, now=None)`、`promote(session, experiment, metrics, *, now=None)` 和 `rollback(session, experiment, reason, *, now=None)`。

`GateDecision` 必须包含 `passed: bool`、`reason: str`、`metrics: dict`、`insufficient: list[str]`。每日窗口只按 `finished_at` 完整 UTC 自然日。晋升/回滚对 `SystemSettings.defaults` 使用带 `SystemSettings.defaults == expected_defaults` 谓词的 SQLAlchemy `update()` compare-and-set，并检查 `rowcount == 1`；失败记录冲突，绝不覆盖维护者设置。成功后 `refresh_cache(session)`。

- [ ] **Step 4: 运行指标和设置并发回归**

Run: `python -m pytest -q tests/test_prompt_experiment_metrics.py tests/test_prompt_experiment_state_machine.py tests/test_prompt_release_settings.py`

Expected: PASS。

- [ ] **Step 5: 提交状态机**

```powershell
git add app/prompt_experiments.py tests/test_prompt_experiment_metrics.py tests/test_prompt_experiment_state_machine.py
git commit -m "功能：实现提示词实验硬门槛与自动回滚"
```

### Task 8: 脱敏 fixture 加载器与真实 LLM 行为回放

**Files:**
- Create: `app/prompt_replay.py`
- Create: `tests/fixtures/prompt_replay/ssrf.json`
- Create: `tests/fixtures/prompt_replay/xxe.json`
- Create: `tests/fixtures/prompt_replay/deserialization.json`
- Create: `tests/fixtures/prompt_replay/jwt.json`
- Create: `tests/test_prompt_replay.py`

- [ ] **Step 1: 写 schema、脱敏、顺序与网络封锁失败测试**

fixture 必填字段与设计一致。测试拒绝重复 case ID、真实域名/IP、`Authorization: Bearer`、Cookie、`sk-` key、手机号、身份证号；允许 `[TARGET]`、`[ACCOUNT_A]`、`[TOKEN_A]`。测试 seed 生成 Stable/Candidate 交错顺序且每案例每 release 恰好 3 次；未声明工具、脚本结果耗尽或工具参数含非占位外部 URL 时记录 forbidden action；所有 assistant tool call 必须产生配对 tool result。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_replay.py`

Expected: FAIL because replay loader and runner are absent。

- [ ] **Step 3: 实现 ReplayFixture 与 PromptReplayRunner**

```python
@dataclass(frozen=True)
class ReplayFixture:
    schema_version: int
    case_id: str
    src_type: str
    route_id: str
    initial_context: dict[str, Any]
    scripted_tool_results: dict[str, tuple[dict[str, Any], ...]]
    allowed_tools: tuple[str, ...]
    forbidden_tools: tuple[str, ...]
    expected_terminal_verdicts: tuple[str, ...]
    required_evidence: tuple[str, ...]
    max_rounds: int
    max_total_tokens: int
    historical_human_outcome: str
```

Runner 使用 `render_worker_prompt(release, src_type)` 和 Worker schema 调真实 `LLMRouter.chat()`，但工具调度只从 fixture 队列取结果。终态仅接受 fixture 声明的 verdict；结果转 `PromptExperimentSample(phase="offline")`。按 `sha256(seed:case_id:run_number:release_id)` 排序执行，禁止任何 `ToolExecutor` 或目标网络依赖。

- [ ] **Step 4: 运行回放与静态契约测试**

Run: `python -m pytest -q tests/test_prompt_replay.py tests/test_prompt_eval_script.py`

Expected: PASS。

- [ ] **Step 5: 提交回放器与 fixtures**

```powershell
git add app/prompt_replay.py tests/fixtures/prompt_replay tests/test_prompt_replay.py
git commit -m "功能：增加脱敏历史提示词行为回放"
```

### Task 9: 实验创建、离线门槛与运维 CLI

**Files:**
- Modify: `app/prompt_experiments.py`
- Create: `scripts/manage_prompt_experiment.py`
- Create: `tests/test_prompt_experiment_cli.py`

- [ ] **Step 1: 写 start/status/report/cancel/rollback 失败测试**

测试 `start` 拒绝不可晋升/与 Stable 不一致/已有 active 实验，创建 `offline` 后先运行 100% 静态契约检查再运行行为回放，门槛通过转 `live`、失败转 `failed`；`status` 输出门槛缺口；`report` JSON 仅含 release、fixture ID、聚合指标；`cancel` 不改 Stable；`rollback` 只接受 promoted；失败命令非零退出码。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_experiment_cli.py`

Expected: FAIL because CLI does not exist。

- [ ] **Step 3: 实现服务入口和 argparse CLI**

命令保持设计接口：

```powershell
python scripts/manage_prompt_experiment.py start --candidate worker-2026-07-27-r1 --canary-percent 10
python scripts/manage_prompt_experiment.py status
python scripts/manage_prompt_experiment.py report --format json --out artifacts/prompt-experiment.json
python scripts/manage_prompt_experiment.py cancel --reason "停止本轮候选"
python scripts/manage_prompt_experiment.py rollback --reason "人工触发回滚"
```

脚本启动时依次 `init_db()`、`init_settings_cache()`；`start` 先复用 `scripts.evaluate_prompts` 的契约案例校验 Candidate 渲染结果，再读取当前 Provider 创建 replay router；输出路径父目录自动创建；报告通过白名单字段构造，禁止 ORM `__dict__` 直出。

- [ ] **Step 4: 运行 CLI 及脚本直启测试**

Run: `python -m pytest -q tests/test_prompt_experiment_cli.py`

Expected: PASS。

- [ ] **Step 5: 提交 CLI**

```powershell
git add app/prompt_experiments.py scripts/manage_prompt_experiment.py tests/test_prompt_experiment_cli.py
git commit -m "功能：提供提示词实验运维命令"
```

### Task 10: 事件重算与启动恢复

**Files:**
- Modify: `app/main.py`
- Modify: `app/orchestrator.py`
- Modify: `app/api/findings.py`
- Modify: `app/api/missed_signals.py`
- Modify: `app/prompt_experiments.py`
- Create: `tests/test_prompt_experiment_hooks.py`

- [ ] **Step 1: 写 hook 和恢复失败测试**

测试目标终态、人工 passed/rejected、归档恢复、missed signal 转换/拒绝后各调用一次 `recompute()`；启动恢复 Candidate 缺失令 offline/live failed；promoted 新 Stable 缺失时依次回 previous Stable、编译期 Stable；无新数据不重复生成窗口。

- [ ] **Step 2: 运行测试确认 RED**

Run: `python -m pytest -q tests/test_prompt_experiment_hooks.py`

Expected: FAIL because lifecycle hooks are absent。

- [ ] **Step 3: 接入重算与恢复**

新增顶层 async 函数 `recompute_active_prompt_experiment(session: AsyncSession) -> None` 和 `recover_prompt_experiments(session: AsyncSession) -> None`。

hook 均在业务事务 commit 后调用；重算异常记录 logger，不把用户已成功的审核/恢复请求回滚。`main.lifespan` 在 `init_settings_cache()` 后、恢复任务前使用独立 session 调 `recover_prompt_experiments()`。

- [ ] **Step 4: 运行 hook、API 与启动测试**

Run: `python -m pytest -q tests/test_prompt_experiment_hooks.py tests/test_escalation_service.py tests/test_killsweep_service.py tests/test_app_imports.py`

Expected: PASS。

- [ ] **Step 5: 提交生命周期接入**

```powershell
git add app/main.py app/orchestrator.py app/api/findings.py app/api/missed_signals.py app/prompt_experiments.py tests/test_prompt_experiment_hooks.py
git commit -m "功能：接入提示词实验自动重算与启动恢复"
```

### Task 11: 移除普通前端 profile 控制并保留 API 兼容

**Files:**
- Modify: `frontend/src/views/CreateView.vue`
- Modify: `frontend/src/components/TaskEditModal.vue`
- Modify: `frontend/src/views/SettingsView.vue`
- Modify: `frontend/tests/promptDefaults.test.js`
- Modify: `tests/test_task_model_config.py`

- [ ] **Step 1: 写前后端兼容失败测试**

前端静态测试断言三处不再包含 Worker 提示词 select，不再从新建/编辑/设置 payload 主动发送 `prompt_version`/`worker_prompt_version`。后端测试继续断言旧 create/patch payload 可写和读 `prompt_version=legacy/modern`。

- [ ] **Step 2: 运行测试确认 RED**

Run: `node --test frontend/tests/promptDefaults.test.js && python -m pytest -q tests/test_task_model_config.py`

Expected: frontend test FAIL because selectors and payload fields still exist；backend compatibility remains PASS。

- [ ] **Step 3: 删除普通 UI 控制和主动写入**

从三个 Vue 文件删除表单字段、settings hydrate、payload 字段和 select 模板。不得删除 `app/api/dto.py` 的兼容字段，不得删除 `app/api/tasks.py` 的读取/patch 逻辑。设置摘要可显示只读 `stable_prompt_release_id`，不提供切换控件。

- [ ] **Step 4: 运行前端全测和构建**

Run:

```powershell
node --test frontend/tests/*.test.js
npm run build --prefix frontend
python -m pytest -q tests/test_task_model_config.py tests/test_prompt_release_settings.py
```

Expected: PASS。

- [ ] **Step 5: 提交前端兼容调整**

```powershell
git add frontend/src/views/CreateView.vue frontend/src/components/TaskEditModal.vue frontend/src/views/SettingsView.vue frontend/tests/promptDefaults.test.js tests/test_task_model_config.py
git commit -m "功能：普通任务统一使用 Stable 提示词通道"
```

### Task 12: 完整回归、隐私检查与运维文档

**Files:**
- Modify: `README.md`
- Verify all changed files

- [ ] **Step 1: 补充 CLI 运维说明**

README 仅记录 release 不可变原则、五条 CLI、自动门槛、48 小时 holdback、回滚语义和报告不含 secrets/raw evidence；不在普通用户流程暴露实验开关。

- [ ] **Step 2: 运行 Prompt Release 专项测试**

Run:

```powershell
python -m pytest -q tests/test_prompt_releases.py tests/test_prompt_candidate_routes.py tests/test_prompt_experiment_models.py tests/test_prompt_release_settings.py tests/test_prompt_experiment_assignment.py tests/test_prompt_experiment_usage.py tests/test_prompt_experiment_metrics.py tests/test_prompt_experiment_state_machine.py tests/test_prompt_replay.py tests/test_prompt_experiment_cli.py tests/test_prompt_experiment_hooks.py
```

Expected: PASS。

- [ ] **Step 3: 运行后端全量回归**

Run: `python -m pytest -q`

Expected: 基线 1102 项加全部新增测试通过，仅允许既有 Starlette `httpx` 弃用警告。

- [ ] **Step 4: 运行前端全量测试、构建和 Python 编译检查**

```powershell
node --test frontend/tests/*.test.js
npm run build --prefix frontend
python -m compileall -q app scripts
```

Expected: 全部 PASS，Vite build 成功。

- [ ] **Step 5: 检查隐私、diff 和工作区**

```powershell
rg -n "Authorization: Bearer [A-Za-z0-9]|Cookie:|sk-[A-Za-z0-9]" tests/fixtures/prompt_replay
git diff --check
git status --short
git log --oneline origin/main..HEAD
```

Expected: fixture secret scan 无输出；diff check 无输出；仅 README 有待提交变更；提交历史均为中文。

- [ ] **Step 6: 提交文档**

```powershell
git add README.md
git commit -m "文档：补充提示词灰度治理运维流程"
```

- [ ] **Step 7: 最终核验分支**

Run:

```powershell
git status --short --branch
git diff --check origin/main...HEAD
git log --oneline origin/main..HEAD
```

Expected: 工作树干净，分支只领先 `origin/main`，无未提交或无关文件。
