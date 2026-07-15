# SRC Toolchain Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the registered SRC CLI tools into a staged discovery-to-evidence workflow with normalized candidates, pending-lead verification, and fail-closed enterprise policy.

**Architecture:** Keep command construction in `app/tools/src_toolkit.py`, add a pure parser/catalog layer there, and isolate lead identity/state transitions in `app/agents/src_leads.py`. Worker owns the in-memory lead queue and workflow stage; `RoutePlan` supplies recommendations, while schema filtering and executor checks enforce the same catalog. Existing `RawEvidence` remains the private full-fidelity store; no database migration is introduced.

**Tech Stack:** Python 3.11, FastAPI, Pydantic, SQLAlchemy async sessions, pytest, existing `ToolExecutor` capture spool, OpenAI-compatible function schemas.

---

## File Map

- Create: `app/agents/src_leads.py` — candidate normalization, Lead identity/state transitions, final summaries.
- Modify: `app/tools/src_toolkit.py` — `ToolSpec`, catalog, bounded parsers, capture parsing, redirect-safe plans.
- Modify: `app/tools/guard.py` — enterprise command tokenizer/allowlist returning validated argv.
- Modify: `app/tools/executor.py` — parser invocation, process/parse envelope, scope-aware HTTP and shell execution.
- Modify: `app/tools/schemas.py` — workflow stage/role registry and stage-aware schema selection.
- Modify: `app/agents/playbook_router.py` — `RoutePlan.tool_sequence` and route-specific sequences.
- Modify: `app/agents/history.py` — SRC head/tail/priority summaries and failure metadata.
- Modify: `app/agents/worker.py` — lead queue, stage transitions, CLI events, finalization on every exit path.
- Modify: `app/schemas.py` — optional `WorkerResult.lead_summary`.
- Modify: `app/orchestrator.py` — live CLI projections, private preview fields, result persistence.
- Modify: `app/api/tasks.py` — running-task `src_type` lock.
- Modify: `README.md` — staged workflow and scenario matrix.
- Test: `tests/test_src_toolkit.py`, `tests/test_enterprise_prompt_policy.py`, `tests/test_raw_evidence.py`, `tests/test_llm_consumers.py`, `tests/test_task_operations_api.py`.
- Create: `tests/test_src_leads.py`, `tests/test_src_workflow.py`.

## Task 1: Add the Pure Lead State Module

**Files:**
- Create: `app/agents/src_leads.py`
- Create: `tests/test_src_leads.py`

- [ ] **Step 1: Write failing identity and state tests**

```python
def test_parameter_identity_includes_endpoint_and_location():
    a = SrcCandidate("parameter", "GET https://a.test/users", "id", "GET", "id", "query", None, .8, 8, "arjun")
    b = SrcCandidate("parameter", "GET https://a.test/orders", "id", "GET", "id", "query", None, .8, 8, "arjun")
    assert lead_key(a) != lead_key(b)


def test_timeout_retries_then_skips():
    candidate = SrcCandidate("endpoint", "GET https://a.test/api", "/api", "GET", "", "path", 200, .9, 9, "katana")
    lead = Lead.from_candidate(candidate, round_no=1, capture_id="cap-1")
    resolve_lead(lead, outcome="timeout", round_no=2, evidence_id="cap-2")
    assert lead.status == "inconclusive"
    resolve_lead(lead, outcome="timeout", round_no=3, evidence_id="cap-3")
    assert lead.status == "skipped"


def test_403_verifies_endpoint_without_claiming_a_vulnerability():
    candidate_403 = SrcCandidate("endpoint", "GET https://a.test/admin", "/admin", "GET", "", "path", 403, .9, 8, "ffuf")
    lead = Lead.from_candidate(candidate_403, round_no=1, capture_id="cap-1")
    resolve_lead(lead, outcome="verified", round_no=2, evidence_id="cap-2")
    assert lead.status == "verified"
    assert lead.vulnerability_confirmed is False
```

- [ ] **Step 2: Run the focused test and verify the missing-module failure**

Run: `python -m pytest tests/test_src_leads.py -q`

Expected: collection reports `ModuleNotFoundError: No module named 'app.agents.src_leads'`.

- [ ] **Step 3: Implement the bounded state module**

Implement frozen `SrcCandidate` and mutable `Lead` with `sources`, `capture_ids`, `attempt_count`, `last_attempt_round`, `resolution_reason`, and `vulnerability_confirmed=False`. Expose:

Start the module with `from collections import Counter`, `from dataclasses import dataclass`, and `from typing import Iterable` so the shown summary implementation is directly runnable.

```python
def lead_key(candidate: SrcCandidate) -> tuple[str, str, str, str, str]:
    return (candidate.kind, candidate.endpoint_key, candidate.method, candidate.parameter, candidate.location)


def merge_candidate(lead: Lead, candidate: SrcCandidate, capture_id: str, source_tool: str) -> Lead:
    lead.sources = tuple(dict.fromkeys((*lead.sources, source_tool)))
    lead.capture_ids = tuple(dict.fromkeys((*lead.capture_ids, capture_id)))
    lead.confidence = max(lead.confidence, candidate.confidence)
    lead.priority = max(lead.priority, candidate.priority)
    return lead


def resolve_lead(lead: Lead, *, outcome: str, round_no: int, evidence_id: str = "", reason: str = "") -> Lead:
    lead.attempt_count += 1
    lead.last_attempt_round = round_no
    if outcome in {"timeout", "network", "insufficient"}:
        lead.status = "skipped" if lead.attempt_count >= 2 else "inconclusive"
    else:
        lead.status = outcome
    lead.resolution_reason = reason or outcome
    if evidence_id:
        lead.evidence_ids = tuple(dict.fromkeys((*lead.evidence_ids, evidence_id)))
    return lead


@dataclass(frozen=True)
class LeadSummary:
    counts: dict[str, int]
    deepen_lead: str
    samples: tuple[str, ...]


def finalize_leads(leads: Iterable[Lead], *, reason: str, round_no: int, high_priority: int = 8) -> LeadSummary:
    items = list(leads)
    actionable = [lead for lead in items if lead.priority >= high_priority and lead.status in {"pending", "inconclusive"}]
    for lead in items:
        if lead.status in {"pending", "inconclusive"}:
            lead.status = "skipped"
            lead.last_attempt_round = round_no
            lead.resolution_reason = reason
    counts = Counter(lead.status for lead in items)
    deepen = actionable[0].verify_action if actionable else ""
    samples = tuple(lead.value[:160] for lead in items[:3])
    return LeadSummary(counts=dict(counts), deepen_lead=deepen, samples=samples)
```

Use `verified` for endpoint/parameter existence, `failed` only for explicit negative evidence, `inconclusive` for timeout/network/insufficient evidence, and `skipped` after the second inconclusive attempt or budget exhaustion. Merge duplicates by `(kind, endpoint_key, method, parameter, location)` and bound all public values.

- [ ] **Step 4: Run tests and commit**

Run: `python -m pytest tests/test_src_leads.py -q`

Expected: all lead identity, merge, retry, and finalization tests pass.

```powershell
git add app/agents/src_leads.py tests/test_src_leads.py
git commit -m "feat: add SRC lead state machine"
```

## Task 2: Add the SRC Catalog and Output Parsers

**Files:**
- Modify: `app/tools/src_toolkit.py`
- Modify: `tests/test_src_toolkit.py`

- [ ] **Step 1: Write failing parser/catalog tests**

Cover HTTPX JSON, Katana JSONL, FFUF JSON, Arjun text, wafw00f JSON, and Nmap service output. Assert every `SRC_TOOL_NAMES` entry has a `ToolSpec`, scanner candidates have `roles=("worker",)` and `enterprise_allowed=False`, and empty output has `parse_ok=False, failure_kind="empty"`.

```python
def test_parser_preserves_head_tail_and_priority():
    output = "\n".join(json.dumps({"url": f"https://a.test/api/{i}", "status_code": 200}) for i in range(8))
    parsed = parse_src_output("crawl_endpoints", output)
    assert parsed.count == 8
    assert parsed.head_candidates[0].value.endswith("/0")
    assert parsed.tail_candidates[-1].value.endswith("/7")
```

- [ ] **Step 2: Run the focused tests and verify the missing API failure**

Run: `python -m pytest tests/test_src_toolkit.py -k "parser or catalog" -q`

Expected: missing attributes for `ToolSpec`, `SRC_TOOL_CATALOG`, and `parse_src_output`.

- [ ] **Step 3: Implement normalized parsers and catalog**

Add `ToolSpec`, `SrcCandidate`, `SrcParseResult`, and `SRC_TOOL_CATALOG`. Implement a shared bounded normalizer. The pure parser reads text; `parse_src_capture(tool, capture, scope_target)` streams the private `output` channel and applies scope filtering before admitting URL candidates. Scan up to 64 MiB/50,000 lines, retain head 3, tail 3, and priority 3, and set `remaining_unknown=True` when the scan limit is reached. `empty` is always `parse_ok=False`; `parse_error` is used when malformed output has no usable candidate. Add `next_actions` per tool.

Change `probe_http` plans to avoid automatic redirects. Keep the legacy flag for compatibility, but same-host redirect handling belongs to the executor. Add Nmap service-line parsing and canonical endpoint values with query values removed.

- [ ] **Step 4: Run the existing SRC suite and commit**

Run: `python -m pytest tests/test_src_toolkit.py -q`

Expected: new parser/catalog tests and all existing bounded argv tests pass.

```powershell
git add app/tools/src_toolkit.py tests/test_src_toolkit.py
git commit -m "feat: normalize SRC tool output"
```

## Task 3: Enforce Scope, Redirect, and Enterprise Shell Policy

**Files:**
- Modify: `app/tools/guard.py`
- Modify: `app/tools/executor.py`
- Modify: `tests/test_enterprise_prompt_policy.py`
- Modify: `tests/test_raw_evidence.py`

- [ ] **Step 1: Write failing command and redirect tests**

Test same-host curl success; cross-host URL, `-L`, `-K`, output files, `Host`/proxy/resolve flags, shell metacharacters, and unregistered parser arguments raise `CommandBlocked`. Add an HTTP test proving an external `Location` is recorded without a second request.

- [ ] **Step 2: Run focused tests and verify failure**

Run: `python -m pytest tests/test_enterprise_prompt_policy.py tests/test_raw_evidence.py -k "enterprise or redirect" -q`

Expected: missing `check_enterprise_command` or an assertion that the current shell path accepts a forbidden command.

- [ ] **Step 3: Implement the positive enterprise command parser**

Implement:

```python
def check_enterprise_command(command: str, *, scope_target: str, allowed_parsers: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    tokens = _tokenize_command(command)
    if _is_allowed_curl(tokens):
        _validate_curl_tokens(tokens, scope_target)
    else:
        _validate_parser_tokens(tokens, allowed_parsers)
    return tuple(tokens)
```

Tokenize once, reject shell operators, permit only `curl`/`curl.exe` or fixed `python -m app.tools.local_parsers <json|headers|urlencode> --value TEXT`, enforce one same-host URL, bounded timeout/body, and safe headers. Make enterprise `ToolExecutor.run_shell()` execute returned argv with `shell=False`; keep `check_command()` as defense in depth.

- [ ] **Step 4: Merge process and parse status into one envelope**

Update `run_src_tool()` to return `process_ok`, `parse_ok`, top-level `ok`, `failure_kind`, and `summary`. Use the fixed failure set from the spec. Register partial candidates even when process status is timeout/nonzero, while top-level `ok` remains false. When full capture is absent, parse the bounded preview and mark `partial=True, remaining_unknown=True, failure_kind="capture_unavailable"`.

- [ ] **Step 5: Add scope-aware HTTP and CLI redirect handling**

Add `_enforce_scope_url()` to `ToolExecutor`; call it before every `http_request`. Disable automatic redirects, inspect `Location`, and follow only same-host redirects for at most three hops. Set `redirect_blocked=True` for an external Location. Ensure probe/Katana plans use an anchored same-host scope.

- [ ] **Step 6: Run tests and commit**

Run: `python -m pytest tests/test_enterprise_prompt_policy.py tests/test_raw_evidence.py -q`

Expected: existing scanner blocks and new allowlist/redirect/capture tests pass.

```powershell
git add app/tools/guard.py app/tools/executor.py tests/test_enterprise_prompt_policy.py tests/test_raw_evidence.py
git commit -m "feat: enforce SRC scope and enterprise shell policy"
```

## Task 4: Add Workflow Catalog and Route Sequences

**Files:**
- Modify: `app/tools/schemas.py`
- Modify: `app/agents/playbook_router.py`
- Modify: `tests/test_src_toolkit.py`
- Modify: `tests/test_llm_consumers.py`

- [ ] **Step 1: Write failing stage/role visibility tests**

Assert recon exposes baseline tools, locate exposes route-registered discovery tools, verify hides broad discovery while a lead is actionable, Escalate excludes `scan_nuclei`/`verify_xss`, and enterprise filters every `enterprise_allowed=False` tool. Assert public schema names are unique and each SRC name has a catalog entry.

- [ ] **Step 2: Run visibility tests and verify failure**

Run: `python -m pytest tests/test_src_toolkit.py tests/test_llm_consumers.py -k "stage or schema or escalate" -q`

Expected: missing `tool_schemas_for` or assertions showing the current all-tools behavior.

- [ ] **Step 3: Implement stage/role selection**

Add `WORKFLOW_TOOL_STAGES`, `ALWAYS_VISIBLE_TOOLS`, and:

```python
def tool_schemas_for(stage: str, role: str, *, enterprise: bool = False, route_id: str = "") -> list[dict]:
    names = _allowed_tool_names(stage, role, enterprise=enterprise, route_id=route_id)
    return [schema for schema in _ALL_SCHEMAS if _schema_name(schema) in names]
```

Keep `worker_tool_schemas()` and `escalate_tool_schemas()` compatibility wrappers. Give scanner candidates the worker role only and apply the SRC allowlist before the legacy enterprise block set.

- [ ] **Step 4: Add route sequences and commit**

Extend `RoutePlan` with `tool_sequence=()`, update `as_dict()` and `_build_plan()`, and assign exact IDs `spa_js_api`, `generic_admin_api`, `upload_business_idor`, and `directed_deepen`. Unknown route IDs use the default sequence without broadening visibility.

Run: `python -m pytest tests/test_src_toolkit.py tests/test_llm_consumers.py -k "stage or schema or route or escalate" -q`

Expected: all stage/role and route sequence tests pass.

```powershell
git add app/tools/schemas.py app/agents/playbook_router.py tests/test_src_toolkit.py tests/test_llm_consumers.py
git commit -m "feat: add staged SRC tool visibility"
```

## Task 5: Integrate Leads and Stages into Worker

**Files:**
- Modify: `app/agents/worker.py`
- Modify: `app/schemas.py`
- Create: `tests/test_src_workflow.py`

- [ ] **Step 1: Write a failing scripted Worker test**

Use a fake LLM sequence: `crawl_endpoints` returns one endpoint candidate, `http_request` returns 403 for that endpoint, then `finish(no_vuln)`. Assert finish succeeds only after the lead is verified. Add an unverified priority-9 lead case returning `kind="premature_finish"`, and a submit → second-Finding case proving stage recovery.

- [ ] **Step 2: Run the workflow test and observe failure**

Run: `python -m pytest tests/test_src_workflow.py -q`

Expected: missing `lead_summary`, lead registration, or premature-finish enforcement.

- [ ] **Step 3: Extend `WorkerResult` and initialize state**

Add `lead_summary: dict = Field(default_factory=dict)` to `app/schemas.py`. In `Worker.__init__`, initialize `_pending_leads`, `_workflow_stage`, `_stage_before_evidence`, and route ID. Start `verify` for `deepen_context`/`directed_deepen`; otherwise start `recon`.

- [ ] **Step 4: Register and resolve candidates**

After a successful SRC result, call `register_src_leads(result, scope_target, capture_id, round)`. After `http_request`/`compare_http_responses`, call `resolve_leads()` using status, material difference, URL, method, parameter, and capture ID. Use `priority >= 8` as the actionable threshold.

- [ ] **Step 5: Make schemas and finish checks stage-aware**

Pass stage, role, enterprise flag, and route ID into `tool_schemas_for()`. `_premature_finish_reason()` blocks high-priority pending or retryable inconclusive leads and returns the next `verify_action`. `submit_finding` enters transient evidence, then returns to verify when actionable leads remain or locate otherwise.

- [ ] **Step 6: Finalize every exit path**

Call `finalize_leads()` before explicit finish, cancel, LLM error, no-tool auto-finish, repeated failures, and max-round exhaustion. High-priority unresolved leads become `deepen_lead`; remaining leads become `skipped` with a reason. Preserve `render_deepen_brief`, duplicate checks, coverage, and existing cancellation semantics.

- [ ] **Step 7: Run workflow tests and commit**

Run: `python -m pytest tests/test_src_leads.py tests/test_src_workflow.py tests/test_llm_consumers.py -q`

Expected: scripted CLI → HTTP → lead settlement, premature finish, directed deepen, and multi-Finding tests pass.

```powershell
git add app/agents/worker.py app/schemas.py tests/test_src_workflow.py
git commit -m "feat: connect SRC leads to Worker lifecycle"
```

## Task 6: Persist Summaries and Live CLI Events

**Files:**
- Modify: `app/agents/history.py`
- Modify: `app/orchestrator.py`
- Modify: `tests/test_raw_evidence.py`
- Modify: `tests/test_src_workflow.py`

- [ ] **Step 1: Write failing summary/event tests**

Build a large SRC result with a tail sentinel and assert history compaction retains head, tail, priority, `failure_kind`, and `remaining_unknown`. Assert `tool_src_cli_started` and `tool_src_cli_result` update live state without exposing headers, cookies, query values, or capture paths.

- [ ] **Step 2: Run focused tests and observe failure**

Run: `python -m pytest tests/test_raw_evidence.py tests/test_src_workflow.py -k "history or cli or live or redaction" -q`

Expected: tail sentinel is absent or live action remains generic because the current code only handles the pre-execution event.

- [ ] **Step 3: Implement bounded history and preview fields**

Add SRC compression for scalar status, head/tail/priority samples, counts, parse errors, and next actions. Extend `_private_tool_preview()` with `summary`, `process_ok`, `parse_ok`, and `failure_kind`; keep `_capture` private.

- [ ] **Step 4: Implement event projections and result persistence**

Emit `tool_src_cli_started` before process execution and `tool_src_cli_result` after parsing. Update `_update_live()` for both. Include `lead_summary` in `worker_finish` and `_persist_worker_result`; retain raw capture import and stop/drain waiting behavior.

- [ ] **Step 5: Run evidence/live tests and commit**

Run: `python -m pytest tests/test_raw_evidence.py tests/test_src_workflow.py -q`

Expected: capture persistence, redaction, tail preservation, and live CLI state tests pass.

```powershell
git add app/agents/history.py app/orchestrator.py tests/test_raw_evidence.py tests/test_src_workflow.py
git commit -m "feat: expose normalized SRC evidence events"
```

## Task 7: Lock Runtime `src_type` Changes

**Files:**
- Modify: `app/api/tasks.py`
- Modify: `tests/test_task_operations_api.py`

- [ ] **Step 1: Write the failing API test**

Create a running `Task(src_type="edusrc")`, PATCH `src_type="enterprise"`, and assert HTTP 409. Set the same task to paused and assert the update succeeds.

- [ ] **Step 2: Run the test and verify current behavior fails**

Run: `python -m pytest tests/test_task_operations_api.py -k "src_type or running" -q`

Expected: the current update endpoint accepts the running-task change.

- [ ] **Step 3: Implement the state guard**

In `update_task()`, check `task.status == "running"` before assigning `req.src_type`; raise `HTTPException(status_code=409, detail="运行中的任务需暂停后切换 SRC 模式")`. Keep other update fields and transaction behavior unchanged.

- [ ] **Step 4: Run API tests and commit**

Run: `python -m pytest tests/test_task_operations_api.py -q`

Expected: new running/paused cases and existing task operation tests pass.

```powershell
git add app/api/tasks.py tests/test_task_operations_api.py
git commit -m "fix: lock SRC policy while task is running"
```

## Task 8: Document Scenarios and Run Full Verification

**Files:**
- Modify: `README.md`
- Modify: `tests/test_enterprise_prompt_policy.py`
- Modify: `tests/test_src_toolkit.py`

- [ ] **Step 1: Add documentation assertions**

Assert README contains the staged workflow, CLI-to-HTTP handoff, enterprise allowlist, same-host redirect rule, and scenario table. Keep the existing enterprise exclusion of Nuclei-like scanners.

- [ ] **Step 2: Update usage documentation**

Add this concise matrix:

| 场景 | 首选链路 | 结束条件 |
| --- | --- | --- |
| SPA/API | `probe_http → crawl_endpoints → analyze_javascript → http_request` | 高价值端点已复核 |
| 后台/目录 | `probe_http → discover_content → http_request` | 命中已排除软 404 |
| 隐藏参数 | `discover_parameters → baseline → compare_http_responses` | 参数差异已结算 |
| 企业 SRC | `crawl_endpoints → discover_parameters → http_request` | 只有单请求/证据工具 |

Document that CLI output is a candidate map rather than a Finding, and define `tool_src_cli_started/result` event meanings.

- [ ] **Step 3: Run targeted and full backend verification**

Run:

```powershell
python -m pytest tests/test_src_toolkit.py tests/test_src_leads.py tests/test_src_workflow.py tests/test_enterprise_prompt_policy.py tests/test_task_operations_api.py tests/test_raw_evidence.py tests/test_llm_consumers.py -q
python -m pytest -q
```

Expected: focused tests pass first, then the full backend suite passes with no new failures.

- [ ] **Step 4: Run frontend/build checks**

Run `npm test` and `npm run build` in `frontend/`; verify both pass because the only response addition is optional `lead_summary`.

- [ ] **Step 5: Review the final diff and commit documentation**

Run: `git diff --check; git status --short; git diff --stat c4e5be0..HEAD`

Confirm concurrent files remain present and only the listed integration files changed for this feature. Commit README/test assertion updates separately:

```powershell
git add README.md tests/test_enterprise_prompt_policy.py tests/test_src_toolkit.py
git commit -m "docs: describe staged SRC tool workflow"
```

## Plan Self-Review

- Catalog, parser, scope, redirect, process/parse envelope, lead lifecycle, stages, enterprise policy, runtime policy lock, events, documentation, and regression tests each have an explicit task.
- `empty` is fixed as `parse_ok=False, failure_kind="empty"`; `remaining_unknown` distinguishes bounded scans from complete parses.
- `directed_deepen` starts in `verify`; `evidence` is transient so one Worker can submit multiple Findings.
- Existing `render_deepen_brief`, Cookie/session, redirect handling, stop/drain persistence, and private capture ownership are named compatibility boundaries.
- No database migration or `TargetArtifact` persistence is included.
