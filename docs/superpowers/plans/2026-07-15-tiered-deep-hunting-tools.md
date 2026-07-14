# Tiered Deep Hunting Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add structured evidence-analysis tools and make every accepted severity tier follow an explicit, bounded deep-hunting policy.

**Architecture:** Put pure response/OpenAPI analysis in `app/tools/evidence.py` and expose it through the existing function-calling schema and executor boundaries. URL-backed analyzers fetch the complete bounded response inside `ToolExecutor`, preserving raw capture metadata while returning bounded summaries to the LLM. Put severity normalization, budgets, retry caps, priorities, and objectives in `app/agents/depth_policy.py`, then consume that policy from reviewer requeue, Worker round routing, and the escalation Hunter. Persist accepted-finding escalation work in `EscalationAttempt` so review commit, restart recovery, task budgets, and dispatch share one durable state machine.

**Tech Stack:** Python 3.12, Pydantic, SQLAlchemy, pytest, existing LLM function-calling abstractions.

---

### Task 1: Structured evidence tools

**Files:**
- Create: `app/tools/evidence.py`
- Modify: `app/tools/executor.py`
- Modify: `app/tools/schemas.py`
- Modify: `app/agents/worker.py`
- Modify: `app/agents/escalate.py`
- Test: `tests/test_deep_hunting_tools.py`

- [x] **Step 1: Write failing tests**

Cover response comparison with JSON-path changes and volatile-field suppression, OpenAPI endpoint extraction/ranking, schema registration, and Worker/Hunter dispatch.

- [x] **Step 2: Verify RED**

Run: `.venv\Scripts\python.exe -m pytest -q tests\test_deep_hunting_tools.py`

Expected: collection/import failure because `app.tools.evidence` and the new tool names do not exist.

- [x] **Step 3: Implement pure analyzers**

Add:

```python
def compare_http_responses(baseline: dict, candidate: dict, ignore_json_paths: list[str] | None = None) -> dict: ...
def analyze_api_schema(document: str, base_url: str = "", focus: list[str] | None = None) -> dict: ...
def extract_http_surface(body: str, base_url: str = "", response_headers: dict | None = None) -> dict: ...
def analyze_auth_material(request_headers: dict | None = None, response_headers: dict | None = None, body: str = "") -> dict: ...
```

Return bounded structured summaries, never a vulnerability verdict. Add `ToolExecutor` wrappers and all four dispatch names to both Worker and EscalateHunter.

For OpenAPI and HTML larger than the LLM preview, allow `analyze_api_schema(url=...)` and `extract_http_surface(url=...)` to fetch up to `WORKER_HTTP_MAX_BYTES` internally and retain the resulting `_capture` descriptor.

- [x] **Step 4: Verify GREEN**

Run: `.venv\Scripts\python.exe -m pytest -q tests\test_deep_hunting_tools.py`

Expected: all tests pass.

### Task 2: Severity-tier depth policy

**Files:**
- Create: `app/agents/depth_policy.py`
- Modify: `app/agents/deepen.py`
- Modify: `app/agents/worker.py`
- Modify: `app/agents/prompts.py`
- Modify: `app/agents/escalate.py`
- Modify: `app/orchestrator.py`
- Test: `tests/test_depth_policy.py`

- [x] **Step 1: Write failing tests**

Specify normalized policies for low/medium/high/critical severity, increasing reviewer requeue caps and Worker soft-round budgets, per-tier escalation rounds/objectives, and accepted-finding escalation at every valid tier.

- [x] **Step 2: Verify RED**

Run: `.venv\Scripts\python.exe -m pytest -q tests\test_depth_policy.py`

Expected: collection/import failure because `app.agents.depth_policy` does not exist.

- [x] **Step 3: Implement and integrate the policy**

Expose:

```python
@dataclass(frozen=True)
class DepthPolicy:
    severity: str
    deepen_cap: int
    priority_bonus: float
    soft_round_ratio: float
    escalation_rounds: int
    objective: str
    evidence_requirements: tuple[str, ...]

def depth_policy_for(severity: str | None) -> DepthPolicy: ...
```

Persist the policy snapshot in `Target.deepen_context`, respect configured hard Worker caps, and let the escalation Hunter use the per-tier objective and round budget. Keep escalation output behind the existing significance gate.

- [x] **Step 4: Verify GREEN**

Run: `.venv\Scripts\python.exe -m pytest -q tests\test_depth_policy.py`

Expected: all tests pass.

### Task 3: Documentation and regression verification

**Files:**
- Modify: `.env.example`
- Modify: `README.md`

- [x] **Step 1: Document behavior**

Describe the four new tools, tier budgets, the `ESCALATE_MAX_ROUNDS` override, and the fact that hard Worker budget caps remain authoritative.

- [x] **Step 2: Run focused regressions**

Run: `.venv\Scripts\python.exe -m pytest -q tests\test_deep_hunting_tools.py tests\test_depth_policy.py tests\test_llm_consumers.py tests\test_missed_signal_runtime.py`

- [x] **Step 3: Run the full backend suite**

Run: `.venv\Scripts\python.exe -m pytest -q tests`

- [x] **Step 4: Self-review**

Inspect `git diff --check`, `git diff --stat`, and the complete diff for duplicated schemas, unbounded outputs, leaked capture descriptors, accidental changes to configured hard caps, or escalation recursion.

### Task 4: Durable escalation queue and task budgets

**Files:**
- Create: `app/escalation_service.py`
- Modify: `app/db/models.py`
- Modify: `app/orchestrator.py`
- Modify: `app/api/tasks.py`
- Test: `tests/test_escalation_service.py`
- Test: `tests/test_task_deletion.py`
- Test: `tests/test_db_migrations.py`

- [x] **Step 1: Persist one attempt per accepted Finding**

Create the attempt in the same transaction as the accepted review, then dispatch only after commit. Record `queued`, `running`, `succeeded`, `skipped`, and `failed` outcomes.

- [x] **Step 2: Recover interrupted attempts**

Requeue `running` attempts on cancellation or process startup and dispatch durable `queued` rows from the task loop.

- [x] **Step 3: Enforce task-level budgets**

Use `ESCALATE_TASK_MAX_ATTEMPTS` and `ESCALATE_TASK_ROUND_BUDGET`; preserve budget-exhausted rows as `skipped` audit records.

- [x] **Step 4: Cover lifecycle behavior**

Test idempotent queueing, claim/finalize/recovery, accepted-review transaction ordering, cancellation requeue, runtime dispatch, migration, and task deletion.
