# Task Findings, Missed Signals, and Killsweep Operations Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add navigable scanned/raw-finding task views, a persistent cross-task missed-signal workflow, and a fully auditable killsweep operations center while preserving complete tool evidence separately from LLM previews.

**Architecture:** Keep the existing FastAPI/SQLAlchemy/Vue structure and add two focused API domains (`missed_signals`, `killsweeps`) plus a shared chunked raw-evidence store. Tool execution becomes dual-channel: bounded previews continue to the LLM, while full bytes spool to disk and are imported into SQLite chunks. Existing task endpoints remain compatible; new list endpoints use server pagination and never include raw chunks.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy async/SQLite, Pydantic, Vue 3 Composition API, Vue Router, Node test runner, Vite.

---

### Task 1: Persistent Operations Schema and Migrations

**Files:**
- Modify: `app/db/models.py`
- Modify: `app/db/session.py`
- Modify: `tests/test_db_migrations.py`
- Create: `tests/test_operations_models.py`

- [ ] **Step 1: Write failing schema and migration tests**

```python
def test_operations_tables_and_indexes_exist():
    names = inspect_database_tables_and_indexes()
    assert {"missed_signals", "missed_signal_events", "missed_signal_drafts"} <= names.tables
    assert {"raw_evidence", "raw_evidence_chunks"} <= names.tables
    assert {"killsweep_attempts", "killsweep_events"} <= names.tables
    assert "ux_killsweeps_task_product" not in names.indexes
```

Also assert legacy `killsweeps.status='done'` is mapped to `succeeded`, legacy rows expose `legacy_without_timeline`, and a source Finding can own only one non-legacy case.

- [ ] **Step 2: Run the tests and verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_db_migrations.py tests/test_operations_models.py -q`

Expected: FAIL because the operations tables and new lifecycle columns do not exist.

- [ ] **Step 3: Add models**

Add `MissedSignal`, `MissedSignalEvent`, `MissedSignalDraft`, `RawEvidence`, `RawEvidenceChunk`, `KillsweepAttempt`, `KillsweepEvent`, and `KillsweepReanalysisBatch`. Evolve `Killsweep` into a source-Finding case with separate automatic/manual verdict fields. Add nullable `Target.killsweep_case_id` for queued derived-target cancellation.

Required states:

```text
MissedSignal: pending | deepening | converted | rejected
Draft: generating | ready | failed | confirmed
Killsweep case: queued | running | succeeded | failed
Attempt: queued | running | succeeded | failed | cancelled
Automatic verdict: pending_validation | killsweep | not_killsweep
Manual verdict: confirmed | not_killsweep | invalid
Raw evidence: writing | complete | partial | failed | legacy_partial
```

- [ ] **Step 4: Extend lightweight migrations and indexes**

Drop the old unique product index, create a normal product lookup index, add a conditional unique source-Finding index, add active-attempt uniqueness, and add `schema_migrations` for idempotent legacy data transforms.

- [ ] **Step 5: Run schema tests and full backend tests**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_db_migrations.py tests/test_operations_models.py -q`

Expected: PASS.

Run: `.\.venv\Scripts\python.exe -m pytest -q`

Expected: all tests pass.

### Task 2: Full Evidence Dual Channel

**Files:**
- Modify: `app/tools/executor.py`
- Create: `app/raw_evidence.py`
- Create: `tests/test_raw_evidence.py`

- [ ] **Step 1: Write failing capture tests**

```python
def test_shell_full_capture_survives_preview_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(executor, "_SHELL_CAPTURE_MAX_BYTES", 32)
    result = ToolExecutor("capture", work_dir=tmp_path, capture_full=True).run_shell(long_output_command())
    assert len(result["output"]) < len(read_capture_bytes(result["_capture"]))
    assert read_capture_bytes(result["_capture"]) == expected_output

def test_http_full_capture_survives_preview_limit(...):
    assert reconstructed_response_bytes == upstream_response_bytes
```

Cover non-UTF-8 bytes, partial/cancelled captures, SHA-256, chunk ordering, and idempotent spool import.

- [ ] **Step 2: Run and verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_raw_evidence.py -q`

Expected: FAIL because `capture_full` and chunk import do not exist.

- [ ] **Step 3: Implement bounded previews plus full spool files**

For shell, write every stdout/stderr byte to a capture file while keeping only the existing bounded preview in memory. For HTTP, continue consuming the complete response stream into a capture file while retaining the current bounded body preview for the model. Return a private `_capture` descriptor that callers must remove before serializing tool results to the LLM or WebSocket.

- [ ] **Step 4: Implement chunk import and streaming reconstruction**

Import fixed 1 MiB chunks into `raw_evidence_chunks`, calculate per-channel sizes/hashes, commit short batches, mark final status, then remove the spool only after completion. Provide helpers that stream a channel in sequence without assembling it in memory.

- [ ] **Step 5: Verify evidence tests and backend suite**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_raw_evidence.py -q`

Expected: PASS.

### Task 3: Missed-Signal Detection and State Service

**Files:**
- Create: `app/missed_signals.py`
- Modify: `app/agents/worker.py`
- Modify: `app/schemas.py`
- Modify: `app/orchestrator.py`
- Create: `tests/test_missed_signal_service.py`

- [ ] **Step 1: Write failing detector and upsert tests**

```python
def test_generic_http_200_is_not_a_signal(): ...
def test_sensitive_endpoint_requires_response_evidence(): ...
def test_login_success_requires_session_or_token(): ...
def test_upload_success_requires_write_method_and_returned_path(): ...
def test_exception_and_secret_rules_create_signals(): ...
def test_same_evidence_increments_hit_and_changed_evidence_reopens_rejected(): ...
```

Also cover archived Review, actionable `deepen_lead`, coverage gaps, and successful Finding conversion.

- [ ] **Step 2: Run and verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_missed_signal_service.py -q`

Expected: FAIL because the detector/service does not exist.

- [ ] **Step 3: Implement deterministic detection**

Use strict path/response combinations for `login_success`, `upload_success`, `token_exposure`, `sensitive_endpoint`, and `exception_leak`. Canonicalize endpoints by method, host, path, and query parameter names. Do not classify a generic 200 or SPA fallback page.

- [ ] **Step 4: Implement transactional upsert and audit**

Deduplicate by task/target/rule/canonical endpoint. Same evidence hash increments `hit_count`; a new hash appends evidence and reopens only rejected records. Append immutable status/audit events for every transition.

- [ ] **Step 5: Wire runtime sources**

After each Worker tool call, remove `_capture` from the LLM result and emit a private persistence event. In orchestrator transactions create signals from tool evidence, ignored/deepen reviews, actionable deepen leads, and coverage gaps. Mark matching candidates converted when a real Finding is persisted.

- [ ] **Step 6: Verify service tests**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_missed_signal_service.py -q`

Expected: PASS.

### Task 4: Missed-Signal API, Drafts, and Deepening

**Files:**
- Create: `app/api/missed_signals.py`
- Create: `app/missed_signal_prompts.py`
- Modify: `app/main.py`
- Modify: `app/waf.py`
- Modify: `app/api/tasks.py`
- Create: `tests/test_missed_signal_api.py`
- Create: `tests/test_task_deletion.py`

- [ ] **Step 1: Write failing API tests**

Test stats/list pagination and ordering, observer denial, readonly raw streaming, reject/restore, deepen limit 10, persistent optimistic-lock drafts, LLM failure retention, idempotent confirmation, and task deletion cleanup.

```python
response = client.get("/api/missed-signals?status=pending&limit=50&offset=0")
assert response.json().keys() >= {"items", "total", "has_more", "limit", "offset"}
assert "raw_evidence_chunks" not in response.text
```

- [ ] **Step 2: Run and verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_missed_signal_api.py tests/test_task_deletion.py -q`

Expected: FAIL with missing routes.

- [ ] **Step 3: Add read/action endpoints**

Implement `/api/missed-signals`, `/stats`, detail/evidence metadata, streamed evidence channel, deepen, reject, restore, draft get/generate/update/confirm. Lists are compact and paginated. Observer remains denied by the existing allowlist; readonly can perform GET only.

- [ ] **Step 4: Add the dedicated no-tool draft prompt**

Generate JSON fields for a Finding from stored evidence only. Reuse owner, same-request/response, reproducible PoC, impact, and kill-chain rules. Missing facts become `missing_evidence`; the model may not issue network/tool calls or invent steps.

- [ ] **Step 5: Confirm draft into the human review queue**

Create `Finding(status='reviewed', worker_id='missed_signal')` and `Review(verdict='accepted', confidence='uncertain', user_status='pending')` atomically, then mark the signal/draft converted/confirmed. Preserve raw evidence independently.

- [ ] **Step 6: Add limited startup backfill**

Idempotently import current ignored/deepen Findings as `legacy_partial`; do not infer missing tool output.

- [ ] **Step 7: Verify API and deletion tests**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_missed_signal_api.py tests/test_task_deletion.py -q`

Expected: PASS.

### Task 5: Killsweep Case, Attempts, Timeline, and Batch Reanalysis

**Files:**
- Create: `app/killsweep_service.py`
- Create: `app/api/killsweeps.py`
- Modify: `app/agents/killsweep.py`
- Modify: `app/orchestrator.py`
- Modify: `app/api/findings.py`
- Modify: `app/main.py`
- Create: `tests/test_killsweep_service.py`
- Create: `tests/test_killsweep_api.py`

- [ ] **Step 1: Write failing lifecycle tests**

```python
def test_human_pass_persists_queued_attempt_before_dispatch(): ...
def test_missing_fofa_and_missing_llm_finish_attempt_as_failed(): ...
def test_unverified_positive_is_pending_validation(): ...
def test_retry_appends_attempt_without_overwriting_history(): ...
def test_batch_selects_oldest_allowed_cases_and_caps_at_40(): ...
```

Cover complete tool timeline/evidence, manual verdict coexistence, queued derived-target cancellation, process restart, and legacy rows.

- [ ] **Step 2: Run and verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_killsweep_service.py tests/test_killsweep_api.py -q`

Expected: FAIL because attempts/events/global APIs do not exist.

- [ ] **Step 3: Implement transactional queue/claim/finalize**

Human pass creates a case and queued attempt in the same transaction. Dispatcher atomically claims queued attempts. Every exit path (missing config, LLM error, timeout, cancellation, unexpected exception) finalizes the attempt and case with a persisted error event.

- [ ] **Step 4: Persist tool results in sequence**

The Hunter emits post-call FOFA/HTTP/shell events. Store summaries/payloads in `killsweep_events`; import complete request/response/command/output through `RawEvidence` without exposing raw values over WebSocket.

- [ ] **Step 5: Implement manual and retry behavior**

Manual verdicts never overwrite automatic verdicts or statistics. Negative verdicts cancel only queued derived targets. Reanalysis appends attempts. Batch selection accepts current filters, allowed states only, oldest failure first, maximum 40.

- [ ] **Step 6: Implement global and compatibility APIs**

Add global stats/list/detail/events/manual-review/reanalysis endpoints and preserve `/api/tasks/{task_id}/killsweeps` as a compatibility wrapper.

- [ ] **Step 7: Restore pending attempts and make stop/delete await cleanup**

On startup, fail stale running attempts with `process_restart` and dispatch queued attempts. Await killsweep tasks before task deletion to prevent post-delete writes.

- [ ] **Step 8: Verify lifecycle/API tests**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_killsweep_service.py tests/test_killsweep_api.py -q`

Expected: PASS.

### Task 6: Scanned Targets and Raw Findings Task Contracts

**Files:**
- Modify: `app/api/tasks.py`
- Modify: `app/api/findings.py`
- Create: `tests/test_task_operations_api.py`

- [ ] **Step 1: Write failing endpoint tests**

Assert terminal targets include `done/dead/skipped`, include `finding_count`, use server pagination/search, and target detail includes related compact Findings. Assert raw Finding lists exclude `superseded` by default and compact mode omits raw evidence.

- [ ] **Step 2: Run and verify RED**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_task_operations_api.py -q`

Expected: FAIL on response contract/counts.

- [ ] **Step 3: Implement compatible list/detail contracts**

Keep old array behavior when pagination parameters are absent; return the standard page envelope when `compact=true` or `limit/offset` are supplied. Make board `done` represent all terminal targets.

- [ ] **Step 4: Verify endpoint tests**

Run: `.\.venv\Scripts\python.exe -m pytest tests/test_task_operations_api.py -q`

Expected: PASS.

### Task 7: Frontend API Helpers, Navigation, Preferences, and Tests

**Files:**
- Modify: `frontend/src/api.js`
- Create: `frontend/src/operations.js`
- Create: `frontend/src/theme.js`
- Modify: `frontend/src/main.js`
- Modify: `frontend/src/App.vue`
- Modify: `frontend/src/views/TasksView.vue`
- Modify: `frontend/src/views/SettingsView.vue`
- Modify: `frontend/src/style.css`
- Create: `frontend/tests/operations.test.js`

- [ ] **Step 1: Write failing pure/helper wiring tests**

Test query creation, page normalization, status labels, independent Markdown filenames/download selection, route/nav presence, observer visibility, and settings event wiring.

- [ ] **Step 2: Run and verify RED**

Run: `npm test -- --run`

Expected: new tests fail because routes/helpers do not exist.

- [ ] **Step 3: Implement API and helper modules**

Expose all new task/missed/killsweep endpoints. Add stable pure functions for page envelopes, state presentation, filenames, and sequential independent Markdown downloads.

- [ ] **Step 4: Rebuild navigation and settings access**

Desktop/mobile navigation becomes Task, Missed, Killsweep, Settings. Hide sensitive operations pages from observers. Put full-only New Task in the task-page header. Move token/theme and GitHub/About into Settings; non-full roles render only personal settings and do not request system configuration.

- [ ] **Step 5: Verify frontend tests**

Run: `npm test -- --run`

Expected: PASS.

### Task 8: Task Board Scanned/Raw/Killsweep Views

**Files:**
- Modify: `frontend/src/views/BoardView.vue`
- Modify: `frontend/src/report.js`
- Modify: `frontend/src/style.css`
- Modify: `frontend/tests/operations.test.js`

- [ ] **Step 1: Add failing source-contract tests**

Assert metrics are semantic buttons, scanned/raw tabs load paginated endpoints, raw rows open `ReportDrawer`, all/filter download selection exists, and task killsweep renders all lifecycle states/timeline.

- [ ] **Step 2: Run and verify RED**

Run: `npm test -- --run`

Expected: FAIL on missing view contracts.

- [ ] **Step 3: Implement task views**

Clicking metrics switches the current task panel and records `?view=scanned|findings`. Scanned rows expand target details and linked Findings. Raw Findings exclude superseded, support server search/page controls, open reports, and download each report as a separate `.md` after all/current-filter selection. Killsweep task mode uses the global contract filtered by task and exposes timeline/manual actions.

- [ ] **Step 4: Verify frontend tests**

Run: `npm test -- --run`

Expected: PASS.

### Task 9: Global Missed-Signal and Killsweep Pages

**Files:**
- Create: `frontend/src/views/MissedSignalsView.vue`
- Create: `frontend/src/views/KillsweepsView.vue`
- Modify: `frontend/src/main.js`
- Modify: `frontend/src/style.css`
- Modify: `frontend/tests/operations.test.js`

- [ ] **Step 1: Add failing page-contract tests**

Assert filters/search/page controls, counts/badges, evidence expansion and full-content loading, draft autosave/actions, manual review, batch reanalysis, filtered Intel link, manual refresh, and task-home navigation.

- [ ] **Step 2: Run and verify RED**

Run: `npm test -- --run`

Expected: FAIL because global views do not exist.

- [ ] **Step 3: Implement Missed Signals page**

Use Pending/Converted/Rejected/All filters, default pending-risk-time ordering, compact list rows, on-demand full evidence, persistent draft editor, reject/restore/deepen actions, and full/readonly action gating.

- [ ] **Step 4: Implement Killsweep page**

Use automatic status cards including Pending Validation, failed-count badge, oldest-failure ordering, split list/detail layout, complete attempt timeline, separate automatic/manual verdicts, filtered batch retry capped at 40, and manual refresh only.

- [ ] **Step 5: Verify frontend tests and build**

Run: `npm test -- --run`

Expected: PASS.

Run: `npm run build`

Expected: Vite build exits 0.

### Task 10: End-to-End Verification, Browser QA, and Review

**Files:**
- Modify only files required by findings from verification/review.

- [ ] **Step 1: Run complete automated verification**

```powershell
.\.venv\Scripts\python.exe -m pytest -q
Set-Location frontend
npm test -- --run
npm run build
```

Expected: all commands exit 0.

- [ ] **Step 2: Start the application on an available local port**

Start FastAPI serving the new `web/dist`, without replacing an unrelated process already on port 18800.

- [ ] **Step 3: Browser QA at desktop and mobile widths**

Verify 1440x900 and 390x844: no overlaps, four-item navigation, settings role variants, task metric navigation, raw report downloads, missed evidence/draft states, killsweep split pane/timeline, focus states, and 44px mobile targets.

- [ ] **Step 4: Request spec and quality review**

Dispatch a fresh reviewer against this plan and the complete diff. Fix all Critical/Important findings and rerun the full verification suite.

- [ ] **Step 5: Review the final diff for scope and secrets**

Run: `git diff --check` and `git status --short`.

Expected: no whitespace errors, no generated runtime evidence/database files staged, and only feature/test/plan changes remain.
