# Settings One-Click Health Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or execute each task inline with the same RED-GREEN verification gates.

**Goal:** Add a manual one-click settings diagnostic that checks every configured LLM Provider and the saved FOFA key, reports safe per-item results, and atomically disables unavailable services.

**Architecture:** Add one `POST /api/settings/health-check` orchestration endpoint. It snapshots Provider/FOFA configuration, runs bounded concurrent probes, then applies failed-state changes in one `BEGIN IMMEDIATE` transaction guarded by configuration fingerprints so stale probe results cannot disable newly edited credentials. The settings sidebar owns the aggregate UI while `LlmProvidersPanel` receives the same Provider results for row-level red status.

**Tech Stack:** FastAPI, SQLAlchemy async sessions, httpx, Vue 3, Vite, Node test runner, pytest.

---

### Task 1: FOFA Account Probe And Runtime Enable State

**Files:**
- Modify: `app/fofa/client.py`
- Modify: `app/settings_service.py`
- Modify: `tests/test_llm_provider_api.py`
- Modify: `tests/test_settings_service.py`

- [ ] **Step 1: Write failing FOFA probe tests**

Assert that the saved key is sent only to `${base_url}/api/v1/info/my`, SSRF validation runs first, success returns a safe timing result, and failures never echo the key.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest -q tests/test_llm_provider_api.py -k "fofa_probe"`

- [ ] **Step 3: Implement the official account-info request**

Add `get_userinfo(key, base_url)` to `app/fofa/client.py` using the same allowed-host SSRF boundary as `search()`. Add `probe_fofa_key()` to `settings_service.py` returning only:

```python
{"ok": bool, "latency_ms": int, "error": str}
```

- [ ] **Step 4: Add and verify FOFA runtime-state tests**

Ensure global FOFA settings expose `enabled`, saved UI FOFA values are the resolver fallback, a failed diagnostic can suppress only the global key, task-specific keys still win, and saving a replacement key re-enables global FOFA.

### Task 2: Atomic Batch Health Endpoint

**Files:**
- Modify: `app/settings_service.py`
- Modify: `app/api/settings.py`
- Modify: `tests/test_llm_provider_api.py`

- [ ] **Step 1: Write the failing endpoint test**

Seed enabled Provider A, enabled Provider B, disabled Provider C, and a FOFA key. Mock only the external probes. Assert all three Providers are tested, B and failing FOFA are disabled in one persisted result, C is tested but remains manually disabled, A remains enabled, ordering is stable, and no secret appears in the response.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest -q tests/test_llm_provider_api.py -k "settings_health_check"`

- [ ] **Step 3: Implement bounded probing and atomic state application**

Return this stable response contract:

```python
{
    "checked_at": "2026-07-14T12:00:00+08:00",
    "provider_results": [
        {
            "name": "Primary", "ok": False, "latency_ms": 120,
            "model": "gpt", "protocol": "openai_chat", "error": "safe",
            "enabled": False, "auto_disabled": True, "stale": False,
        }
    ],
    "fofa_result": {
        "name": "FOFA", "ok": False, "latency_ms": 80,
        "error": "safe", "enabled": False, "auto_disabled": True,
        "stale": False,
    },
    "providers": [],
}
```

Probe all stored Providers, including disabled/keyless drafts, with concurrency capped at three. Fingerprints must prevent a late failure from disabling a configuration changed during the probe.

- [ ] **Step 4: Verify GREEN**

Run the endpoint tests, then `python -m pytest -q`.

### Task 3: Sidebar Command And Result Presentation

**Files:**
- Create: `frontend/src/settingsHealth.js`
- Modify: `frontend/tests/llmProviders.test.js`
- Modify: `frontend/src/api.js`
- Modify: `frontend/src/views/SettingsView.vue`
- Modify: `frontend/src/components/LlmProvidersPanel.vue`
- Modify: `frontend/src/style.css`

- [ ] **Step 1: Write failing frontend state tests**

Test aggregate passed/failed/auto-disabled counts, stable Provider lookup by name, FOFA inclusion, and stale-state derivation without exposing error details as HTML.

- [ ] **Step 2: Verify RED**

Run: `cd frontend && npm test`

- [ ] **Step 3: Implement the settings UI**

Add `api.checkSettingsHealth()`. Place a full-width `一键检测` command below `settings-note` in the left summary. Show running, complete, stale, request-error, per-item green/red state, safe error text, latency, timestamp, and automatic-disable count. Expose an `applyHealthCheck()` method from `LlmProvidersPanel` so the right-side rows use the same result source and failed rows receive a red state.

- [ ] **Step 4: Verify GREEN and build**

Run: `cd frontend && npm test && npm run build`.

### Task 4: Runtime And Responsive Verification

**Files:**
- Verify only; no new production files expected.

- [ ] **Step 1: Run final automated checks**

Run full pytest, frontend tests/build, `python -m compileall -q app tests`, app import, and `git diff --check`.

- [ ] **Step 2: Restart the local service**

Reuse `.tmp/multi-llm-smoke.db` on `127.0.0.1:18800` so the existing Provider fixture remains visible.

- [ ] **Step 3: Browser-test with intercepted responses**

Verify mixed success/failure, red row state, automatic toggle-off, FOFA status, no secret in DOM/network response, repeat-run recovery, and no console errors. Check desktop and `390x844`; assert document `scrollWidth == clientWidth`.
