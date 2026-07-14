# Prompt Governance Refactor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce prompt duplication and role conflicts while preserving legacy compatibility, then compare the legacy and current profiles with five repeatable offline scenarios.

**Architecture:** Keep `app/agents/prompts.py` as the public compatibility facade. Put reusable profile normalization and bounded policy composition in `app/agents/prompt_profiles.py`; pass task rules only to Reviewer, keep Worker focused on evidence gathering, and make Collector scope selection multi-anchor. Runtime defaults move to `current`, while `legacy` and `modern` remain selectable.

**Tech Stack:** Python 3.11, pytest, FastAPI/Pydantic, Vue 3, Node test runner.

**EduSRC References:** `C:/Users/kings/Desktop/EDUSRC挖掘思路与方法论.md`, `C:/Users/kings/Desktop/等级评定.txt`, and `C:/Users/kings/Desktop/EduSRC漏洞审核辅助提示词.md` define the business-model workflow, official score bands, downgrade/ignore conditions, authenticity checks, and minimal-impact evidence standard used by the compact EduSRC prompts.

---

### Task 1: Prompt Profile Contract

**Files:**
- Create: `app/agents/prompt_profiles.py`
- Create: `tests/test_prompt_profiles.py`
- Create: `tests/test_edusrc_prompt_policy.py`
- Modify: `app/agents/prompts.py`

- [ ] Write tests asserting alias normalization, a compact `current` Worker prompt, legacy compatibility, and an 8,000-character Reviewer policy limit.
- [ ] Run `\.venv\Scripts\python.exe -m pytest tests/test_prompt_profiles.py -q` and confirm failures are caused by the missing profile module and policy composer.
- [ ] Implement immutable profile metadata, version normalization, policy trimming, and Reviewer prompt composition.
- [ ] Route the existing `prompts.py` public functions through those helpers without moving the large prompt constants.
- [ ] Re-run the focused tests and confirm all cases pass.

### Task 2: Reviewer Rule Injection

**Files:**
- Create: `tests/test_reviewer_policy.py`
- Modify: `app/agents/reviewer.py`
- Modify: `app/orchestrator.py`

- [ ] Write tests that capture Reviewer messages and assert `src_rules` appears exactly once in the system policy, is absent from Finding payloads, and is clipped at 8,000 characters.
- [ ] Run `\.venv\Scripts\python.exe -m pytest tests/test_reviewer_policy.py -q` and confirm Reviewer rejects the new constructor argument or omits the policy.
- [ ] Add the optional `src_rules` constructor argument and pass the task field from `_run_review_inner`.
- [ ] Re-run the focused tests and the existing reviewer consumer tests.

### Task 3: Collector and Enterprise Contracts

**Files:**
- Create: `tests/test_collector_scope.py`
- Create: `tests/test_enterprise_prompt_policy.py`
- Modify: `app/agents/prompts.py`
- Modify: `app/agents/collector_llm.py`
- Modify: `app/tools/schemas.py`
- Modify: `app/tools/guard.py`
- Modify: `app/tools/src_toolkit.py`
- Modify: `app/agents/worker.py`
- Modify: `app/agents/escalate.py`

- [ ] Write tests asserting EduSRC queries accept multiple education anchors, `judge_edu` preserves a concise reason, and Enterprise Escalate constructs `ToolExecutor(enterprise=True)`.
- [ ] Add enterprise-only tests proving automated vulnerability scanners are absent from Worker/Escalate schemas and blocked when invoked through `run_shell`, while `curl` and bounded evidence tools remain usable.
- [ ] Run the new tests and confirm the hard CERNET rule, missing reason field, shared scanner schemas, shell bypass, and missing executor flag fail.
- [ ] Replace the hard-only Collector rule with domain/certificate/organization/system anchors, align the tool schema/parser, pass the enterprise flag, and add a dedicated Enterprise prompt/tool policy.
- [ ] Re-run focused Collector, Escalate, and schema tests.

### Task 4: Default Version Alignment

**Files:**
- Create: `frontend/tests/promptDefaults.test.js`
- Modify: `app/config.py`
- Modify: `app/settings_service.py`
- Modify: `frontend/src/views/CreateView.vue`
- Modify: `frontend/src/components/TaskEditModal.vue`
- Modify: `frontend/src/views/SettingsView.vue`

- [ ] Add backend and frontend assertions that unset configuration resolves to `current`, with `current`, `modern`, and `legacy` still selectable.
- [ ] Run the focused tests and confirm the existing `legacy` fallbacks fail.
- [ ] Change only fallback/default values and reorder labels so `current` is the clear default.
- [ ] Re-run backend settings tests and `npm test` in `frontend`.

### Task 5: Five-Scenario Offline A/B Evaluation

**Files:**
- Create: `tests/fixtures/prompt_eval_cases.json`
- Create: `scripts/evaluate_prompts.py`
- Create: `tests/test_prompt_eval_script.py`

- [ ] Define five scenarios: Worker evidence discipline, compactness, Reviewer custom policy, Collector scope recall, and Enterprise scanner/tool separation.
- [ ] Add tests for deterministic JSON output, score bounds, profile names, prompt-size totals, and five results per profile.
- [ ] Run the tests and confirm the missing evaluator fails.
- [ ] Implement an offline evaluator that loads real prompt builders, applies explicit assertions from the fixture, and emits per-case plus aggregate metrics for `legacy` and `current`.
- [ ] Run `\.venv\Scripts\python.exe scripts/evaluate_prompts.py --repeat 5 --json-out .tmp\prompt-eval.json` and retain averages, standard deviations, pass rates, characters, and estimated tokens.

### Task 6: Verification

**Files:**
- Modify only files required by failures introduced by Tasks 1-5.

- [ ] Run all newly added prompt governance tests.
- [ ] Run `\.venv\Scripts\python.exe -m pytest -q`; compare failures to the recorded baseline of 336 passed and four pre-existing `tests/test_src_toolkit.py` failures.
- [ ] Run `npm test` and `npm run build` in `frontend`.
- [ ] Inspect `git diff --check` and the scoped diff, preserving all pre-existing uncommitted changes.
- [ ] Report measured A/B results separately from projected production behavior; do not label static contract scores as live-model accuracy.
