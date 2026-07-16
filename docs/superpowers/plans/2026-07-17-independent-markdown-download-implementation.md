# 独立 Markdown 下载与 AI 未采纳批量操作 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 统一三个漏洞列表的独立 Markdown 下载，并为 AI 未采纳列表补齐多选与下载状态筛选。

**Architecture:** 报告渲染层提供完整阅读版和下载精简版；下载工具层始终按 Finding 逐条保存；Vue 列表层只负责选择范围、状态筛选和成功 ID 回写，后端复用现有下载时间字段与标记接口。

**Tech Stack:** Vue 3、FastAPI、SQLAlchemy、SQLite 轻量迁移、Node test、pytest、Vite。

---

### Task 1: 下载版报告渲染

**Files:**
- Modify: `frontend/src/report.js`
- Test: `frontend/tests/operationsFoundation.test.js`

- [ ] Add `buildDownloadReportMd` that excludes AI review conclusion and EduSRC JSON while retaining evidence and attack-chain sections.
- [ ] Add tests that assert excluded headings are absent and core vulnerability sections remain.

### Task 2: Independent downloads for existing lists

**Files:**
- Modify: `frontend/src/components/task/RawFindingsPanel.vue`
- Modify: `frontend/src/views/BoardView.vue`
- Test: `frontend/tests/taskOperationsPanels.test.js`

- [ ] Replace raw findings renderer with `buildDownloadReportMd`.
- [ ] Replace review queue merged Blob export with `downloadMarkdownReports`, one file per Finding, and mark only successful IDs.
- [ ] Keep selection, progress, cancellation, and status refresh behavior intact.
- [ ] Extend static contracts to prohibit merged separators and require the shared download utility.

### Task 3: AI 未采纳 list filtering and batch download

**Files:**
- Modify: `app/api/findings.py`
- Modify: `frontend/src/api.js`
- Modify: `frontend/src/views/BoardView.vue`
- Modify: `frontend/src/styles/operations.css`
- Test: `tests/test_findings_downloads.py`
- Test: `frontend/tests/taskOperationsPanels.test.js`

- [ ] Add `download_status` to archived list query and API client options.
- [ ] Add archived selection Set, status tabs, scope controls, one-file-per-finding download, success marking, and reload.
- [ ] Keep restore/deepen actions independent from selection controls.
- [ ] Test downloaded/pending archived responses and UI contracts.

### Task 4: Verification

- [ ] Run `npm test` and `npm run build`.
- [ ] Run focused pytest for findings downloads, task operations API, and migrations.
- [ ] Run `git diff --check` and inspect the final diff for unrelated changes.
