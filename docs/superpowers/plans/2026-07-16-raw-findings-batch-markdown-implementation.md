# 原始发现多选与 Markdown 批量下载 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在任务页原始发现列表提供跨页多选、Markdown 批量下载和已下载/未下载状态筛选。

**Architecture:** 使用 Finding 持久化下载时间；列表 API 负责状态过滤与返回状态，批量标记 API 保证任务隔离；Vue 组件以 ID Set 管理跨页选择，沿用现有报告渲染和下载工具。

**Tech Stack:** FastAPI、SQLAlchemy、SQLite 轻量迁移、Vue 3、Node test、Vite。

---

### Task 1: 持久化下载状态与 API

**Files:**
- Modify: `app/db/models.py`
- Modify: `app/db/session.py`
- Modify: `app/api/findings.py`
- Modify: `app/api/dto.py`
- Test: `tests/test_findings_downloads.py`

- [ ] Add nullable `markdown_downloaded_at` to Finding and migration entry.
- [ ] Return `downloaded` and timestamp in `_finding_dict`, accept `download_status` in list endpoint.
- [ ] Add `POST /tasks/{task_id}/findings/mark-downloaded` validating IDs belong to task, set timestamp, return marked IDs.
- [ ] Add API tests for filtering and task isolation.

### Task 2: Frontend multi-select and status filtering

**Files:**
- Modify: `frontend/src/api.js`
- Modify: `frontend/src/components/task/RawFindingsPanel.vue`
- Modify: `frontend/tests/taskOperationsPanels.test.js`

- [ ] Add API method and reactive `downloadStatus`, `selectedIds` Set, selection helpers, and reset behavior.
- [ ] Pass status to list/download pagination requests; add toolbar status tabs and select-all/clear controls.
- [ ] Render row checkboxes/status badges without changing row navigation.
- [ ] Extend download dialog to selected/filtered/all and report selected count.

### Task 3: Download completion persistence and verification

**Files:**
- Modify: `frontend/src/components/task/RawFindingsPanel.vue`
- Modify: `frontend/tests/taskOperationsPanels.test.js`

- [ ] Track successfully saved IDs during download, call mark-downloaded API, refresh list while preserving search/status, and remove marked IDs from selection.
- [ ] Cover success, cancellation, and status filter contracts in frontend tests.
- [ ] Run `npm test`, `npm run build`, and focused Python tests.
