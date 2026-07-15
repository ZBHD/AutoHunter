import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import * as taskViews from "../src/taskViews.js";
import * as missedSignals from "../src/missedSignals.js";
import * as killsweeps from "../src/killsweeps.js";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("terminal aggregate drives task totals and progress without double counting", () => {
  assert.equal(typeof taskViews.taskProgressSummary, "function");
  assert.deepEqual(
    taskViews.taskProgressSummary({ queued: 10, scanning: 5, done: 20, dead: 6, skipped: 4 }),
    { total: 35, resolved: 20, percent: 57 },
  );
});

test("search control is available only for active fofa-backed tasks", () => {
  assert.equal(typeof taskViews.taskSearchControl, "function");
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "fofa", status: "running" }),
    { visible: true, canStop: true, draining: false, label: "停止搜索" },
  );
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "both", status: "idle", search_enabled: true }),
    { visible: true, canStop: true, draining: false, label: "停止搜索" },
  );

  for (const target_source of ["manual", "site"]) {
    assert.deepEqual(
      taskViews.taskSearchControl({ target_source, status: "running" }),
      { visible: false, canStop: false, draining: false, label: "停止搜索" },
    );
  }
});

test("search control reports stopped, draining, and working states", () => {
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "fofa", status: "running", search_enabled: false }),
    { visible: true, canStop: false, draining: true, label: "搜索已停止" },
  );
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "fofa", status: "stopped", search_enabled: false }),
    { visible: true, canStop: false, draining: false, label: "搜索已停止" },
  );
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "both", status: "idle" }, true),
    { visible: true, canStop: false, draining: false, label: "正在停止" },
  );
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "fofa", status: "running" }, false, true),
    { visible: true, canStop: false, draining: false, label: "停止搜索" },
  );
  assert.deepEqual(
    taskViews.taskSearchControl({ target_source: "fofa", status: "running", search_enabled: false }, false, true),
    { visible: true, canStop: false, draining: true, label: "搜索已停止" },
  );
});

test("control responses preserve board-derived task metrics when the DTO is sparse", () => {
  assert.equal(typeof taskViews.mergeTaskControlResponse, "function");
  const current = {
    status: "running",
    search_enabled: true,
    stats: { queued: 12, scanning: 3, done: 8 },
    pending_user_review: 6,
    fofa_config: { collector_phase: "enrich", max_pages: 3 },
    model_config_data: { model: "old-model", board_only: "keep" },
    engine_config: { region: "cn", board_only: "keep" },
    llm_usage: { requests: 9, board_only: "keep" },
    unrelated_config: { board_only: "discard", value: "old" },
  };
  const updated = {
    status: "idle",
    search_enabled: false,
    stats: null,
    pending_user_review: 0,
    fofa_config: { base_url: "https://fofa.example" },
    model_config_data: { model: "new-model" },
    engine_config: { region: "global" },
    llm_usage: { requests: 10 },
    unrelated_config: { value: "new" },
  };

  const merged = taskViews.mergeTaskControlResponse(current, updated);
  assert.deepEqual(merged.stats, current.stats);
  assert.equal(merged.pending_user_review, current.pending_user_review);
  assert.equal(merged.fofa_config.collector_phase, current.fofa_config.collector_phase);
  assert.equal(merged.fofa_config.max_pages, current.fofa_config.max_pages);
  assert.equal(merged.fofa_config.base_url, updated.fofa_config.base_url);
  for (const key of ["model_config_data", "engine_config", "llm_usage"]) {
    assert.equal(merged[key].board_only, "keep");
  }
  assert.deepEqual(merged.unrelated_config, updated.unrelated_config);
  assert.equal(merged.status, updated.status);
  assert.equal(merged.search_enabled, updated.search_enabled);
  assert.equal(
    taskViews.mergeTaskControlResponse(current, { ...updated, pending_user_review: 2 }).pending_user_review,
    current.pending_user_review,
  );
});

test("task operation request identity requires both the version and task route", () => {
  assert.equal(typeof taskViews.isCurrentTaskRequest, "function");
  assert.equal(taskViews.isCurrentTaskRequest(3, 3, "task-a", "task-a", "task-a"), true);
  assert.equal(taskViews.isCurrentTaskRequest(2, 3, "task-a", "task-a", "task-a"), false);
  assert.equal(taskViews.isCurrentTaskRequest(3, 3, "task-a", "task-b", "task-b"), false);
  assert.equal(taskViews.isCurrentTaskRequest(3, 3, "task-a", "task-a", "task-b"), false);
});

test("ordinary task refreshes reject control-era responses but explicit control refreshes pass", () => {
  assert.equal(typeof taskViews.isCurrentTaskRefresh, "function");
  assert.equal(taskViews.isCurrentTaskRefresh(1, 2, false, false), false, "started before control");
  assert.equal(taskViews.isCurrentTaskRefresh(2, 2, true, false), false, "started during control");
  assert.equal(taskViews.isCurrentTaskRefresh(2, 2, false, true), false, "applied during control");
  assert.equal(taskViews.isCurrentTaskRefresh(2, 2, true, true, 2), true, "explicit control refresh");
});

test("observer task views always collapse sensitive panels to the board", () => {
  assert.equal(typeof taskViews.taskViewForRole, "function");
  for (const view of [
    "scanned",
    "findings",
    "review",
    "submit",
    "killsweep",
    "rejected",
    "archived",
  ]) {
    assert.equal(taskViews.taskViewForRole(view, "observer"), "board");
  }
  assert.equal(taskViews.taskViewForRole("findings", "readonly"), "findings");

  const board = source("../src/views/BoardView.vue");
  assert.match(board, /taskViewForRole/);
  assert.match(board, /authRoleRef !== ['"]observer['"] && tab === ['"]scanned['"]/);
  assert.match(board, /authRoleRef !== ['"]observer['"] && tab === ['"]findings['"]/);
  assert.match(
    board,
    /<template v-if="authRoleRef !== 'observer'">[\s\S]*tab === 'review'[\s\S]*tab === 'submit'[\s\S]*tab === 'killsweep'[\s\S]*tab === 'rejected'[\s\S]*tab === 'archived'[\s\S]*<\/template>/,
  );
  assert.match(
    board,
    /async function loadTabData[\s\S]*authRoleRef\.value === ['"]observer['"][\s\S]*return/,
  );
  assert.match(board, /watch\(authRoleRef,[\s\S]*\{\s*immediate:\s*true\s*\}/);
});

test("stale target-detail responses cannot replace the expanded target", () => {
  assert.equal(typeof taskViews.isCurrentTargetDetail, "function");
  assert.equal(taskViews.isCurrentTargetDetail(1, 2, "target-a", "target-b"), false);
  assert.equal(taskViews.isCurrentTargetDetail(2, 2, "target-a", "target-b"), false);
  assert.equal(taskViews.isCurrentTargetDetail(2, 2, "target-b", "target-b"), true);

  const scanned = source("../src/components/task/ScannedTargetsPanel.vue");
  assert.match(scanned, /detailVersion/);
  assert.match(scanned, /isCurrentTargetDetail/);
});

test("draft flush queue preserves the newest revision and isolates signals", async () => {
  assert.equal(typeof missedSignals.createDraftFlushQueue, "function");

  const writes = [];
  let releaseFirst;
  let markFirstStarted;
  const firstStarted = new Promise((resolve) => { markFirstStarted = resolve; });
  const firstGate = new Promise((resolve) => { releaseFirst = resolve; });
  const saver = missedSignals.createDraftFlushQueue({
    delayMs: 60_000,
    persist: async (snapshot) => {
      writes.push({ ...snapshot });
      if (snapshot.signalId === "signal-a" && snapshot.editVersion === 1) {
        markFirstStarted();
        await firstGate;
      }
      return { revision: snapshot.revision + 1 };
    },
  });

  saver.schedule({ signalId: "signal-a", revision: 1, editVersion: 1, content: "first" });
  const flushing = saver.flush("signal-a");
  await firstStarted;
  saver.schedule({ signalId: "signal-a", revision: 1, editVersion: 2, content: "latest" });
  saver.schedule({ signalId: "signal-b", revision: 7, editVersion: 1, content: "other" });
  releaseFirst();
  await flushing;

  assert.deepEqual(writes.map(({ signalId, revision, content }) => ({ signalId, revision, content })), [
    { signalId: "signal-a", revision: 1, content: "first" },
    { signalId: "signal-a", revision: 2, content: "latest" },
  ]);
  await saver.flushAll();
  assert.deepEqual(writes.at(-1), {
    signalId: "signal-b", revision: 7, editVersion: 1, content: "other",
  });
});

test("draft editor flushes the loaded signal on switch and unmount", () => {
  const draft = source("../src/components/missed-signals/MissedSignalDraftEditor.vue");
  assert.match(draft, /createDraftFlushQueue/);
  assert.match(draft, /loadedSignalId/);
  assert.match(draft, /flushCurrentDraft/);
  assert.match(draft, /onBeforeUnmount\([\s\S]*flushAll/);
});

test("global killsweep statistics expose completed and cancelled lifecycle states", () => {
  assert.equal(typeof killsweeps.killsweepStatCount, "function");
  const stats = { pending_validation: 2, killsweep: 3, not_killsweep: 4, cancelled: 5 };
  assert.equal(killsweeps.killsweepStatCount(stats, "succeeded"), 9);
  assert.equal(killsweeps.killsweepStatCount(stats, "cancelled"), 5);

  const view = source("../src/views/KillsweepsView.vue");
  assert.match(view, /key:\s*['"]succeeded['"]/);
  assert.match(view, /key:\s*['"]cancelled['"]/);
  assert.match(view, /killsweepStatCount/);
});

test("mobile operation controls keep a 44px target", () => {
  const style = source("../src/style.css");
  const scanned = source("../src/components/task/ScannedTargetsPanel.vue");
  const findings = source("../src/components/task/RawFindingsPanel.vue");

  assert.match(style, /@media \(max-width:\s*640px\)[\s\S]*\.head-action\s*\{[^}]*min-height:\s*44px/);
  assert.match(style, /\.personal-setting-action\s*\{[^}]*min-height:\s*44px/);
  assert.match(style, /\.settings-theme-switch button\s*\{[^}]*min-height:\s*44px/);
  assert.match(scanned, /\.operation-search button\{min-height:44px\}/);
  assert.match(findings, /\.raw-search button\{min-height:44px\}/);
});

test("operation search and download dialog expose keyboard contracts", () => {
  const missed = source("../src/views/MissedSignalsView.vue");
  const globalKillsweep = source("../src/views/KillsweepsView.vue");
  const taskKillsweep = source("../src/components/task/TaskKillsweepPanel.vue");
  const findings = source("../src/components/task/RawFindingsPanel.vue");

  assert.match(missed, /aria-label="搜索疑似漏洞"/);
  assert.match(globalKillsweep, /aria-label="搜索通杀案例"/);
  assert.match(taskKillsweep, /aria-label="搜索任务通杀案例"/);
  assert.match(findings, /ref="downloadTrigger"/);
  assert.match(findings, /ref="downloadDialog"/);
  assert.match(findings, /@keydown\.escape\.prevent="closeDownload"/);
  assert.match(findings, /@keydown\.tab="trapDownloadFocus"/);
  assert.match(findings, /nextTick[\s\S]*focus/);
});

test("scanned target colors use the established design tokens", () => {
  const scanned = source("../src/components/task/ScannedTargetsPanel.vue");
  assert.doesNotMatch(scanned, /var\(--(?:success|warning|text)\)/);
  assert.match(scanned, /status-done\{background:var\(--ok\)\}/);
  assert.match(scanned, /status-skipped\{background:var\(--warn\)\}/);
  assert.match(scanned, /target-findings b\{color:var\(--ink\)\}/);
});
