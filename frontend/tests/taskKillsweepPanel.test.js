import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function source(path) {
  try {
    return readFileSync(new URL(path, import.meta.url), "utf8");
  } catch {
    return "";
  }
}

const board = source("../src/views/BoardView.vue");
const panel = source("../src/components/task/TaskKillsweepPanel.vue");
const operationsStyle = source("../src/styles/operations.css");

test("task board delegates killsweep lifecycle rendering without using the legacy endpoint", () => {
  assert.match(board, /import TaskKillsweepPanel from "\.\.\/components\/task\/TaskKillsweepPanel\.vue"/);
  assert.match(board, /<TaskKillsweepPanel/);
  assert.match(board, /:task-id="props\.id"/);
  assert.match(board, /:active="tab === 'killsweep'"/);
  assert.doesNotMatch(board, /api\.killsweeps\(/);
  assert.doesNotMatch(board, /invalidateKillsweep/);
  assert.doesNotMatch(board, /const LIST_TABS = new Set\([^\n]*killsweep/);
  assert.doesNotMatch(board, /loadTabData\([^\n]*killsweep/);
});

test("task killsweep panel filters the global lifecycle contract by task and exposes every state", () => {
  assert.match(panel, /api\.killsweepCases\(killsweepListParams\(/);
  assert.match(panel, /taskId:\s*props\.taskId/);
  for (const state of [
    "queued", "running", "succeeded", "failed", "cancelled",
    "pending_validation", "killsweep", "not_killsweep",
  ]) {
    assert.match(panel, new RegExp(`\\b${state}\\b`));
  }
  assert.match(panel, /@click="refresh"/);
  assert.doesNotMatch(panel, /setInterval\(/);
  assert.match(panel, /const hasLoaded = ref\(false\)/);
  assert.match(panel, /active && canRead && !hasLoaded\.value/);
});

test("task badge count remains the unfiltered lifecycle total", () => {
  assert.match(
    panel,
    /if \(status\.value === "all" && !searchText\.value\) emit\("count", normalized\.total\)/,
  );
});

test("task killsweep detail keeps automatic and manual verdicts separate with full audit history", () => {
  assert.match(panel, /api\.killsweepCase\(/);
  assert.match(panel, /api\.killsweepEvents\(/);
  assert.match(panel, /<KillsweepTimeline/);
  assert.match(panel, /自动结论/);
  assert.match(panel, /人工结论/);
  assert.match(panel, /selected\.attempts/);
  assert.match(panel, /原始证据/);
});

test("task killsweep write actions are full-role gated and preserve manual review choices", () => {
  assert.match(panel, /const writable = computed\(\(\) => canWrite\(\)\)/);
  assert.match(panel, /v-if="writable"/);
  assert.match(panel, /api\.reviewKillsweep\(/);
  assert.match(panel, /confirmed/);
  assert.match(panel, /not_killsweep/);
  assert.match(panel, /invalid/);
  assert.match(panel, /canReanalyzeKillsweep/);
  assert.match(panel, /api\.reanalyzeKillsweep\(/);
});

test("task killsweep layout remains usable at 390px with 44px touch controls", () => {
  assert.match(operationsStyle, /\.task-killsweep-panel/);
  assert.match(operationsStyle, /@media \(max-width:\s*420px\)[\s\S]*\.task-killsweep-panel[\s\S]*min-height:\s*44px/);
});
