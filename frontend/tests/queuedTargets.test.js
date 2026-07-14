import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const helperUrl = new URL("../src/queuedTargets.js", import.meta.url);
const componentUrl = new URL("../src/components/task/QueuedTargetsPanel.vue", import.meta.url);
const board = readFileSync(new URL("../src/views/BoardView.vue", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/api.js", import.meta.url), "utf8");
const taskViews = readFileSync(new URL("../src/taskViews.js", import.meta.url), "utf8");

test("queue helpers sort and move targets without mutating the loaded snapshot", async () => {
  assert.equal(existsSync(helperUrl), true, "queuedTargets.js should exist");
  const { moveQueueTarget, queueOrderIds, sortQueueTargets } = await import(helperUrl);
  const items = [
    { id: "b", url: "https://b.test", priority_score: 20, created_at: "2026-07-15T02:00:00Z" },
    { id: "a", url: "https://a.test", priority_score: 80, created_at: "2026-07-15T01:00:00Z" },
    { id: "c", url: "https://c.test", priority_score: 20, created_at: "2026-07-15T03:00:00Z" },
  ];

  assert.deepEqual(queueOrderIds(sortQueueTargets(items, "priority", "desc")), ["a", "b", "c"]);
  assert.deepEqual(queueOrderIds(sortQueueTargets(items, "url", "asc")), ["a", "b", "c"]);
  assert.deepEqual(queueOrderIds(sortQueueTargets(items, "created", "desc")), ["c", "b", "a"]);
  assert.deepEqual(queueOrderIds(moveQueueTarget(items, 2, 0)), ["c", "b", "a"]);
  assert.deepEqual(queueOrderIds(items), ["b", "a", "c"]);
});

test("task board wires a persistent queued-target operations panel after AI archives", () => {
  assert.equal(existsSync(componentUrl), true, "QueuedTargetsPanel.vue should exist");
  const component = readFileSync(componentUrl, "utf8");

  assert.match(board, /import QueuedTargetsPanel/);
  assert.match(board, /AI 未采纳[\s\S]+selectTaskView\(['"]queued['"]\)/);
  assert.match(board, /QueuedTargetsPanel[^>]+:progress="targetProgress"/);
  assert.match(taskViews, /["']queued["']/);
  assert.match(api, /queuedTargets:\s*\(/);
  assert.match(api, /orderQueuedTargets:\s*\(/);
  assert.match(api, /deleteQueuedTarget:\s*\(/);

  assert.match(component, /role="progressbar"/);
  assert.match(component, /progress\.resolved/);
  assert.match(component, /progress\.percent/);
  assert.match(component, /index \+ 1/);
  assert.match(component, /draggable/);
  assert.match(component, /@dragstart/);
  assert.match(component, /@drop/);
  assert.match(component, /sortQueueTargets/);
  assert.match(component, /moveQueueTarget/);
  assert.match(component, /api\.orderQueuedTargets/);
  assert.match(component, /api\.deleteQueuedTarget/);
  assert.match(component, /role="alertdialog"/);
  assert.match(component, /props\.readonly/);
  assert.match(component, /emit\(["']count["'],\s*null\)/);
});
