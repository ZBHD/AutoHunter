import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  TASK_STATUS_FILTERS,
  filterTasksByStatus,
  taskStatusFilterCounts,
} from "../src/taskStatusFilters.js";

const tasks = [
  { id: "running", status: "running" },
  { id: "paused", status: "paused" },
  { id: "idle", status: "idle" },
  { id: "created", status: "created" },
  { id: "stopped", status: "stopped" },
  { id: "unknown", status: "unknown" },
];

const taskView = readFileSync(new URL("../src/views/TasksView.vue", import.meta.url), "utf8");
const style = readFileSync(new URL("../src/style.css", import.meta.url), "utf8");

test("task status filters keep the required display order", () => {
  assert.deepEqual(TASK_STATUS_FILTERS.map(({ key, label }) => [key, label]), [
    ["all", "全部"],
    ["running", "运行中"],
    ["paused", "已暂停"],
    ["stopped", "已停止"],
  ]);
});

test("paused filter includes paused idle and created tasks", () => {
  assert.deepEqual(
    filterTasksByStatus(tasks, "paused").map(({ id }) => id),
    ["paused", "idle", "created"],
  );
  assert.deepEqual(filterTasksByStatus(tasks, "running").map(({ id }) => id), ["running"]);
  assert.deepEqual(filterTasksByStatus(tasks, "stopped").map(({ id }) => id), ["stopped"]);
  assert.deepEqual(filterTasksByStatus(tasks, "all").map(({ id }) => id), tasks.map(({ id }) => id));
});

test("task status counts use the same grouping rules as filtering", () => {
  assert.deepEqual(taskStatusFilterCounts(tasks), {
    all: 6,
    running: 1,
    paused: 3,
    stopped: 1,
  });
});

test("task list renders status filters and filtered results", () => {
  assert.match(taskView, /TASK_STATUS_FILTERS/);
  assert.match(taskView, /const statusFilter = ref\("all"\)/);
  assert.match(taskView, /const filteredTasks = computed/);
  assert.match(taskView, /v-for="filter in TASK_STATUS_FILTERS"/);
  assert.match(taskView, /:aria-pressed="statusFilter === filter\.key"/);
  assert.match(taskView, /v-for="t in filteredTasks"/);
  assert.match(taskView, /当前筛选下没有任务/);
});

test("task status filters have stable responsive controls", () => {
  assert.match(style, /\.task-status-filters\s*\{[\s\S]*grid-template-columns:\s*repeat\(4,/);
  assert.match(style, /\.task-status-filters button\.active/);
  assert.match(style, /@media \(max-width:\s*640px\)[\s\S]*\.task-status-filters button[\s\S]*min-height:\s*44px/);
});
