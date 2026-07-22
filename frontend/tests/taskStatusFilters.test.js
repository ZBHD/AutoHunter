import test from "node:test";
import assert from "node:assert/strict";

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
