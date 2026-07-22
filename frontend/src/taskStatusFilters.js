export const TASK_STATUS_FILTERS = Object.freeze([
  { key: "all", label: "全部" },
  { key: "running", label: "运行中" },
  { key: "paused", label: "已暂停" },
  { key: "stopped", label: "已停止" },
]);

const FILTER_STATUSES = Object.freeze({
  running: new Set(["running"]),
  paused: new Set(["paused", "idle", "created"]),
  stopped: new Set(["stopped"]),
});

export function filterTasksByStatus(tasks = [], filter = "all") {
  if (filter === "all") return tasks;
  const statuses = FILTER_STATUSES[filter];
  return statuses ? tasks.filter((task) => statuses.has(task?.status)) : tasks;
}

export function taskStatusFilterCounts(tasks = []) {
  return Object.fromEntries(
    TASK_STATUS_FILTERS.map(({ key }) => [key, filterTasksByStatus(tasks, key).length]),
  );
}
