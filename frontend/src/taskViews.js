export const TASK_VIEWS = Object.freeze({
  board: { key: "board", label: "任务看板" },
  scanned: { key: "scanned", label: "已扫" },
  findings: { key: "findings", label: "原始发现" },
  killsweeps: { key: "killsweeps", label: "通杀" },
});

export function normalizeTaskView(view) {
  return Object.hasOwn(TASK_VIEWS, view) ? view : "board";
}

export function taskViewQuery(view) {
  const normalized = normalizeTaskView(view);
  return normalized === "board" ? {} : { view: normalized };
}

const SENSITIVE_TASK_VIEWS = new Set([
  "scanned",
  "findings",
  "review",
  "submit",
  "killsweep",
  "killsweeps",
  "rejected",
  "archived",
]);

export function taskViewForRole(view, role) {
  const requested = String(view || "board");
  if (SENSITIVE_TASK_VIEWS.has(requested) && !["full", "readonly"].includes(role)) {
    return "board";
  }
  return requested;
}

export function taskProgressSummary(stats = {}) {
  const queued = Math.max(0, Number(stats.queued) || 0);
  const scanning = Math.max(0, Number(stats.scanning) || 0);
  const resolved = Math.max(0, Number(stats.done) || 0);
  const total = queued + scanning + resolved;
  return {
    total,
    resolved,
    percent: total ? Math.round((resolved / total) * 100) : 0,
  };
}

export function isCurrentTargetDetail(requestVersion, currentVersion, targetId, expandedId) {
  return requestVersion === currentVersion && targetId === expandedId;
}
