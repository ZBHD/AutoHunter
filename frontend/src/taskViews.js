export const TASK_VIEWS = Object.freeze({
  board: { key: "board", label: "任务看板" },
  scanned: { key: "scanned", label: "已扫" },
  findings: { key: "findings", label: "原始发现" },
  killsweeps: { key: "killsweeps", label: "通杀" },
  "gateway-assets": { key: "gateway-assets", label: "网关资产" },
  "gateway-secrets": { key: "gateway-secrets", label: "Secret" },
  "gateway-observations": { key: "gateway-observations", label: "探测记录" },
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
  "queued",
  "gateway-assets",
  "gateway-secrets",
  "gateway-observations",
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

export function taskSearchControl(task, working = false, blocked = false) {
  const visible = task?.target_source === "fofa" || task?.target_source === "both";
  const enabled = task?.search_enabled !== false;
  const active = task?.status === "running" || task?.status === "idle";
  return {
    visible,
    canStop: visible && active && enabled && !working && !blocked,
    draining: visible && !enabled && active,
    label: working ? "正在停止" : enabled ? "停止搜索" : "搜索已停止",
  };
}

export function mergeTaskControlResponse(current, updated) {
  if (!updated) return current;
  const merged = { ...(current || {}), ...updated };
  for (const key of ["fofa_config", "model_config_data", "engine_config", "llm_usage"]) {
    const currentValue = current?.[key];
    const updatedValue = updated[key];
    if (currentValue && typeof currentValue === "object" && !Array.isArray(currentValue)
        && updatedValue && typeof updatedValue === "object" && !Array.isArray(updatedValue)) {
      merged[key] = { ...currentValue, ...updatedValue };
    }
  }
  if (updated.stats == null && current?.stats != null) merged.stats = current.stats;
  if (Object.hasOwn(current || {}, "pending_user_review")) {
    merged.pending_user_review = current.pending_user_review;
  }
  return merged;
}

export function isCurrentTaskRequest(requestVersion, currentVersion, requestTaskId, currentTaskId, loadedTaskId) {
  return requestVersion === currentVersion
    && requestTaskId === currentTaskId
    && requestTaskId === loadedTaskId;
}

export function isCurrentTaskRefresh(
  requestVersion,
  currentVersion,
  startedWhileControlWorking,
  currentControlWorking,
  expectedRequestVersion,
) {
  if (expectedRequestVersion !== undefined) return expectedRequestVersion === currentVersion;
  return requestVersion === currentVersion
    && !startedWhileControlWorking
    && !currentControlWorking;
}

export function isCurrentTargetDetail(requestVersion, currentVersion, targetId, expandedId) {
  return requestVersion === currentVersion && targetId === expandedId;
}
