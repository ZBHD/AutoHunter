export const MISSED_SIGNAL_STATUS = Object.freeze({
  pending: { label: "待复核", tone: "warning" },
  deepening: { label: "深挖中", tone: "running" },
  converted: { label: "已转报告", tone: "success" },
  rejected: { label: "已驳回", tone: "muted" },
});

export function missedSignalPresentation(status) {
  const value = MISSED_SIGNAL_STATUS[status];
  return value
    ? { key: status, ...value }
    : { key: status || "unknown", label: status || "未知", tone: "muted" };
}

export const MISSED_SIGNAL_SOURCE = Object.freeze({
  tool: "工具证据",
  archived_review: "AI 未采纳",
  deepen_lead: "深挖线索",
  coverage_gap: "覆盖度遗漏",
});

export function missedSignalSourceLabel(source) {
  return MISSED_SIGNAL_SOURCE[source] || source || "未知来源";
}

export const MISSED_SIGNAL_PAGE_SIZE = 50;

export function missedSignalListParams({ status = "pending", q = "", page = 0, taskId = "" } = {}) {
  const params = {
    limit: MISSED_SIGNAL_PAGE_SIZE,
    offset: Math.max(0, Math.floor(Number(page) || 0)) * MISSED_SIGNAL_PAGE_SIZE,
  };
  if (status && status !== "all") params.status = status;
  const query = String(q || "").trim();
  if (query) params.q = query;
  if (taskId) params.task_id = taskId;

  // Keep request keys in the same order as the controls users set them in.
  return Object.fromEntries([
    ...(params.status ? [["status", params.status]] : []),
    ...(params.task_id ? [["task_id", params.task_id]] : []),
    ...(params.q ? [["q", params.q]] : []),
    ["limit", params.limit],
    ["offset", params.offset],
  ]);
}

function chainLine(step) {
  if (!step || typeof step !== "object") return String(step || "");
  return [step.method, step.detail].filter(Boolean).join("｜");
}

export function draftFormFromContent(content = {}) {
  return {
    ...content,
    steps: Array.isArray(content.steps) ? content.steps.join("\n") : String(content.steps || ""),
    kill_chain: Array.isArray(content.kill_chain)
      ? content.kill_chain.map(chainLine).filter(Boolean).join("\n")
      : String(content.kill_chain || ""),
    evidence_json: JSON.stringify(content.evidence || {}, null, 2),
  };
}

export function draftContentFromForm(form = {}, original = {}) {
  const steps = String(form.steps || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  const killChain = String(form.kill_chain || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [method, ...detail] = line.split(/[｜|]/);
      return { method: method.trim(), detail: detail.join("｜").trim() };
    });

  let evidence = original.evidence || {};
  try {
    evidence = JSON.parse(String(form.evidence_json || "{}"));
  } catch {
    // The editor validates JSON before persistence; retain the last valid value here.
  }
  const { evidence_json: _evidenceJson, ...editable } = form;

  return {
    ...original,
    ...editable,
    steps,
    kill_chain: killChain,
    evidence,
  };
}

export function createDraftFlushQueue({ persist, delayMs = 600, onError = () => {} } = {}) {
  if (typeof persist !== "function") throw new TypeError("persist must be a function");

  const pending = new Map();
  const timers = new Map();
  const active = new Map();

  function clearScheduled(signalId) {
    const timer = timers.get(signalId);
    if (timer !== undefined) clearTimeout(timer);
    timers.delete(signalId);
  }

  function schedule(snapshot) {
    const signalId = String(snapshot?.signalId || "");
    if (!signalId) throw new TypeError("snapshot.signalId is required");
    pending.set(signalId, { ...snapshot, signalId });
    clearScheduled(signalId);
    timers.set(signalId, setTimeout(() => {
      timers.delete(signalId);
      void flush(signalId).catch(onError);
    }, delayMs));
  }

  async function run(signalId) {
    let lastResult;
    while (pending.has(signalId)) {
      clearScheduled(signalId);
      const snapshot = pending.get(signalId);
      pending.delete(signalId);
      try {
        lastResult = await persist(snapshot);
      } catch (error) {
        if (!pending.has(signalId)) pending.set(signalId, snapshot);
        throw error;
      }

      const next = pending.get(signalId);
      const revision = lastResult?.revision;
      if (next && revision !== undefined && next.revision === snapshot.revision) {
        pending.set(signalId, { ...next, revision });
      }
    }
    return lastResult;
  }

  async function flush(value) {
    const signalId = String(value || "");
    if (!signalId) return undefined;
    clearScheduled(signalId);

    const running = active.get(signalId);
    if (running) {
      const result = await running;
      return pending.has(signalId) ? flush(signalId) : result;
    }
    if (!pending.has(signalId)) return undefined;

    const job = run(signalId);
    active.set(signalId, job);
    try {
      return await job;
    } finally {
      if (active.get(signalId) === job) active.delete(signalId);
    }
  }

  async function flushAll() {
    const signalIds = new Set([...pending.keys(), ...timers.keys(), ...active.keys()]);
    return Promise.all([...signalIds].map((signalId) => flush(signalId)));
  }

  return { schedule, flush, flushAll };
}
