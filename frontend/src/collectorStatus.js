const AUTO_SOURCES = new Set(["fofa", "both"]);
const ACTIVE_PHASES = new Set([
  "initializing", "querying", "prefilter", "scoring", "target_filter", "enrich",
]);
const WAITING_PHASES = new Set(["fofa_cooldown", "fofa_pool_waiting"]);
const BLOCKED_PHASES = new Set(["fofa_pool_blocked"]);
const KNOWN_PHASES = new Set([
  ...ACTIVE_PHASES,
  ...WAITING_PHASES,
  ...BLOCKED_PHASES,
  "dispatch", "exhausted", "fofa_error",
]);

export function isAutoCollectionTask(task = {}) {
  return AUTO_SOURCES.has(String(task.target_source || "")) && task.search_enabled !== false;
}

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

/**
 * Apply only fields carried by a collector event. Runtime snapshots are
 * intentionally sparse, so absent counters must never be interpreted as 0.
 */
export function mergeCollectorEvent(current = {}, event = {}) {
  const next = { ...(isRecord(current) ? current : {}) };
  const kind = String(event.kind || event.event_kind || "");
  const previousRotation = isRecord(current?.last_rotation) ? current.last_rotation : {};

  if (event.to_key_name) next.last_key_name = String(event.to_key_name);
  if (kind === "fofa_key_rotated") {
    const rotation = {};
    const from = event.from_key_name || previousRotation.from_key_name;
    const to = event.to_key_name || previousRotation.to_key_name;
    const reason = event.reason || previousRotation.reason;
    if (from) rotation.from_key_name = String(from);
    if (to) rotation.to_key_name = String(to);
    if (reason) rotation.reason = String(reason);
    if (Object.keys(rotation).length) next.last_rotation = rotation;
  } else if (event.last_rotation !== undefined) {
    next.last_rotation = event.last_rotation;
  }

  if (event.phase !== undefined) next.collector_phase = event.phase;
  if (event.message !== undefined) next.collector_phase_text = event.message;
  if (event.survivors !== undefined) next.last_target_filter_total = event.survivors;
  if (event.filter_evaluated !== undefined) next.last_target_filter_evaluated = event.filter_evaluated;

  const fields = [
    "engine", "key_source", "pool_state", "pool_available", "pool_total",
    "cooldown_until", "fofa_next_retry_at", "fofa_pool_summary", "fofa_pool_blocked",
  ];
  for (const key of fields) {
    if (event[key] !== undefined) next[key] = event[key];
  }

  if (kind === "fofa_pool_waiting") {
    next.pool_state = "cooling";
    if (event.next_retry_at !== undefined) {
      next.cooldown_until = event.next_retry_at;
      next.fofa_next_retry_at = event.next_retry_at;
    }
  } else if (kind === "fofa_pool_blocked") {
    next.pool_state = "blocked";
    next.fofa_pool_blocked = true;
  } else if (kind === "fofa_key_rotated") {
    next.pool_state = "ready";
    next.fofa_pool_blocked = false;
  }
  return next;
}

function totalTargets(stats = {}) {
  return Math.max(0, Number(stats.queued) || 0)
    + Math.max(0, Number(stats.scanning) || 0)
    + Math.max(0, Number(stats.done) || 0);
}

function normalizedEngine(task, cfg) {
  return String(cfg.engine || task.engine || "").trim().toLowerCase();
}

function keySourceLabel(source) {
  if (source === "task_override") return "任务专用 Key";
  if (source === "legacy") return "Legacy Key";
  return "全局 Key 池";
}

export function collectorViewModel(task = {}, stats = {}, cfg = {}, now = Date.now()) {
  const auto = isAutoCollectionTask(task);
  const engine = normalizedEngine(task, cfg);
  const phase = String(cfg.collector_phase || "");
  const poolState = String(cfg.pool_state || "");
  const waiting = WAITING_PHASES.has(phase) || poolState === "cooling";
  const blocked = BLOCKED_PHASES.has(phase) || poolState === "blocked" || cfg.fofa_pool_blocked === true;
  const phaseKnown = !phase || KNOWN_PHASES.has(phase);
  const active = auto && task.status === "running" && !waiting && !blocked;
  const working = active && (!phase || ACTIVE_PHASES.has(phase));
  const hasTargets = totalTargets(stats) > 0;
  const visible = auto && Boolean(working || phase || waiting || blocked || cfg.collector_phase_text);
  const isFofa = engine === "fofa";
  const keySource = isFofa ? String(cfg.key_source || "global_pool") : "";
  const cooldownUntil = cfg.cooldown_until || cfg.fofa_next_retry_at || null;
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const parsedCooldown = cooldownUntil ? Date.parse(cooldownUntil) : NaN;
  const cooldownExpired = Number.isFinite(parsedCooldown) && parsedCooldown <= nowMs;

  let tone = "neutral";
  if (blocked) tone = "blocked";
  else if (waiting && !cooldownExpired) tone = "waiting";
  else if (working) tone = "active";

  let label = "搜集状态更新中";
  if (phaseKnown && cfg.collector_phase_text) label = String(cfg.collector_phase_text);
  else if (blocked) label = "FOFA 凭据池暂无可用 Key";
  else if (waiting) label = "FOFA 凭据池处于冷却期";
  else if (working) label = "正在初始化搜集引擎";
  else if (phase === "exhausted") label = "本轮无新增资产";

  return {
    visible,
    progressMode: working && !hasTargets ? "collecting" : "disposition",
    tone,
    indeterminate: working && !hasTargets && (!phase || ACTIVE_PHASES.has(phase)),
    label,
    phase,
    phaseKnown,
    lastKeyName: isFofa ? String(cfg.last_key_name || "") : "",
    rotation: isFofa && isRecord(cfg.last_rotation) ? cfg.last_rotation : null,
    cooldownUntil,
    cooldownExpired,
    now: nowMs,
    isFofa,
    keySource,
    keySourceLabel: isFofa ? keySourceLabel(keySource) : "",
    poolAvailable: isFofa && keySource !== "task_override"
      && Object.hasOwn(cfg, "pool_available") && Number.isFinite(Number(cfg.pool_available))
      ? Number(cfg.pool_available) : null,
    poolTotal: isFofa && keySource !== "task_override"
      && Object.hasOwn(cfg, "pool_total") && Number.isFinite(Number(cfg.pool_total))
      ? Number(cfg.pool_total) : null,
    settingsPath: blocked ? "/settings" : "",
  };
}

export const collectorStatusPhases = Object.freeze({
  active: ACTIVE_PHASES,
  waiting: WAITING_PHASES,
  blocked: BLOCKED_PHASES,
});
