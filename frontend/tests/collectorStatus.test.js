import test from "node:test";
import assert from "node:assert/strict";
import {
  collectorViewModel,
  isAutoCollectionTask,
  mergeCollectorEvent,
} from "../src/collectorStatus.js";

test("FOFA task with no targets starts in collecting mode", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", search_enabled: true },
    { queued: 0, scanning: 0, done: 0 },
    { collector_phase: "initializing", collector_phase_text: "正在初始化 FOFA 搜集引擎" },
  );
  assert.equal(isAutoCollectionTask({ target_source: "fofa", search_enabled: true }), true);
  assert.equal(model.progressMode, "collecting");
  assert.equal(model.tone, "active");
  assert.equal(model.indeterminate, true);
  assert.equal(model.label, "正在初始化 FOFA 搜集引擎");
});

test("rotation keeps disposition progress once targets exist", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", engine: "fofa", search_enabled: true },
    { queued: 3, scanning: 1, done: 4 },
    {
      engine: "fofa",
      collector_phase: "querying",
      pool_state: "ready",
      last_key_name: "Backup",
      last_rotation: { from_key_name: "Primary", to_key_name: "Backup", reason: "rate_limit" },
    },
  );
  assert.equal(model.progressMode, "disposition");
  assert.equal(model.rotation.to_key_name, "Backup");
  assert.equal(model.tone, "active");
});

test("all cooling stops animation and reports waiting state", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", engine: "fofa", search_enabled: true },
    { queued: 2, scanning: 0, done: 3 },
    { engine: "fofa", collector_phase: "fofa_cooldown", pool_state: "cooling", cooldown_until: "2026-07-17T00:20:00Z" },
    Date.parse("2026-07-17T00:00:00Z"),
  );
  assert.equal(model.tone, "waiting");
  assert.equal(model.indeterminate, false);
  assert.equal(model.cooldownUntil, "2026-07-17T00:20:00Z");
});

test("blocked state is static and exposes the settings route", () => {
  const model = collectorViewModel(
    { status: "paused", target_source: "fofa", search_enabled: true },
    { queued: 1 },
    { engine: "fofa", collector_phase: "fofa_pool_blocked", pool_state: "blocked" },
  );
  assert.equal(model.tone, "blocked");
  assert.equal(model.indeterminate, false);
  assert.equal(model.settingsPath, "/settings");
});

test("partial WebSocket event preserves existing runtime fields", () => {
  const merged = mergeCollectorEvent(
    { last_key_name: "Backup", pool_available: 2, pool_total: 3, last_rotation: { reason: "rate_limit" } },
    { kind: "fofa_key_rotated", to_key_name: "Reserve", reason: "auth" },
  );
  assert.equal(merged.last_key_name, "Reserve");
  assert.equal(merged.pool_available, 2);
  assert.equal(merged.pool_total, 3);
  assert.deepEqual(merged.last_rotation, { to_key_name: "Reserve", reason: "auth" });
});

test("non-FOFA engine keeps generic collector state without pool details", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", search_enabled: true },
    { queued: 0, scanning: 0, done: 0 },
    { engine: "quake", collector_phase: "querying", pool_state: "ready", pool_available: 2 },
  );
  assert.equal(model.visible, true);
  assert.equal(model.isFofa, false);
  assert.equal(model.poolAvailable, null);
  assert.equal(model.indeterminate, true);
});

test("task override labels the key as task-only instead of global pool", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", search_enabled: true },
    { queued: 1 },
    { engine: "fofa", key_source: "task_override", last_key_name: "Task Secret", collector_phase: "querying" },
  );
  assert.equal(model.keySource, "task_override");
  assert.equal(model.keySourceLabel, "任务专用 Key");
  assert.equal(model.poolAvailable, null);
});

test("legacy fallback is shown as a read-only key outside pool management", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "fofa", search_enabled: true },
    { queued: 0 },
    { engine: "fofa", key_source: "legacy", pool_available: 0, pool_total: 0, collector_phase: "querying" },
  );
  assert.equal(model.lastKeyName, "Legacy Key");
  assert.equal(model.keySourceLabel, "Legacy Key");
  assert.equal(model.keyReadonly, true);
  assert.equal(model.poolAvailable, null);
});

test("unknown collector state is neutral and does not animate", () => {
  const model = collectorViewModel(
    { status: "running", target_source: "both", search_enabled: true },
    { queued: 0 },
    { engine: "fofa", collector_phase: "mystery_state" },
  );
  assert.equal(model.tone, "neutral");
  assert.equal(model.label, "搜集状态更新中");
  assert.equal(model.indeterminate, false);
});
