import test from "node:test";
import assert from "node:assert/strict";

import {
  categoryLabel,
  cooldownLabel,
  endpointModeLabel,
  fofaHealthSnapshot,
  fofaKeyList,
  fofaKeyStatus,
  formatFofaCooldown,
  isFofaKeyUsable,
  isLegacyFofaKey,
  moveFofaKey,
  needsEffectiveFofaKeyReload,
} from "../src/fofaKeys.js";

test("fofaKeyList accepts GET arrays and wrapped mutation responses", () => {
  const keys = [{ name: "Primary" }];

  assert.equal(fofaKeyList(keys), keys);
  assert.equal(fofaKeyList({ fofa_keys: keys }), keys);
  assert.deepEqual(fofaKeyList({}), []);
});

test("legacy FOFA keys are read-only and empty mutations request an effective reload", () => {
  assert.equal(isLegacyFofaKey({ source: "legacy" }), true);
  assert.equal(isLegacyFofaKey({ read_only: true }), true);
  assert.equal(isLegacyFofaKey({ source: "database", read_only: false }), false);
  assert.equal(needsEffectiveFofaKeyReload({ fofa_keys: [] }), true);
  assert.equal(needsEffectiveFofaKeyReload({ fofa_keys: [{ name: "Primary" }] }), false);
});

test("FOFA usability excludes disabled, blocked, and cooling entries", () => {
  assert.equal(isFofaKeyUsable({ enabled: true, key_set: true, runtime_state: "ready" }), true);
  assert.equal(isFofaKeyUsable({ enabled: false, key_set: true, runtime_state: "ready" }), false);
  assert.equal(isFofaKeyUsable({ enabled: true, key_set: true, runtime_state: "auth_invalid" }), false);
  assert.equal(isFofaKeyUsable({
    enabled: true,
    key_set: true,
    runtime_state: "rate_limited",
    cooldown_until: "2026-07-16T12:01:00Z",
  }, Date.parse("2026-07-16T12:00:00Z")), false);
  assert.equal(isFofaKeyUsable({
    enabled: true,
    key_set: true,
    runtime_state: "rate_limited",
    cooldown_until: "2026-07-16T11:59:00Z",
  }, Date.parse("2026-07-16T12:00:00Z")), true);
  assert.equal(isFofaKeyUsable({
    enabled: true,
    key_set: true,
    runtime_state: "transient_cooldown",
    cooldown_until: "2026-07-16T12:01:00Z",
  }, Date.parse("2026-07-16T12:00:00Z")), false);
  assert.equal(isFofaKeyUsable({
    enabled: true,
    key_set: true,
    runtime_state: "transient_cooldown",
    cooldown_until: "2026-07-16T11:59:00Z",
  }, Date.parse("2026-07-16T12:00:00Z")), true);
});

test("moveFofaKey reorders names without mutating the input", () => {
  const names = ["Primary", "Backup", "Reserve"];

  assert.deepEqual(moveFofaKey(names, 1, -1), ["Backup", "Primary", "Reserve"]);
  assert.deepEqual(moveFofaKey(names, 1, 1), ["Primary", "Reserve", "Backup"]);
  assert.deepEqual(moveFofaKey(names, 0, -1), names);
  assert.deepEqual(names, ["Primary", "Backup", "Reserve"]);
});

test("health snapshot keeps multi-key metadata and supports the legacy result", () => {
  const snapshot = fofaHealthSnapshot({
    fofa_keys: [{ name: "Primary", is_active: true }],
    fofa_results: [{
      name: "Primary",
      ok: false,
      category: "rate_limit",
      runtime_state: "rate_limited",
      latency_ms: 120,
      resolved_url: "https://mirror.example/api.php",
      endpoint_mode: "api_php",
      http_status: 429,
      cooldown_until: "2026-07-16T12:01:00Z",
    }],
  });

  assert.deepEqual(snapshot.keys, [{ name: "Primary", is_active: true }]);
  assert.equal(snapshot.legacy, false);
  assert.deepEqual(snapshot.results[0], {
    name: "Primary",
    ok: false,
    category: "rate_limit",
    runtime_state: "rate_limited",
    latency_ms: 120,
    error: "",
    resolved_url: "https://mirror.example/api.php",
    endpoint_mode: "api_php",
    http_status: 429,
    cooldown_until: "2026-07-16T12:01:00Z",
    enabled: true,
    auto_blocked: false,
    stale: false,
  });

  const legacy = fofaHealthSnapshot({ fofa_result: { ok: true, latency_ms: 34 } });
  assert.equal(legacy.legacy, true);
  assert.equal(legacy.results[0].name, "FOFA");
  assert.equal(legacy.results[0].ok, true);
});

test("status and labels explain runtime state, category, endpoint mode, and cooldown", () => {
  assert.deepEqual(fofaKeyStatus({ enabled: false, runtime_state: "ready" }), {
    code: "manual_disabled",
    label: "手动停用",
    tone: "muted",
  });
  assert.deepEqual(fofaKeyStatus({ enabled: true, runtime_state: "auth_invalid" }), {
    code: "auth_invalid",
    label: "Key 无效",
    tone: "danger",
  });
  assert.deepEqual(fofaKeyStatus({ enabled: true, runtime_state: "transient_cooldown" }), {
    code: "transient_cooldown",
    label: "临时故障冷却",
    tone: "warn",
  });
  assert.equal(categoryLabel("daily_limit"), "每日额度");
  assert.equal(endpointModeLabel("api_php"), "完整地址");
  assert.equal(cooldownLabel("2026-07-16T12:00:00Z", Date.parse("2026-07-16T11:59:05Z")), "55 秒后恢复");
  assert.equal(cooldownLabel("2026-07-16T11:59:00Z", Date.parse("2026-07-16T11:59:05Z")), "冷却已结束");
  assert.equal(formatFofaCooldown("2026-07-16T12:00:00Z", Date.parse("2026-07-16T11:59:05Z")), "55 秒后恢复");
});
