import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import * as providerHelpers from "../src/llmProviders.js";

const response = {
  checked_at: "2026-07-14T03:20:00+08:00",
  provider_results: [
    {
      name: "Primary",
      ok: true,
      latency_ms: 128,
      model: "gpt-4.1-mini",
      protocol: "openai_responses",
      error: "",
      enabled: true,
      auto_disabled: false,
      stale: false,
    },
    {
      name: "Backup",
      ok: false,
      latency_ms: 412,
      model: "claude-sonnet",
      protocol: "anthropic_messages",
      error: "鉴权失败",
      enabled: false,
      auto_disabled: true,
      stale: false,
    },
  ],
  fofa_result: {
    name: "FOFA",
    ok: true,
    latency_ms: 84,
    error: "",
    enabled: true,
    auto_disabled: false,
    stale: false,
  },
  providers: [
    { name: "Primary", enabled: true, api_key_set: true },
    { name: "Backup", enabled: false, api_key_set: true },
  ],
};

test("health summary aggregates providers and FOFA in stable display order", () => {
  assert.equal(typeof providerHelpers.summarizeHealthCheck, "function");

  const summary = providerHelpers.summarizeHealthCheck(response);

  assert.equal(summary.checkedAt, response.checked_at);
  assert.equal(summary.total, 3);
  assert.equal(summary.passed, 2);
  assert.equal(summary.failed, 1);
  assert.equal(summary.autoDisabled, 1);
  assert.equal(summary.stale, false);
  assert.deepEqual(summary.results.map((item) => item.name), ["Primary", "Backup", "FOFA"]);
});

test("health summary and explicit invalidation preserve stale state without mutating input", () => {
  assert.equal(typeof providerHelpers.markHealthCheckStale, "function");
  assert.equal(typeof providerHelpers.summarizeHealthCheck, "function");

  const original = structuredClone(response);
  original.provider_results[0].stale = true;
  const backendStale = providerHelpers.summarizeHealthCheck(original);
  const marked = providerHelpers.markHealthCheckStale(response);

  assert.equal(backendStale.stale, true);
  assert.equal(marked.stale, true);
  assert.equal(response.stale, undefined);
  assert.notEqual(marked, response);
});

test("provider health snapshot returns updated public providers and row results", () => {
  assert.equal(typeof providerHelpers.providerHealthSnapshot, "function");

  const snapshot = providerHelpers.providerHealthSnapshot(response);

  assert.deepEqual(snapshot.providers, response.providers);
  assert.deepEqual(snapshot.results.map((item) => [item.name, item.ok, item.auto_disabled]), [
    ["Primary", true, false],
    ["Backup", false, true],
  ]);
});

test("frontend API exposes the fixed no-body health-check endpoint", () => {
  const source = readFileSync(new URL("../src/api.js", import.meta.url), "utf8");

  assert.match(
    source,
    /healthCheck:\s*\(\)\s*=>\s*req\("POST",\s*"\/api\/settings\/health-check"\)/,
  );
});

test("provider panel exposes health synchronization and emits CRUD invalidation", () => {
  const source = readFileSync(
    new URL("../src/components/LlmProvidersPanel.vue", import.meta.url),
    "utf8",
  );

  assert.match(source, /defineEmits\(\["change",\s*"mutated"\]\)/);
  assert.match(source, /defineExpose\(\{\s*applyHealthCheck\s*\}\)/);
  assert.match(source, /emit\("mutated"\)/);
});

test("settings view wires the health action, live region, and stale event", () => {
  const source = readFileSync(new URL("../src/views/SettingsView.vue", import.meta.url), "utf8");

  assert.match(source, /ref="providerPanel"/);
  assert.match(source, /@mutated="markHealthStale"/);
  assert.match(source, /@click="runHealthCheck"/);
  assert.match(source, /aria-live="polite"/);
});

test("saving FOFA settings invalidates the previous health result", () => {
  const source = readFileSync(new URL("../src/views/SettingsView.vue", import.meta.url), "utf8");
  const saveBody = source.match(/async function save\(\) \{([\s\S]*?)\n\}/)?.[1] || "";

  assert.match(saveBody, /await api\.updateSettings\(body\)/);
  assert.match(saveBody, /markHealthStale\(\)/);
});
