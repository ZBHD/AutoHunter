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

test("health summary merges every FOFA pool result after the providers", () => {
  const poolResponse = {
    ...response,
    fofa_result: undefined,
    fofa_results: [
      { name: "FOFA-A", ok: true, latency_ms: 51, category: "ok" },
      { name: "FOFA-B", ok: false, latency_ms: 90, category: "rate_limit", auto_blocked: true },
    ],
  };

  const summary = providerHelpers.summarizeHealthCheck(poolResponse);

  assert.equal(summary.total, 4);
  assert.equal(summary.passed, 2);
  assert.equal(summary.failed, 2);
  assert.deepEqual(summary.results.map((item) => item.name), ["Primary", "Backup", "FOFA-A", "FOFA-B"]);
});

test("health summary prefers the FOFA pool result over the legacy fallback", () => {
  const summary = providerHelpers.summarizeHealthCheck({
    provider_results: [],
    fofa_results: [{ name: "FOFA-A", ok: true }],
    fofa_result: { name: "FOFA", ok: false },
  });

  assert.deepEqual(summary.results.map((item) => item.name), ["FOFA-A"]);
});

test("health summary keeps provider disable and FOFA runtime block counts separate", () => {
  const summary = providerHelpers.summarizeHealthCheck({
    provider_results: [{ name: "LLM", ok: false, auto_disabled: true }],
    fofa_results: [{ name: "FOFA", ok: false, auto_blocked: true }],
  });

  assert.equal(summary.autoDisabled, 1);
  assert.equal(summary.autoBlocked, 1);
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

test("frontend API translates fetch transport failures into a clear Chinese message", () => {
  const source = readFileSync(new URL("../src/api.js", import.meta.url), "utf8");

  assert.match(source, /连接服务器失败，请检查服务状态或网络后重试/);
});

test("frontend API exposes FOFA key CRUD, ordering, and detection endpoints", () => {
  const source = readFileSync(new URL("../src/api.js", import.meta.url), "utf8");

  assert.match(source, /listFofaKeys:\s*\(\)\s*=>\s*req\("GET",\s*"\/api\/settings\/fofa-keys"\)/);
  assert.match(source, /createFofaKey:\s*\(data\)\s*=>\s*req\("POST",\s*"\/api\/settings\/fofa-keys",\s*data\)/);
  assert.match(source, /updateFofaKey:\s*\(name,\s*data\)/);
  assert.match(source, /deleteFofaKey:\s*\(name\)/);
  assert.match(source, /testFofaKey:\s*\(name\)/);
  assert.match(source, /orderFofaKeys:\s*\(names\)/);
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

test("FOFA key panel exposes health synchronization and all pool actions", () => {
  const source = readFileSync(
    new URL("../src/components/FofaKeysPanel.vue", import.meta.url),
    "utf8",
  );

  assert.match(source, /defineEmits\(\["change",\s*"mutated"\]\)/);
  assert.match(source, /defineExpose\(\{\s*applyHealthCheck\s*\}\)/);
  assert.match(source, /api\.createFofaKey\(/);
  assert.match(source, /api\.updateFofaKey\(/);
  assert.match(source, /api\.deleteFofaKey\(/);
  assert.match(source, /api\.testFofaKey\(/);
  assert.match(source, /api\.orderFofaKeys\(/);
  assert.match(source, /api\.adoptLegacyFofaKey\(/);
  assert.match(source, /接管并编辑/);
  assert.match(source, /resolved_url/);
  assert.match(source, /endpoint_mode/);
  assert.match(source, /http_status/);
  assert.match(source, /item\.key/);
  assert.match(source.match(/async function reorder[\s\S]*?\n\}/)?.[0] || "", /emit\("mutated"\)/);
  assert.match(source, /deleteError/);
  assert.match(source, /mutationBusy/);
  assert.match(source, /isFofaKeyUsable\(item,\s*nowMs\.value\)/);
  assert.match(source, /function closeDelete\(force = false\)/);
  assert.match(source.match(/function closeEditor[\s\S]*?\n\}/)?.[0] || "", /draft\.key\s*=\s*""/);
});

test("settings view wires the health action, live region, and stale event", () => {
  const source = readFileSync(new URL("../src/views/SettingsView.vue", import.meta.url), "utf8");

  assert.match(source, /ref="providerPanel"/);
  assert.match(source, /ref="fofaKeyPanel"/);
  assert.match(source, /@mutated="markHealthStale"/);
  assert.match(source, /@click="runHealthCheck"/);
  assert.match(source, /aria-live="polite"/);
  assert.match(source, /fofaKeyPanel\.value\?\.applyHealthCheck\(response\)/);
  assert.match(source, /healthResultKey\(result,\s*index\)/);
});

test("health statistics reserve a column for runtime-blocked FOFA keys", () => {
  const source = readFileSync(new URL("../src/style.css", import.meta.url), "utf8");
  assert.match(source, /\.health-check-stats\s*\{[\s\S]*grid-template-columns:\s*repeat\(4,/);
});

test("saving FOFA settings invalidates the previous health result", () => {
  const source = readFileSync(new URL("../src/views/SettingsView.vue", import.meta.url), "utf8");
  const saveBody = source.match(/async function save\(\) \{([\s\S]*?)\n\}/)?.[1] || "";

  assert.match(saveBody, /await api\.updateSettings\(body\)/);
  assert.match(saveBody, /markHealthStale\(\)/);
});
