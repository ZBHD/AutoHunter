import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { modelProbePayload } from "../src/llmProviders.js";

test("dedicated task model probes keep protocol without a provider binding", () => {
  const payload = modelProbePayload({
    baseUrl: "https://api.anthropic.com",
    apiKey: "task-secret",
    protocol: "anthropic_messages",
  });

  assert.deepEqual(payload, {
    base_url: "https://api.anthropic.com",
    api_key: "task-secret",
    protocol: "anthropic_messages",
  });
  assert.equal("provider_name" in payload, false);
});

test("task editor forwards its selected protocol as the third listModels argument", () => {
  const source = readFileSync(
    new URL("../src/components/TaskEditModal.vue", import.meta.url),
    "utf8",
  );

  assert.match(
    source,
    /api\.listModels\(\s*form\.base_url\s*\|\|\s*undefined,\s*form\.api_key\s*\|\|\s*undefined,\s*form\.protocol,?\s*\)/,
  );
});
