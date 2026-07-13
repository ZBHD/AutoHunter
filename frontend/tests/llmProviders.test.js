import test from "node:test";
import assert from "node:assert/strict";

import {
  canReuseSavedProviderKey,
  isLegacyProvider,
  isProviderUsable,
  modelProbePayload,
  moveProvider,
  needsEffectiveProviderReload,
  providerList,
  weightDistribution,
} from "../src/llmProviders.js";

test("saved provider keys can only probe the original base URL", () => {
  assert.equal(
    canReuseSavedProviderKey("https://api.example/v1", "https://api.example/v1/"),
    true,
  );
  assert.equal(
    canReuseSavedProviderKey("https://api.example/v1", "https://other.example/v1"),
    false,
  );
  assert.equal(canReuseSavedProviderKey("", "https://api.example/v1"), false);
});

test("weightDistribution calculates enabled provider percentages", () => {
  const distribution = weightDistribution([
    { name: "Primary", weight: 3, enabled: true, api_key_set: true },
    { name: "Backup", weight: 1, enabled: true, api_key_set: true },
  ]);

  assert.deepEqual(
    distribution.map(({ name, percentage }) => [name, percentage]),
    [["Primary", 75], ["Backup", 25]],
  );
});

test("weightDistribution excludes disabled providers", () => {
  const distribution = weightDistribution([
    { name: "Primary", weight: 2, enabled: true, api_key_set: true },
    { name: "Paused", weight: 100, enabled: false, api_key_set: true },
    { name: "Backup", weight: 1, enabled: true, api_key_set: true },
  ]);

  assert.deepEqual(distribution.map(({ name }) => name), ["Primary", "Backup"]);
  assert.equal(Math.round(distribution[0].percentage * 10) / 10, 66.7);
  assert.equal(Math.round(distribution[1].percentage * 10) / 10, 33.3);
});

test("provider usability and weight distribution exclude enabled providers without a key", () => {
  const providers = [
    { name: "Ready", weight: 3, enabled: true, api_key_set: true },
    { name: "Keyless legacy", weight: 100, enabled: true, api_key_set: false },
    { name: "Paused", weight: 10, enabled: false, api_key_set: true },
  ];

  assert.equal(isProviderUsable(providers[0]), true);
  assert.equal(isProviderUsable(providers[1]), false);
  assert.equal(isProviderUsable(providers[2]), false);
  assert.deepEqual(weightDistribution(providers).map(({ name }) => name), ["Ready"]);
});

test("legacy detection relies on the public read-only contract, not the provider name", () => {
  assert.equal(isLegacyProvider({ name: "Legacy default", source: "database", read_only: false }), false);
  assert.equal(isLegacyProvider({ name: "Anything", source: "legacy", read_only: false }), true);
  assert.equal(isLegacyProvider({ name: "Anything", source: "database", read_only: true }), true);
});

test("providerList accepts GET arrays and wrapped mutation responses", () => {
  const providers = [{ name: "Primary" }];

  assert.equal(providerList(providers), providers);
  assert.equal(providerList({ providers }), providers);
  assert.deepEqual(providerList({}), []);
});

test("empty mutation responses require reloading the effective legacy view", () => {
  assert.equal(needsEffectiveProviderReload({ providers: [] }), true);
  assert.equal(needsEffectiveProviderReload([]), true);
  assert.equal(needsEffectiveProviderReload({ providers: [{ name: "Primary" }] }), false);
});

test("moveProvider moves a name up without mutating the input", () => {
  const names = ["Primary", "Backup", "Reserve"];

  assert.deepEqual(moveProvider(names, 1, -1), ["Backup", "Primary", "Reserve"]);
  assert.deepEqual(names, ["Primary", "Backup", "Reserve"]);
});

test("moveProvider moves a name down and keeps boundary moves stable", () => {
  const names = ["Primary", "Backup", "Reserve"];

  assert.deepEqual(moveProvider(names, 1, 1), ["Primary", "Reserve", "Backup"]);
  assert.deepEqual(moveProvider(names, 0, -1), names);
  assert.deepEqual(moveProvider(names, 2, 1), names);
});

test("modelProbePayload sends the active draft protocol and saved provider name", () => {
  assert.deepEqual(
    modelProbePayload({
      baseUrl: " https://api.anthropic.com ",
      apiKey: " new-secret ",
      protocol: "anthropic_messages",
      providerName: " Claude ",
    }),
    {
      base_url: "https://api.anthropic.com",
      api_key: "new-secret",
      protocol: "anthropic_messages",
      provider_name: "Claude",
    },
  );
});
