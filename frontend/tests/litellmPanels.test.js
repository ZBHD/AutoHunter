import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { taskViewForRole } from "../src/taskViews.js";


const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const api = source("../src/api.js");
const board = source("../src/views/BoardView.vue");


test("API client registers every gateway endpoint", () => {
  assert.match(api, /gatewaySummary:[\s\S]*\/api\/tasks\/\$\{id\}\/gateway\/summary/);
  assert.match(api, /gatewayAssets:[\s\S]*\/api\/tasks\/\$\{id\}\/gateway\/assets/);
  assert.match(api, /gatewaySecrets:[\s\S]*\/api\/tasks\/\$\{id\}\/gateway\/secrets/);
  assert.match(api, /gatewaySecretExport:[\s\S]*\/gateway\/secrets\/export/);
  assert.match(api, /gatewayAsset:[\s\S]*\/api\/gateway\/assets\/\$\{assetId\}/);
  assert.match(api, /gatewayObservations:[\s\S]*\/observations/);
  assert.match(api, /recheckGatewayAsset:[\s\S]*\/recheck/);
  assert.match(api, /revalidateGatewaySecret:[\s\S]*\/revalidate/);
});


test("gateway task views are sensitive and observer-safe", () => {
  for (const view of ["gateway-assets", "gateway-secrets", "gateway-observations"]) {
    assert.equal(taskViewForRole(view, "observer"), "board");
    assert.equal(taskViewForRole(view, "readonly"), view);
    assert.equal(taskViewForRole(view, "full"), view);
  }
});


test("gateway panels expose expected operational controls", () => {
  const assets = source("../src/components/task/LiteLlmAssetsPanel.vue");
  const secrets = source("../src/components/task/LiteLlmSecretsPanel.vue");
  const observations = source("../src/components/task/LiteLlmObservationsPanel.vue");
  assert.match(assets, /api\.gatewaySummary/);
  assert.match(assets, /api\.gatewayAssets/);
  assert.match(assets, /api\.recheckGatewayAsset/);
  assert.match(secrets, /api\.gatewaySecrets/);
  assert.match(secrets, /secret_value/);
  assert.match(secrets, /copyText/);
  assert.match(secrets, /api\.revalidateGatewaySecret/);
  assert.match(secrets, /api\.gatewaySecretExport/);
  assert.match(observations, /api\.gatewayObservations/);
  assert.match(observations, /auth_variant/);
});


test("BoardView renders LiteLLM tabs only for readable LiteLLM tasks", () => {
  assert.match(board, /const isLiteLlmTask = computed/);
  assert.match(board, /LiteLlmAssetsPanel/);
  assert.match(board, /LiteLlmSecretsPanel/);
  assert.match(board, /LiteLlmObservationsPanel/);
  assert.match(board, /v-if="isLiteLlmTask && authRoleRef !== 'observer'"/);
  assert.match(board, /tab === 'gateway-assets'/);
  assert.match(board, /tab === 'gateway-secrets'/);
  assert.match(board, /tab === 'gateway-observations'/);
});
