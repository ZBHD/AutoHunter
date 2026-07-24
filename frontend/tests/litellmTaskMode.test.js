import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  LITELLM_DEFAULT_CHECKS,
  buildLiteLlmTaskPayload,
  litellmFormFromTask,
  validateLiteLlmForm,
} from "../src/litellmTaskMode.js";


const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");


test("builds a global LiteLLM payload with all checks", () => {
  const body = buildLiteLlmTaskPayload({
    name: "lite",
    scopeMode: "global",
    target_source: "fofa",
  });
  assert.equal(body.src_type, "litellm");
  assert.equal(body.mode_config.validation.level, "full");
  assert.equal(body.mode_config.checks.anonymous_inference, true);
  assert.deepEqual(body.mode_config.checks, LITELLM_DEFAULT_CHECKS);
  assert.deepEqual(body.vuln_types, []);
});


test("normalizes targeted anchors and manual targets", () => {
  const body = buildLiteLlmTaskPayload({
    scopeMode: "targeted",
    scopeAnchors: " example.com\n cert:Example Corp \nexample.com ",
    manual_targets: "https://gateway.test/proxy\n\nhttps://two.test",
    checks: { ...LITELLM_DEFAULT_CHECKS, env_leak: false },
  });
  assert.deepEqual(body.mode_config.scope_anchors, ["example.com", "cert:Example Corp"]);
  assert.deepEqual(body.manual_targets, ["https://gateway.test/proxy", "https://two.test"]);
  assert.equal(body.mode_config.checks.env_leak, false);
});


test("validates global and targeted collection requirements", () => {
  assert.equal(validateLiteLlmForm({ scopeMode: "global", target_source: "manual" }).valid, false);
  assert.equal(validateLiteLlmForm({ scopeMode: "targeted", target_source: "manual" }).valid, false);
  assert.equal(validateLiteLlmForm({
    scopeMode: "targeted",
    target_source: "manual",
    manual_targets: "https://gateway.test",
  }).valid, true);
});


test("hydrates editable LiteLLM fields from task mode_config", () => {
  const form = litellmFormFromTask({
    mode_config: {
      scope_mode: "global",
      scope_anchors: ["example.com"],
      checks: { anonymous_inference: false },
      validation: { level: "basic", max_requests_per_asset_epoch: 10 },
      recheck_intervals: { confirmed_seconds: 7200 },
    },
  });
  assert.equal(form.scopeMode, "global");
  assert.equal(form.scopeAnchors, "example.com");
  assert.equal(form.checks.anonymous_inference, false);
  assert.equal(form.checks.key_leak, true);
  assert.equal(form.validationLevel, "basic");
  assert.equal(form.maxRequestsPerAssetEpoch, 10);
  assert.equal(form.confirmedRecheckHours, 2);
});


test("create and edit forms share LiteLLM helper and controls", () => {
  for (const path of ["../src/views/CreateView.vue", "../src/components/TaskEditModal.vue"]) {
    const view = source(path);
    assert.match(view, /buildLiteLlmTaskPayload/);
    assert.match(view, /validateLiteLlmForm/);
    assert.match(view, /value="litellm"/);
    assert.match(view, /LiteLLM 专项检测/);
    assert.match(view, /form\.scopeMode/);
  }
});
