import test from "node:test";
import assert from "node:assert/strict";

import {
  draftContentFromForm,
  draftFormFromContent,
  missedSignalListParams,
} from "../src/missedSignals.js";
import {
  intelFiltersForKillsweep,
  killsweepListParams,
} from "../src/killsweeps.js";

test("missed-signal list parameters use 50-row server pages and omit all status", () => {
  assert.deepEqual(
    missedSignalListParams({ status: "all", q: " login ", page: 2 }),
    { q: "login", limit: 50, offset: 100 },
  );
  assert.deepEqual(
    missedSignalListParams({ status: "rejected", q: "", page: 0 }),
    { status: "rejected", limit: 50, offset: 0 },
  );
});

test("draft form keeps editable arrays human-readable without changing evidence objects", () => {
  const content = {
    title: "未授权读取",
    steps: ["访问接口", "读取记录"],
    kill_chain: [
      { method: "定位", detail: "发现接口" },
      { method: "取证", detail: "返回用户数据" },
    ],
    evidence: { extracted_data_sample: "id=1" },
  };

  const form = draftFormFromContent(content);
  assert.equal(form.steps, "访问接口\n读取记录");
  assert.equal(form.kill_chain, "定位｜发现接口\n取证｜返回用户数据");
  assert.equal(form.evidence_json, '{\n  "extracted_data_sample": "id=1"\n}');

  form.evidence_json = '{"extracted_data_sample":"id=2"}';
  const saved = draftContentFromForm(form, content);
  assert.deepEqual(saved.steps, ["访问接口", "读取记录"]);
  assert.deepEqual(saved.kill_chain, content.kill_chain);
  assert.deepEqual(saved.evidence, { extracted_data_sample: "id=2" });
  assert.equal("evidence_json" in saved, false);
});

test("killsweep list parameters preserve current filters and server paging", () => {
  assert.deepEqual(
    killsweepListParams({ status: "failed", manualVerdict: "invalid", q: " OA ", page: 1 }),
    { status: "failed", manual_verdict: "invalid", q: "OA", limit: 50, offset: 50 },
  );
  assert.deepEqual(
    killsweepListParams({ status: "all", manualVerdict: "all", page: 0 }),
    { limit: 50, offset: 0 },
  );
});

test("killsweep intelligence link carries product and task filters", () => {
  assert.deepEqual(
    intelFiltersForKillsweep({ task_id: "task-7", product_name: "校园 OA" }),
    { task_id: "task-7", q: "校园 OA" },
  );
});
