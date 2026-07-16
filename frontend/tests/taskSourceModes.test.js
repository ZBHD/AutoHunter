import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  isAutoSource,
  isManualOnly,
  isSiteSource,
  isFofaPoolMode,
} from "../src/taskSourceModes.js";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("classifies task target sources", () => {
  assert.equal(isAutoSource("fofa"), true);
  assert.equal(isAutoSource("both"), true);
  assert.equal(isAutoSource("manual"), false);
  assert.equal(isManualOnly("manual"), true);
  assert.equal(isManualOnly("both"), false);
  assert.equal(isSiteSource("site"), true);
  assert.equal(isSiteSource("fofa"), false);
});

test("uses FOFA pool for auto source with FOFA or default engine only", () => {
  assert.equal(isFofaPoolMode("fofa", ""), true);
  assert.equal(isFofaPoolMode("both", undefined), true);
  assert.equal(isFofaPoolMode("fofa", "fofa"), true);
  assert.equal(isFofaPoolMode("both", "quake"), false);
  assert.equal(isFofaPoolMode("manual", "fofa"), false);
  assert.equal(isFofaPoolMode("site", ""), false);
});

test("create and edit forms expose an independent FOFA key source switch", () => {
  const create = source("../src/views/CreateView.vue");
  const edit = source("../src/components/TaskEditModal.vue");
  for (const view of [create, edit]) {
    assert.match(view, /fofa_key_mode/);
    assert.match(view, /使用全局 FOFA Key 池/);
    assert.match(view, /任务专用 FOFA Key/);
    assert.match(view, /不参与全局轮换/);
    assert.match(view, /isFofaPoolMode/);
  }
});
