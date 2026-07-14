import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("create view renders and submits the optional hunt direction", () => {
  const view = source("../src/views/CreateView.vue");

  assert.match(view, /指定挖掘方向（可选）/);
  assert.match(view, /<textarea[^>]*v-model="form\.hunt_direction"[^>]*rows="3"[^>]*maxlength="2000"/);
  assert.match(view, /hunt_direction:\s*form\.hunt_direction\.trim\(\)/);
});
test("task edit modal fills, saves and can clear the hunt direction", () => {
  const view = source("../src/components/TaskEditModal.vue");

  assert.match(view, /hunt_direction:\s*""/);
  assert.match(view, /form\.hunt_direction\s*=\s*task\.hunt_direction\s*\|\|\s*""/);
  assert.match(view, /指定挖掘方向（可选）/);
  assert.match(view, /<textarea[^>]*v-model="form\.hunt_direction"[^>]*rows="3"[^>]*maxlength="2000"/);
  assert.match(view, /hunt_direction:\s*form\.hunt_direction\.trim\(\)/);
});
