import fs from "node:fs";
import test from "node:test";
import assert from "node:assert/strict";

const panel = fs.readFileSync(
  new URL("../src/components/FofaKeysPanel.vue", import.meta.url),
  "utf8",
);
const settings = fs.readFileSync(
  new URL("../src/views/SettingsView.vue", import.meta.url),
  "utf8",
);

test("settings keeps FOFA key pool management and stale health results", () => {
  assert.match(panel, /FOFA Key 池/);
  assert.match(panel, /fofaKeyStatus/);
  assert.match(panel, /cooldownLabel/);
  assert.match(panel, /接管并编辑/);
  assert.match(settings, /FofaKeysPanel/);
  assert.match(settings, /applyHealthCheck/);
});
