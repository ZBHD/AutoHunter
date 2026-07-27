import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const sources = [
  "src/views/CreateView.vue",
  "src/components/TaskEditModal.vue",
  "src/views/SettingsView.vue",
].map((path) => ({ path, text: readFileSync(new URL(`../${path}`, import.meta.url), "utf8") }));

test("ordinary task forms use Stable without exposing or sending prompt profiles", () => {
  for (const { path, text } of sources.slice(0, 2)) {
    assert.doesNotMatch(text, /prompt_version|Worker 提示词/, path);
    assert.doesNotMatch(text, /value="(?:current|modern|legacy)"/, path);
  }
});

test("settings show the Stable release read-only without sending a profile override", () => {
  const { path, text } = sources[2];
  assert.match(text, /stable_prompt_release_id/, path);
  assert.doesNotMatch(text, /worker_prompt_version|v-model="form\.(?:worker_)?prompt/, path);
  assert.doesNotMatch(text, /value="(?:current|modern|legacy)"/, path);
});
