import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const sources = [
  "src/views/CreateView.vue",
  "src/components/TaskEditModal.vue",
  "src/views/SettingsView.vue",
].map((path) => ({ path, text: readFileSync(new URL(`../${path}`, import.meta.url), "utf8") }));

test("prompt selectors default to current while keeping compatibility profiles", () => {
  for (const { path, text } of sources) {
    assert.doesNotMatch(text, /prompt_version:\s*"legacy"|worker_prompt_version:\s*"legacy"|prompt_version\s*\|\|\s*"legacy"|worker_prompt_version\s*\|\|\s*"legacy"/, path);
    assert.match(text, /value="current"/, path);
    assert.match(text, /value="modern"/, path);
    assert.match(text, /value="legacy"/, path);
  }
});
