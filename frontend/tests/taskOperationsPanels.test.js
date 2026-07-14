import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const board = readFileSync(new URL("../src/views/BoardView.vue", import.meta.url), "utf8");
const scanned = readFileSync(
  new URL("../src/components/task/ScannedTargetsPanel.vue", import.meta.url),
  "utf8",
);
const findings = readFileSync(
  new URL("../src/components/task/RawFindingsPanel.vue", import.meta.url),
  "utf8",
);

test("task metrics are semantic navigation buttons with persistent views", () => {
  assert.match(board, /class="metric-card metric-action[^"]*"/);
  assert.match(board, /selectTaskView\(['"]scanned['"]\)/);
  assert.match(board, /selectTaskView\(['"]findings['"]\)/);
  assert.match(board, /selectTaskView\(['"]review['"]\)/);
  assert.match(board, /selectTaskView\(['"]submit['"]\)/);
  assert.match(board, /selectTaskView\(['"]killsweep['"]\)/);
  assert.match(board, /metric-action warn[^>]+tab === 'review'/);
  assert.match(board, /metric-action ok[^>]+tab === 'submit'/);
  assert.match(board, /metric-action sweep[^>]+tab === 'killsweep'/);
  assert.match(board, /route\.query\.view/);
  assert.match(board, /ScannedTargetsPanel/);
  assert.match(board, /RawFindingsPanel/);
});

test("scanned targets use terminal pagination and load target audit details", () => {
  assert.match(scanned, /api\.terminalTargets/);
  assert.match(scanned, /limit:\s*PAGE_SIZE/);
  assert.match(scanned, /api\.targetDetail/);
  assert.match(scanned, /finding_count/);
  assert.match(scanned, /open-finding/);
});

test("raw findings use server pagination and explicit all or filtered downloads", () => {
  assert.match(findings, /api\.rawFindings/);
  assert.match(findings, /downloadScope/);
  assert.match(findings, /value="all"/);
  assert.match(findings, /value="filtered"/);
  assert.match(findings, /downloadMarkdownReports/);
  assert.match(findings, /api\.finding/);
  assert.match(findings, /open-finding/);
});
