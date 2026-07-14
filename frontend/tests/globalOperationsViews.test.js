import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

function source(path) {
  try {
    return readFileSync(new URL(path, import.meta.url), "utf8");
  } catch {
    return "";
  }
}

test("router registers protected global missed-signal and killsweep pages", () => {
  const main = source("../src/main.js");
  assert.match(main, /import MissedSignalsView from "\.\/views\/MissedSignalsView\.vue"/);
  assert.match(main, /import KillsweepsView from "\.\/views\/KillsweepsView\.vue"/);
  assert.match(main, /path:\s*"\/missed-signals"[^\n]+MissedSignalsView/);
  assert.match(main, /path:\s*"\/killsweeps"[^\n]+KillsweepsView/);
});

test("missed-signal operations page has server filters, search, manual refresh and pagination", () => {
  const view = source("../src/views/MissedSignalsView.vue");
  assert.match(view, /api\.missedSignalStats\(/);
  assert.match(view, /api\.missedSignals\(missedSignalListParams/);
  assert.match(view, /pending[\s\S]*deepening[\s\S]*converted[\s\S]*rejected[\s\S]*all/);
  assert.match(view, /v-model="searchDraft"/);
  assert.match(view, /<PagerBar/);
  assert.match(view, /@click="refresh"/);
  assert.doesNotMatch(view, /setInterval\(/);
});

test("missed-signal detail loads full evidence on demand and gates state actions", () => {
  const view = source("../src/views/MissedSignalsView.vue");
  const raw = source("../src/components/shared/RawEvidenceViewer.vue");
  assert.match(view, /<RawEvidenceViewer/);
  assert.match(raw, /api\.missedSignalEvidenceContent\(/);
  assert.match(raw, /加载原值/);
  assert.match(view, /v-if="writable"/);
  assert.match(view, /api\.deepenMissedSignal\(/);
  assert.match(view, /api\.rejectMissedSignal\(/);
  assert.match(view, /api\.restoreMissedSignal\(/);
});

test("missed-signal draft is persistent, autosaves after 600ms and confirms explicitly", () => {
  const draft = source("../src/components/missed-signals/MissedSignalDraftEditor.vue");
  assert.match(draft, /api\.generateMissedSignalDraft\(/);
  assert.match(draft, /catch \(generateError\)[\s\S]*await loadDraft\(signalId\)/);
  assert.match(draft, /api\.missedSignalDraft\(/);
  assert.match(draft, /delayMs:\s*600/);
  assert.match(draft, /editVersion/);
  assert.match(draft, /loadedSignalId/);
  assert.match(draft, /flushCurrentDraft/);
  assert.match(draft, /api\.updateMissedSignalDraft\(/);
  assert.match(draft, /revision/);
  assert.match(draft, /api\.confirmMissedSignalDraft\(/);
  assert.match(draft, /missing_evidence/);
});

test("killsweep center exposes status counts, split detail, manual refresh and timeline", () => {
  const view = source("../src/views/KillsweepsView.vue");
  assert.match(view, /pending_validation/);
  assert.match(view, /api\.killsweepStats\(/);
  assert.match(view, /api\.killsweepCases\(killsweepListParams/);
  assert.match(view, /class="operations-split/);
  assert.match(view, /<KillsweepTimeline/);
  assert.match(view, /api\.killsweepEvents\(/);
  assert.match(view, /@click="refresh"/);
  assert.match(view, /@change="changeManualFilter"/);
  assert.doesNotMatch(view, /watch\(manualVerdict/);
  assert.doesNotMatch(view, /setInterval\(/);
});

test("killsweep actions preserve automatic verdict and retry the current filters", () => {
  const view = source("../src/views/KillsweepsView.vue");
  assert.match(view, /自动结论/);
  assert.match(view, /人工结论/);
  assert.match(view, /api\.reviewKillsweep\(/);
  assert.match(view, /confirmed/);
  assert.match(view, /not_killsweep/);
  assert.match(view, /invalid/);
  assert.match(view, /api\.reanalyzeKillsweeps\(\{\s*filters:/);
  assert.match(view, /最多 40 条/);
  assert.match(view, /v-if="writable"/);
});

test("killsweep detail links to task home and filtered intelligence", () => {
  const view = source("../src/views/KillsweepsView.vue");
  const api = source("../src/api.js");
  const intel = source("../src/views/IntelView.vue");
  assert.match(view, /router\.push\(`\/task\/\$\{selected\.task_id\}`\)/);
  assert.match(view, /name:\s*"intel"/);
  assert.match(view, /intelFiltersForKillsweep/);
  assert.match(view, /<PagerBar/);
  assert.match(api, /killsweepEvidenceContent:/);
  assert.match(intel, /useRoute\(\)/);
  assert.match(intel, /route\.query\.task_id/);
  assert.match(intel, /source_task_id/);
});

test("operations styles are imported without embedding page CSS in the views", () => {
  const style = source("../src/style.css");
  const missed = source("../src/views/MissedSignalsView.vue");
  const killsweeps = source("../src/views/KillsweepsView.vue");
  assert.match(style, /@import "\.\/styles\/operations\.css"/);
  assert.doesNotMatch(missed, /<style/);
  assert.doesNotMatch(killsweeps, /<style/);
});
