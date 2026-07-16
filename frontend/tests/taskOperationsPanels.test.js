import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const board = readFileSync(new URL("../src/views/BoardView.vue", import.meta.url), "utf8");
const api = readFileSync(new URL("../src/api.js", import.meta.url), "utf8");
const style = readFileSync(new URL("../src/style.css", import.meta.url), "utf8");
const operationsStyle = readFileSync(new URL("../src/styles/operations.css", import.meta.url), "utf8");
const scanned = readFileSync(
  new URL("../src/components/task/ScannedTargetsPanel.vue", import.meta.url),
  "utf8",
);
const findings = readFileSync(
  new URL("../src/components/task/RawFindingsPanel.vue", import.meta.url),
  "utf8",
);
const boardView = readFileSync(new URL("../src/views/BoardView.vue", import.meta.url), "utf8");

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

test("raw findings support cross-page selection and download status filters", () => {
  assert.match(findings, /selectedIds/);
  assert.match(findings, /downloadStatus/);
  assert.match(findings, /download_status/);
  assert.match(findings, /value="selected"/);
  assert.match(findings, /downloadStatus === 'downloaded'/);
  assert.match(findings, /downloadStatus === 'pending'/);
  assert.match(findings, /markFindingsDownloaded/);
  assert.match(api, /markFindingsDownloaded/);
});

test("review queue supports multi-select Markdown export and download status tabs", () => {
  assert.match(boardView, /reviewSelectedIds/);
  assert.match(boardView, /reviewDownloadStatus/);
  assert.match(boardView, /reviewDownloadScope/);
  assert.match(boardView, /markFindingsDownloaded/);
  assert.match(boardView, /复审队列[\s\S]*已下载/);
  assert.match(boardView, /复审队列[\s\S]*未下载/);
  assert.match(boardView, /downloadMarkdownReports/);
  assert.doesNotMatch(boardView, /source\.map\(\(finding\) => buildReportMd/);
});

test("review and submit rows reserve a shared right-side metadata/action column", () => {
  assert.match(boardView, /class="review-result-open"[\s\S]*class="review-result-side"/);
  assert.match(boardView, /class="submit-result-side"[\s\S]*class="score"/);
  assert.match(operationsStyle, /\.review-result-open\{[\s\S]*grid-template-columns:minmax\(0,1fr\) auto/);
  assert.match(operationsStyle, /\.review-result-side,[\s\S]*\.submit-result-side,[\s\S]*justify-content:flex-end/);
});

test("raw findings expose severity-specific text color classes", () => {
  assert.match(findings, /class="raw-severity" :class="\[.*effectiveSeverity/);
  assert.match(findings, /\.raw-severity\.严重/);
  assert.match(findings, /\.raw-severity\.高危/);
  assert.match(findings, /\.raw-severity\.中危/);
  assert.match(findings, /\.raw-severity\.低危/);
});

test("severity pills center their text inside the colored background", () => {
  assert.match(style, /\.sev-pill\s*\{[\s\S]*display:\s*inline-flex/);
  assert.match(style, /\.sev-pill\s*\{[\s\S]*justify-content:\s*center/);
  assert.match(style, /\.sev-pill\s*\{[\s\S]*text-align:\s*center/);
});

test("AI 未采纳 reuses selection and independent Markdown download controls", () => {
  assert.match(boardView, /archivedSelectedIds/);
  assert.match(boardView, /archivedDownloadStatus/);
  assert.match(boardView, /archivedDownloadScope/);
  assert.match(boardView, /AI 未采纳[\s\S]*批量下载 Markdown/);
  assert.match(boardView, /archivedDownloadMarkdown/);
  assert.match(boardView, /downloadMarkdownReports/);
  assert.match(operationsStyle, /\.result-row\.archived-result-row\s*\{\s*display:\s*grid/);
  assert.match(operationsStyle, /\.archived-result-open[\s\S]*width:\s*100%/);
});

test("submit Markdown export uses independent files and the shared downloader", () => {
  const start = boardView.indexOf("async function exportAll()");
  const end = boardView.indexOf("\nfunction edusrcReports", start);
  assert.ok(start >= 0 && end > start);
  const handler = boardView.slice(start, end);
  assert.match(handler, /downloadMarkdownReports/);
  assert.match(handler, /buildDownloadReportMd/);
  assert.doesNotMatch(handler, /join\("\\n\\n---\\n\\n"\)/);
});

test("task board exposes the stop-search control contract", () => {
  assert.match(api, /stopSearch:\s*\(id\)\s*=>\s*req\("POST", `\/api\/tasks\/\$\{id\}\/stop-search`\)/);
  assert.match(board, /import \{[\s\S]*taskProgressSummary,[\s\S]*taskViewForRole,[\s\S]*taskSearchControl,[\s\S]*mergeTaskControlResponse,[\s\S]*isCurrentTaskRequest,[\s\S]*isCurrentTaskRefresh,[\s\S]*\} from "\.\.\/taskViews\.js"/);
  assert.match(board, /const stopSearchWorking = ref\(false\)/);
  assert.match(board, /const taskControlWorking = ref\(false\)/);
  assert.match(board, /const searchControl = computed\(\(\) => taskSearchControl\(task\.value, stopSearchWorking\.value, taskControlWorking\.value\)\)/);
  assert.match(board, /async function stopSearch\(\)[\s\S]*if \(taskControlWorking\.value \|\| !searchControl\.value\.canStop\) return[\s\S]*stopSearchWorking\.value = true/);
  assert.match(board, /api\.stopSearch\(requestTaskId\)/);
  assert.match(board, /已停止继续搜索，剩余队列将继续处理/);
  assert.match(board, /停止搜索失败：\$\{e\?\.message \|\| e\}/);
  assert.match(board, /stopSearchWorking\.value = false/);
  assert.match(board, /searchControl\.draining/);
  assert.match(board, /engineName\s*\}\}\s*·\s*已停止 · 正在排空队列/);
  assert.match(board, /searchControl\.visible && task\.search_enabled === false && task\.status === ['"]stopped['"]/);
  assert.match(board, /engineName\s*\}\}\s*·\s*搜索已停止 · 下次启动将恢复搜索/);
  assert.match(board, /v-else-if="task\.engine && task\.engine !== 'fofa'" class="engine-badge">🔍 \{\{ engineName \}\}<\/span>/);
  assert.match(board, /编辑参数[\s\S]*启动[\s\S]*暂停[\s\S]*class="stop-search"[\s\S]*searchControl\.label[\s\S]*停止任务/);
  assert.match(board, /@click="ctl\('stop'\)"/);
  assert.match(board, /@click="ctl\('start'\)" :disabled="task\.status === 'running' \|\| stopSearchWorking \|\| taskControlWorking"/);
  assert.match(board, /@click="ctl\('pause'\)" :disabled="task\.status !== 'running' \|\| stopSearchWorking \|\| taskControlWorking"/);
  assert.match(board, /class="stop-task"[^>]*:disabled="stopSearchWorking \|\| taskControlWorking"/);
  assert.match(style, /\.mission-actions \.stop-search/);
  assert.match(style, /\.mission-actions button \{ min-height: 36px; \}/);
  assert.match(style, /@media \(max-width:\s*640px\)[\s\S]*?\.mission-actions button \{[^}]*min-height:\s*42px/);
});

test("stop-search board refresh failures stay outside the operation failure path", () => {
  const start = board.indexOf("async function stopSearch()");
  const end = board.indexOf("\nfunction openEdit()", start);
  assert.ok(start >= 0 && end > start, "stopSearch handler should be present");

  const handler = board.slice(start, end);
  assert.match(handler, /catch \(e\) \{[\s\S]*停止搜索失败：[\s\S]*return;[\s\S]*\}/);
  assert.match(handler, /try \{\s*await loadBoard\(\{ expectedRequestVersion: requestVersion \}\);\s*\} catch \{/);

  const refreshPath = handler.slice(handler.indexOf("await loadBoard({ expectedRequestVersion: requestVersion })"));
  assert.doesNotMatch(refreshPath, /停止搜索失败/);
});

test("stop-search ignores responses from a stale task route", () => {
  const start = board.indexOf("async function stopSearch()");
  const end = board.indexOf("\nfunction openEdit()", start);
  assert.ok(start >= 0 && end > start, "stopSearch handler should be present");

  const handler = board.slice(start, end);
  const responsePos = handler.indexOf("await api.stopSearch(requestTaskId)");
  const updatePos = handler.indexOf("task.value = mergeTaskControlResponse");
  const successToastPos = handler.indexOf("已停止继续搜索，剩余队列将继续处理");
  const refreshPos = handler.indexOf("await loadBoard({ expectedRequestVersion: requestVersion })");
  const guardPositions = [...handler.matchAll(/if \(!isCurrentRequest\(\)\) return;/g)].map((match) => match.index);

  assert.match(handler, /const requestTaskId = props\.id/);
  assert.match(handler, /if \(taskControlWorking\.value \|\| !searchControl\.value\.canStop\) return/);
  assert.match(handler, /const requestVersion = \+\+taskControlRequestVersion/);
  assert.match(handler, /isCurrentTaskRequest\([\s\S]*requestVersion,[\s\S]*taskControlRequestVersion,[\s\S]*requestTaskId,[\s\S]*props\.id,[\s\S]*loadedTaskId\.value/);
  assert.ok(responsePos >= 0 && guardPositions.length === 2, "API response and errors need current-request guards");
  const successGuardPos = guardPositions.at(-1);
  assert.ok(successGuardPos > responsePos, "response must be checked after it resolves");
  assert.match(
    handler.slice(successGuardPos, updatePos + "task.value = mergeTaskControlResponse".length),
    /^if \(!isCurrentRequest\(\)\) return;\s*task\.value = mergeTaskControlResponse/,
  );
  assert.ok(updatePos > successGuardPos, "stale responses must not update task state");
  assert.ok(successToastPos > successGuardPos, "stale responses must not toast success");
  assert.ok(refreshPos > successGuardPos, "stale responses must not refresh the board");
  assert.match(handler, /if \(requestVersion === taskControlRequestVersion\) stopSearchWorking\.value = false/);
  assert.match(board, /function resetTaskState[\s\S]*taskControlRequestVersion \+= 1;[\s\S]*stopSearchWorking\.value = false/);
});

test("stop-search board refresh applies only the current request version", () => {
  const loadStart = board.indexOf("async function loadBoard(");
  const loadEnd = board.indexOf("\nfunction connectWs", loadStart);
  assert.ok(loadStart >= 0 && loadEnd > loadStart, "loadBoard handler should be present");

  const loadHandler = board.slice(loadStart, loadEnd);
  const applyPos = loadHandler.indexOf("liveWorkers.value =");
  const guardPos = loadHandler.indexOf("expectedRequestVersion !== undefined");
  assert.match(board, /await loadBoard\(\{ expectedRequestVersion: requestVersion \}\)/);
  assert.match(loadHandler, /async function loadBoard\(options = \{\}\)/);
  assert.match(loadHandler, /const expectedRequestVersion = options\.expectedRequestVersion/);
  assert.match(loadHandler, /expectedRequestVersion !== undefined[\s\S]*isCurrentTaskRequest\(/);
  assert.ok(guardPos >= 0 && applyPos > guardPos, "board response guard must run before applying b");
});

test("task lifecycle controls share an epoch and ignore stale command responses", () => {
  const start = board.indexOf("async function ctl(action)");
  const end = board.indexOf("\nasync function stopSearch()", start);
  assert.ok(start >= 0 && end > start, "ctl handler should be present");

  const handler = board.slice(start, end);
  const responsePos = handler.indexOf("await api[action](requestTaskId)");
  const guardPos = handler.indexOf("if (!isCurrentRequest()) return;");
  const updatePos = handler.indexOf("task.value = mergeTaskControlResponse");
  const toastPos = handler.indexOf("toast(");
  assert.match(board, /let taskControlRequestVersion = 0/);
  assert.doesNotMatch(board, /stopSearchRequestVersion/);
  assert.match(handler, /const requestTaskId = props\.id/);
  assert.match(handler, /const requestVersion = \+\+taskControlRequestVersion/);
  assert.match(handler, /taskControlWorking\.value = true/);
  assert.match(handler, /isCurrentTaskRequest\([\s\S]*requestVersion,[\s\S]*taskControlRequestVersion,[\s\S]*requestTaskId,[\s\S]*props\.id,[\s\S]*loadedTaskId\.value/);
  assert.ok(responsePos >= 0 && guardPos > responsePos, "ctl response needs a current-request guard");
  assert.ok(updatePos > guardPos && toastPos > guardPos, "stale ctl responses must not update or toast");
  assert.match(handler, /await loadBoard\(\{ expectedRequestVersion: requestVersion \}\)/);
});

test("mission actions switch to two columns at 320px without shrinking touch targets", () => {
  assert.match(style, /@media \(max-width:\s*640px\)[\s\S]*?\.mission-actions\s*\{[^}]*repeat\(3,/);
  assert.match(style, /@media \(max-width:\s*360px\)[\s\S]*?\.mission-actions\s*\{[^}]*repeat\(2,/);
  assert.match(style, /@media \(max-width:\s*360px\)[\s\S]*?\.mission-actions button\s*\{[^}]*min-height:\s*42px/);
  assert.match(style, /\.mission-actions \.stop-search,[\s\S]*?\.mission-actions \.stop-task\s*\{[^}]*white-space:\s*nowrap/);
});

test("task refresh handlers capture the control epoch and reject in-flight background responses", () => {
  for (const [name, nextMarker] of [["loadTask", "async function loadQueue"], ["loadBoard", "function connectWs"]]) {
    const start = board.indexOf(`async function ${name}`);
    const end = board.indexOf(`\n${nextMarker}`, start);
    assert.ok(start >= 0 && end > start, `${name} handler should be present`);
    const handler = board.slice(start, end);
    const applyPos = handler.indexOf(name === "loadTask" ? "task.value = t" : "liveWorkers.value =");
    const guardPos = handler.indexOf("isCurrentTaskRefresh(");
    assert.match(handler, /const requestVersion = taskControlRequestVersion/);
    assert.match(handler, /const startedWhileControlWorking = stopSearchWorking\.value \|\| taskControlWorking\.value/);
    assert.match(handler, /expectedRequestVersion/);
    assert.ok(guardPos >= 0 && applyPos > guardPos, `${name} must guard before applying its response`);
  }
});

test("task board renders the collector state machine and FOFA rotation events", () => {
  assert.match(board, /collectorViewModel/);
  assert.match(board, /mergeCollectorEvent/);
  assert.match(board, /fofa_key_rotated/);
  assert.match(board, /fofa_pool_waiting/);
  assert.match(board, /fofa_pool_blocked/);
  assert.match(board, /搜集进度/);
  assert.match(board, /处置进度/);
  assert.match(board, /最近使用/);
  assert.match(board, /collectorModel\.keySourceLabel/);
  assert.match(board, /router\.push\(['"]\/settings['"]\)/);
  assert.match(board, /aria-live="polite"/);
  const fmtStart = board.indexOf("function fmtEvent(ev)");
  const fmtEnd = board.indexOf("\nfunction phaseStateText", fmtStart);
  assert.ok(fmtStart >= 0 && fmtEnd > fmtStart);
  const formatter = board.slice(fmtStart, fmtEnd);
  const fallback = formatter.indexOf("if (ev.message) return ev.message");
  const structuredFormatter = formatter.indexOf("formatFofaCollectorEvent");
  assert.ok(structuredFormatter >= 0 && structuredFormatter < fallback, "structured FOFA formatter must run before message fallback");
});

test("collector status styles cover static failure states and reduced motion", () => {
  assert.match(style, /\.mission-progress\.indeterminate/);
  assert.match(style, /\.collector-stage\.tone-active/);
  assert.match(style, /\.collector-stage\.tone-waiting/);
  assert.match(style, /\.collector-stage\.tone-blocked/);
  assert.match(style, /\.collector-stage\.tone-neutral/);
  assert.match(style, /@media \(prefers-reduced-motion:\s*reduce\)/);
  assert.match(style, /\.collector-stage-meta\s*>\s*span\s*\{\s*white-space:\s*normal/);
  assert.match(board, /Legacy Key/);
  assert.match(board, /不参与池管理/);
});
