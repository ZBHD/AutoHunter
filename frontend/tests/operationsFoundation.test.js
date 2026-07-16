import test from "node:test";
import assert from "node:assert/strict";

import { buildListQuery, normalizePage } from "../src/listQuery.js";
import {
  downloadMarkdownReports,
  markdownReportFilename,
  reportsForDownload,
} from "../src/downloads.js";
import {
  MISSED_SIGNAL_STATUS,
  missedSignalPresentation,
} from "../src/missedSignals.js";
import {
  KILLSWEEP_STATUS,
  killsweepPresentation,
  reanalysisBatchLimit,
} from "../src/killsweeps.js";
import { normalizeTaskView, taskViewQuery } from "../src/taskViews.js";
import {
  currentTheme,
  nextTheme,
  setThemePreference,
  shouldLoadSystemSettings,
} from "../src/preferences.js";
import { buildDownloadReportMd, buildReportCoreMd, effectiveSeverity } from "../src/report.js";

test("list query omits empty values and preserves zero", () => {
  assert.equal(
    buildListQuery({ status: "pending", q: "登录 / token", limit: 50, offset: 0, empty: "", nil: null }),
    "?status=pending&q=%E7%99%BB%E5%BD%95+%2F+token&limit=50&offset=0",
  );
});

test("page normalization accepts envelopes and legacy arrays", () => {
  assert.deepEqual(normalizePage({ items: [{ id: 1 }], total: 3, limit: 1, offset: 1 }), {
    items: [{ id: 1 }],
    total: 3,
    limit: 1,
    offset: 1,
    hasMore: true,
  });
  assert.deepEqual(normalizePage([{ id: 2 }], { limit: 50, offset: 0 }), {
    items: [{ id: 2 }],
    total: 1,
    limit: 50,
    offset: 0,
    hasMore: false,
  });
});

test("task view helpers only preserve supported task panels", () => {
  assert.equal(normalizeTaskView("scanned"), "scanned");
  assert.equal(normalizeTaskView("findings"), "findings");
  assert.equal(normalizeTaskView("unknown"), "board");
  assert.deepEqual(taskViewQuery("findings"), { view: "findings" });
  assert.deepEqual(taskViewQuery("board"), {});
});

test("report filenames are independent, deterministic Markdown names", () => {
  assert.equal(
    markdownReportFilename({ id: 42, title: "后台 / 越权：读取用户" }, 0),
    "42-后台-越权-读取用户.md",
  );
  assert.equal(markdownReportFilename({ title: "" }, 2), "report-3.md");
});

test("raw report severity falls back to the finding claim before review", () => {
  const finding = {
    title: "Unreviewed finding",
    vuln_type: "info",
    target_url: "https://example.test/info",
    severity_claimed: "medium",
    description: "Unreviewed evidence",
  };

  assert.equal(effectiveSeverity(finding), "medium");
  assert.match(buildReportCoreMd(finding), /\| \*\*漏洞等级\*\* \| medium（- \/ 10） \|/);
});

test("download Markdown omits AI review and EduSRC import sections", () => {
  const finding = {
    id: "download-1",
    title: "Download finding",
    vuln_type: "xss",
    target_url: "https://example.test/xss",
    severity_claimed: "高危",
    description: "Evidence description",
    review: { reviewer_notes: "internal review" },
  };
  const md = buildDownloadReportMd(finding);
  assert.match(md, /## 漏洞描述/);
  assert.match(md, /## 证据链/);
  assert.doesNotMatch(md, /## AI 审核结论/);
  assert.doesNotMatch(md, /## EDUSRC 自动填充 JSON/);
});

test("download scope explicitly chooses all reports or current filtered reports", () => {
  const all = [{ id: 1 }, { id: 2 }, { id: 3 }];
  const filtered = [{ id: 2 }];

  assert.deepEqual(reportsForDownload("all", { all, filtered }), all);
  assert.deepEqual(reportsForDownload("filtered", { all, filtered }), filtered);
  assert.throws(() => reportsForDownload("page", { all, filtered }), /download scope/i);
});

test("Markdown downloads run sequentially and keep one file per report", async () => {
  const calls = [];
  const findings = [{ id: 1, title: "First" }, { id: 2, title: "Second" }];

  const result = await downloadMarkdownReports(findings, {
    render: async (finding) => `# ${finding.title}`,
    save: async (file) => calls.push(file),
    pause: async () => calls.push("pause"),
  });

  assert.deepEqual(calls, [
    { filename: "1-First.md", content: "# First", finding: findings[0] },
    "pause",
    { filename: "2-Second.md", content: "# Second", finding: findings[1] },
  ]);
  assert.equal(result.downloaded, 2);
});

test("missed-signal statuses expose stable Chinese presentation", () => {
  assert.equal(MISSED_SIGNAL_STATUS.pending.label, "待复核");
  assert.deepEqual(missedSignalPresentation("deepening"), {
    key: "deepening",
    label: "深挖中",
    tone: "running",
  });
  assert.equal(missedSignalPresentation("new-state").label, "new-state");
});

test("killsweep lifecycle includes pending validation and caps a batch at 40", () => {
  assert.equal(KILLSWEEP_STATUS.pending_validation.label, "待验证");
  assert.equal(killsweepPresentation("failed").tone, "danger");
  assert.equal(reanalysisBatchLimit(100), 40);
  assert.equal(reanalysisBatchLimit(12), 12);
  assert.equal(reanalysisBatchLimit(-1), 1);
});

test("personal preferences normalize theme and isolate full-only system settings", () => {
  const storage = new Map();
  const root = { setAttribute: (name, value) => storage.set(name, value) };
  const localStorage = {
    getItem: (key) => storage.get(key) || null,
    setItem: (key, value) => storage.set(key, value),
  };

  assert.equal(currentTheme(localStorage), "dark");
  assert.equal(nextTheme("dark"), "light");
  assert.equal(setThemePreference("light", { root, storage: localStorage, notify: false }), "light");
  assert.equal(storage.get("data-theme"), "light");
  assert.equal(currentTheme(localStorage), "light");
  assert.equal(shouldLoadSystemSettings("full"), true);
  assert.equal(shouldLoadSystemSettings("readonly"), false);
  assert.equal(shouldLoadSystemSettings("observer"), false);
});
