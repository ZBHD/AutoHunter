import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const view = source("../src/views/ReviewsView.vue");
const main = source("../src/main.js");

test("global review route lists pending findings across tasks", () => {
  assert.match(main, /import ReviewsView/);
  assert.match(main, /path:\s*["']\/reviews["'][^}]*component:\s*ReviewsView/);
  assert.match(view, /api\.globalReviewQueue/);
  assert.match(view, /task_name/);
  assert.match(view, /download_status/);
  assert.match(view, /normalizePage/);
});

test("global review page supports selection, independent downloads, and approvals", () => {
  assert.match(view, /selectedIds/);
  assert.match(view, /全选当前页/);
  assert.match(view, /downloadMarkdownReports/);
  assert.match(view, /buildDownloadReportMd/);
  assert.match(view, /markFindingsDownloaded/);
  assert.match(view, /批量通过/);
  assert.match(view, /批量不通过/);
  assert.match(view, /api\.userReview/);
  assert.match(view, /<ReportDrawer/);
  assert.match(view, /mode="review"/);
});

test("global review page keeps approval actions full-role only", () => {
  assert.match(view, /const writable = computed\(\(\) => authRoleRef\.value === "full"\)/);
  assert.match(view, /v-if="writable"[^>]*class="review-bulk-actions"/);
});
