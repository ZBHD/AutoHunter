import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

const assertSiteReconControl = (view) => {
  assert.match(view, /<div v-if="isSiteMode" class="[^"]*\bsite-recon-mode\b[^"]*">/);
  assert.match(
    view,
    /<button type="button"[^>]*:aria-pressed="form\.site_recon_mode === 'full'"[^>]*@click="form\.site_recon_mode = 'full'"[^>]*>\s*完整入口盘点\s*<\/button>/,
  );
  assert.match(
    view,
    /<button type="button"[^>]*:aria-pressed="form\.site_recon_mode === 'light'"[^>]*@click="form\.site_recon_mode = 'light'"[^>]*>\s*轻量入口盘点（最多 18 轮）\s*<\/button>/,
  );
  assert.match(view, /<select v-model="form\.target_source" @change="handleTargetSourceChange">/);
  assert.match(
    view,
    /function handleTargetSourceChange\(\)\s*\{\s*if \(isSiteMode\.value\) form\.site_recon_mode = "full";\s*\}/,
  );
  assert.match(
    view,
    /if \(isSiteMode\.value\) fofaConfig\.site_recon_mode = form\.site_recon_mode;/,
  );
};

test("create view explicitly submits full or light site recon mode", () => {
  const view = source("../src/views/CreateView.vue");
  assert.match(view, /site_recon_mode:\s*[\"']full[\"']/);
  assert.match(view, /完整入口盘点/);
  assert.match(view, /轻量入口盘点（最多 18 轮）/);
  assertSiteReconControl(view);
  assert.doesNotMatch(view, /looksHasCreds|skip_recon_touched/);
});

test("task editor fills and always saves selected site recon mode", () => {
  const view = source("../src/components/TaskEditModal.vue");
  assert.match(view, /site_recon_mode:\s*[\"']full[\"']/);
  assert.match(view, /form\.site_recon_mode\s*=\s*fofaCfg\.site_recon_mode\s*\|\|\s*[\"']full[\"']/);
  assertSiteReconControl(view);
  assert.match(view, /aria-label=[\"']入口盘点模式[\"']/);
});

test("site recon control has stable segmented layout", () => {
  const style = source("../src/style.css");
  const mobileModelStyles = style.match(
    /@media \(max-width: 640px\) \{\s*\.provider-panel-head[\s\S]*?\n\}\r?\n\r?\n\/\* ---------- 任务指挥台 ---------- \*\//,
  );
  assert.match(
    style,
    /\.site-recon-mode\s*\{[^}]*display:\s*grid;[^}]*min-width:\s*0;[^}]*\}/,
  );
  assert.match(
    style,
    /\.site-recon-mode\s+\.model-mode-switch\s*\{[^}]*margin-top:\s*0;[^}]*\}/,
  );
  assert.match(
    style,
    /\.site-recon-mode\s+\.model-mode-switch button\s*\{[^}]*min-height:\s*44px;[^}]*\}/,
  );
  assert.ok(mobileModelStyles, "expected the model controls' mobile media block");
  assert.match(
    mobileModelStyles[0],
    /\.model-mode-switch,\s*\.task-model-grid\s*\{[^}]*grid-template-columns:\s*1fr;[^}]*\}/,
  );
});

test("board renders site recon mode in worker cards and start events", () => {
  const board = source("../src/views/BoardView.vue");
  assert.match(board, /function siteReconModeLabel\(/);
  assert.match(board, /site_route/);
  assert.match(board, /site_recon_mode/);
  assert.match(board, /轻量入口盘点/);
  assert.match(board, /完整入口盘点/);
  assert.match(board, /case "worker_start"[\s\S]*siteReconModeLabel/);
  assert.match(board, /class="wc-recon-mode"/);
});
