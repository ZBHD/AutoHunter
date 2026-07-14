import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  canAccessRoute,
  primaryNavigation,
} from "../src/navigation.js";

const source = (path) => readFileSync(new URL(path, import.meta.url), "utf8");

test("full and readonly roles receive the four primary navigation items", () => {
  for (const role of ["full", "readonly"]) {
    assert.deepEqual(
      primaryNavigation(role).map(({ label, to }) => [label, to]),
      [
        ["任务", "/"],
        ["疑似", "/missed-signals"],
        ["通杀", "/killsweeps"],
        ["设置", "/settings"],
      ],
    );
  }
});

test("observer navigation is limited to tasks and settings", () => {
  assert.deepEqual(
    primaryNavigation("observer").map(({ label }) => label),
    ["任务", "设置"],
  );
  assert.equal(canAccessRoute("observer", "/settings"), true);
  assert.equal(canAccessRoute("observer", "/missed-signals"), false);
  assert.equal(canAccessRoute("observer", "/killsweeps"), false);
});

test("only full access can open task creation while readonly can open operations", () => {
  assert.equal(canAccessRoute("full", "/create"), true);
  assert.equal(canAccessRoute("readonly", "/create"), false);
  assert.equal(canAccessRoute("readonly", "/missed-signals"), true);
  assert.equal(canAccessRoute("readonly", "/killsweeps"), true);
});

test("navigation accepts pending and failed badge counts", () => {
  const items = primaryNavigation("full", { missedPending: 7, killsweepFailed: 3 });
  assert.equal(items.find((item) => item.id === "missed")?.badge, 7);
  assert.equal(items.find((item) => item.id === "killsweeps")?.badge, 3);
});

test("application shell renders one shared four-item nav model on desktop and mobile", () => {
  const app = source("../src/App.vue");

  assert.match(app, /primaryNavigation/);
  assert.match(app, /v-for="item in visibleNavigation"/);
  assert.match(app, /class="topbar-nav desktop-only-nav"/);
  assert.match(app, /class="bottom-nav mobile-only-nav"/);
  assert.doesNotMatch(app, /class="token-switch"/);
  assert.doesNotMatch(app, /class="theme-toggle"/);
  assert.doesNotMatch(app, /class="github-link"/);
});

test("changing to a restricted role leaves a sensitive operations route", () => {
  const app = source("../src/App.vue");

  assert.match(app, /canAccessRoute\(result\.role,\s*route\.path\)/);
  assert.match(app, /await router\.replace\("\/"\)/);
});

test("task list owns the full-only new-task command", () => {
  const tasks = source("../src/views/TasksView.vue");

  assert.match(tasks, /v-if="writable"[^>]*class="[^"]*new-task-action[^"]*"[^>]*to="\/create"/);
  assert.match(tasks, />\s*新建任务\s*</);
  assert.doesNotMatch(tasks, /点顶栏「新建」/);
});

test("settings always renders personal controls and gates system configuration", () => {
  const settings = source("../src/views/SettingsView.vue");

  assert.match(settings, /class="settings-personal"/);
  assert.match(settings, /@click="changeToken"/);
  assert.match(settings, /@click="setTheme\('light'\)"/);
  assert.match(settings, /@click="setTheme\('dark'\)"/);
  assert.match(settings, /github\.com\/ZBHD\/AutoHunter/);
  assert.match(settings, /v-if="systemAccess"/);
  assert.match(settings, /shouldLoadSystemSettings/);
});

test("settings initial auth resolution cannot duplicate the full settings request", () => {
  const settings = source("../src/views/SettingsView.vue");
  const mounted = settings.match(/onMounted\(async \(\) => \{([\s\S]*?)\n\}\);/)?.[1] || "";

  assert.match(mounted, /if \(!authReadyRef\.value\) \{\s*await loadAuthRole\(\);\s*return;\s*\}/);
  assert.match(mounted, /if \(systemAccess\.value && !systemLoaded\.value\) await load\(\)/);
});

test("router guard delegates role checks and keeps settings available to observers", () => {
  const main = source("../src/main.js");

  assert.match(main, /canAccessRoute\(authRoleRef\.value,\s*to\.path\)/);
  assert.doesNotMatch(main, /\["\/create",\s*"\/settings"/);
});

test("frontend API exposes paginated task, missed-signal, and killsweep operations", () => {
  const api = source("../src/api.js");

  assert.match(api, /terminalTargets:/);
  assert.match(api, /rawFindings:/);
  assert.match(api, /missedSignalStats:/);
  assert.match(api, /missedSignals:/);
  assert.match(api, /missedSignalDraft:/);
  assert.match(api, /killsweepStats:/);
  assert.match(api, /killsweepCases:/);
  assert.match(api, /reanalyzeKillsweeps:/);
});
