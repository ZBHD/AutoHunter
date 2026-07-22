# 任务列表状态筛选 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在任务列表中提供“全部 / 运行中 / 已暂停 / 已停止”筛选，并将 `paused`、`idle`、`created` 统一归入“已暂停”。

**Architecture:** 新建纯函数模块集中定义筛选项、匹配规则和计数，`TasksView.vue` 只维护选中项并消费计算结果。所有筛选都在已加载的任务数组上执行，后端接口和任务原始状态标签保持不变。

**Tech Stack:** Vue 3 Composition API、原生 CSS、Node.js `node:test`

---

### Task 1: 状态筛选领域逻辑

**Files:**
- Create: `frontend/src/taskStatusFilters.js`
- Create: `frontend/tests/taskStatusFilters.test.js`

- [ ] **Step 1: Write the failing test**

创建测试，验证筛选顺序、`idle/created` 合并到暂停组、未知状态只出现在全部组，以及各组计数：

```js
import test from "node:test";
import assert from "node:assert/strict";

import {
  TASK_STATUS_FILTERS,
  filterTasksByStatus,
  taskStatusFilterCounts,
} from "../src/taskStatusFilters.js";

const tasks = [
  { id: "running", status: "running" },
  { id: "paused", status: "paused" },
  { id: "idle", status: "idle" },
  { id: "created", status: "created" },
  { id: "stopped", status: "stopped" },
  { id: "unknown", status: "unknown" },
];

test("task status filters keep the required display order", () => {
  assert.deepEqual(TASK_STATUS_FILTERS.map(({ key, label }) => [key, label]), [
    ["all", "全部"],
    ["running", "运行中"],
    ["paused", "已暂停"],
    ["stopped", "已停止"],
  ]);
});

test("paused filter includes paused idle and created tasks", () => {
  assert.deepEqual(
    filterTasksByStatus(tasks, "paused").map(({ id }) => id),
    ["paused", "idle", "created"],
  );
  assert.deepEqual(filterTasksByStatus(tasks, "running").map(({ id }) => id), ["running"]);
  assert.deepEqual(filterTasksByStatus(tasks, "stopped").map(({ id }) => id), ["stopped"]);
  assert.deepEqual(filterTasksByStatus(tasks, "all").map(({ id }) => id), tasks.map(({ id }) => id));
});

test("task status counts use the same grouping rules as filtering", () => {
  assert.deepEqual(taskStatusFilterCounts(tasks), {
    all: 6,
    running: 1,
    paused: 3,
    stopped: 1,
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && npm test -- --test-name-pattern="task status"`

Expected: FAIL，提示找不到 `src/taskStatusFilters.js`。

- [ ] **Step 3: Write minimal implementation**

```js
export const TASK_STATUS_FILTERS = Object.freeze([
  { key: "all", label: "全部" },
  { key: "running", label: "运行中" },
  { key: "paused", label: "已暂停" },
  { key: "stopped", label: "已停止" },
]);

const FILTER_STATUSES = Object.freeze({
  running: new Set(["running"]),
  paused: new Set(["paused", "idle", "created"]),
  stopped: new Set(["stopped"]),
});

export function filterTasksByStatus(tasks = [], filter = "all") {
  if (filter === "all") return tasks;
  const statuses = FILTER_STATUSES[filter];
  return statuses ? tasks.filter((task) => statuses.has(task?.status)) : tasks;
}

export function taskStatusFilterCounts(tasks = []) {
  return Object.fromEntries(
    TASK_STATUS_FILTERS.map(({ key }) => [key, filterTasksByStatus(tasks, key).length]),
  );
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && npm test -- --test-name-pattern="task status"`

Expected: PASS，三个状态筛选测试通过。

- [ ] **Step 5: Commit**

```bash
git add frontend/src/taskStatusFilters.js frontend/tests/taskStatusFilters.test.js
git commit -m "功能：增加任务状态筛选逻辑"
```

### Task 2: 任务列表筛选交互

**Files:**
- Modify: `frontend/src/views/TasksView.vue`
- Modify: `frontend/tests/taskStatusFilters.test.js`

- [ ] **Step 1: Write the failing page contract test**

在同一个测试文件中读取 `TasksView.vue`，验证页面使用领域模块、默认全部、使用筛选后的数据源、按钮选中态与区分两种空态：

```js
import { readFileSync } from "node:fs";

const taskView = readFileSync(new URL("../src/views/TasksView.vue", import.meta.url), "utf8");

test("task list renders status filters and filtered results", () => {
  assert.match(taskView, /TASK_STATUS_FILTERS/);
  assert.match(taskView, /const statusFilter = ref\("all"\)/);
  assert.match(taskView, /const filteredTasks = computed/);
  assert.match(taskView, /v-for="filter in TASK_STATUS_FILTERS"/);
  assert.match(taskView, /:aria-pressed="statusFilter === filter\.key"/);
  assert.match(taskView, /v-for="t in filteredTasks"/);
  assert.match(taskView, /当前筛选下没有任务/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test tests/taskStatusFilters.test.js`

Expected: FAIL，页面尚未包含筛选状态和控件。

- [ ] **Step 3: Integrate the filter into TasksView**

在 `<script setup>` 中导入筛选模块并声明：

```js
import {
  TASK_STATUS_FILTERS,
  filterTasksByStatus,
  taskStatusFilterCounts,
} from "../taskStatusFilters.js";

const statusFilter = ref("all");
const filteredTasks = computed(() => filterTasksByStatus(tasks.value, statusFilter.value));
const statusCounts = computed(() => taskStatusFilterCounts(tasks.value));
```

在页面标题与列表之间渲染按钮，并为当前项设置可访问状态：

```vue
<div v-if="!initialLoading && tasks.length" class="task-status-filters" aria-label="按任务状态筛选">
  <button v-for="filter in TASK_STATUS_FILTERS" :key="filter.key" type="button"
    :class="{ active: statusFilter === filter.key }"
    :aria-pressed="statusFilter === filter.key"
    @click="statusFilter = filter.key">
    <span>{{ filter.label }}</span>
    <b>{{ statusCounts[filter.key] }}</b>
  </button>
</div>
```

保留原有无任务空态；有任务但筛选结果为空时显示“当前筛选下没有任务”，列表循环改用 `filteredTasks`。

- [ ] **Step 4: Run test to verify it passes**

Run: `cd frontend && node --test tests/taskStatusFilters.test.js`

Expected: PASS，领域逻辑和页面契约测试全部通过。

- [ ] **Step 5: Commit**

```bash
git add frontend/src/views/TasksView.vue frontend/tests/taskStatusFilters.test.js
git commit -m "功能：在任务列表接入状态筛选"
```

### Task 3: 响应式样式与完整验证

**Files:**
- Modify: `frontend/src/style.css`
- Modify: `frontend/tests/taskStatusFilters.test.js`

- [ ] **Step 1: Write the failing style contract test**

加入样式契约，要求筛选栏稳定为四列、活动态清晰，并在窄屏保持可点击尺寸：

```js
const style = readFileSync(new URL("../src/style.css", import.meta.url), "utf8");

test("task status filters have stable responsive controls", () => {
  assert.match(style, /\.task-status-filters\s*\{[\s\S]*grid-template-columns:\s*repeat\(4,/);
  assert.match(style, /\.task-status-filters button\.active/);
  assert.match(style, /@media \(max-width:\s*640px\)[\s\S]*\.task-status-filters button[\s\S]*min-height:\s*44px/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd frontend && node --test tests/taskStatusFilters.test.js`

Expected: FAIL，缺少 `.task-status-filters` 样式。

- [ ] **Step 3: Add focused task filter styles**

在任务列表样式区加入四列分段控件。按钮使用 `var(--surface)`、`var(--border)`、`var(--accent-bg)` 和 `var(--accent)` 等现有变量；标签与数字左右排列，活动项通过背景、边框及底部强调线表达，不使用装饰性渐变。在 `max-width: 640px` 下压缩间距并保持按钮 `min-height: 44px`，确保四列不溢出。

- [ ] **Step 4: Run focused and full verification**

Run: `cd frontend && node --test tests/taskStatusFilters.test.js`

Expected: PASS。

Run: `cd frontend && npm test`

Expected: 全部前端测试通过。

Run: `cd frontend && npm run build`

Expected: Vite 构建成功，退出码为 0。

Run: `git diff --check`

Expected: 无输出，退出码为 0。

- [ ] **Step 5: Commit**

```bash
git add frontend/src/style.css frontend/tests/taskStatusFilters.test.js
git commit -m "样式：完善任务筛选响应式布局"
```
