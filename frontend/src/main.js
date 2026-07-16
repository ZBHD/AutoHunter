import { createApp } from "vue";
import { createRouter, createWebHashHistory } from "vue-router";
import App from "./App.vue";
import TasksView from "./views/TasksView.vue";
import CreateView from "./views/CreateView.vue";
import BoardView from "./views/BoardView.vue";
import SettingsView from "./views/SettingsView.vue";
import HardTargetsView from "./views/HardTargetsView.vue";
import IntelView from "./views/IntelView.vue";
import VulnsView from "./views/VulnsView.vue";
import RuntimeLogsView from "./views/RuntimeLogsView.vue";
import MissedSignalsView from "./views/MissedSignalsView.vue";
import KillsweepsView from "./views/KillsweepsView.vue";
import ReviewsView from "./views/ReviewsView.vue";
import { authReadyRef, authRoleRef, loadAuthRole } from "./api.js";
import { canAccessRoute } from "./navigation.js";
import "./style.css";

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/", component: TasksView },
    { path: "/create", component: CreateView },
    { path: "/hard-targets", component: HardTargetsView },
    { path: "/intel", name: "intel", component: IntelView },
    { path: "/vulns", component: VulnsView },
    { path: "/runtime-logs", component: RuntimeLogsView },
    { path: "/settings", component: SettingsView },
    { path: "/reviews", component: ReviewsView },
    { path: "/missed-signals", component: MissedSignalsView },
    { path: "/killsweeps", component: KillsweepsView },
    { path: "/task/:id", component: BoardView, props: true },
  ],
});

router.beforeEach(async (to) => {
  if (!authReadyRef.value) await loadAuthRole();
  if (!canAccessRoute(authRoleRef.value, to.path)) return "/";
  return true;
});

createApp(App).use(router).mount("#app");
