import { createRouter, createWebHistory } from "vue-router";
import AppShell from "@/layouts/AppShell.vue";
import ActivityView from "@/views/ActivityView.vue";
import AuditLogsView from "@/views/AuditLogsView.vue";
import ClientsView from "@/views/ClientsView.vue";
import ConsentView from "@/views/ConsentView.vue";
import DirectoryView from "@/views/DirectoryView.vue";
import IntegrationsView from "@/views/IntegrationsView.vue";
import LoginView from "@/views/LoginView.vue";
import OverviewView from "@/views/OverviewView.vue";
import ResetPasswordView from "@/views/ResetPasswordView.vue";
import SettingsView from "@/views/SettingsView.vue";
import SetupView from "@/views/SetupView.vue";
import UsersView from "@/views/UsersView.vue";
import { useAuthStore } from "@/stores/auth";

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    {
      path: "/login",
      name: "login",
      component: LoginView,
      meta: { public: true },
    },
    {
      path: "/setup",
      name: "setup",
      component: SetupView,
      meta: { public: true, title: "Setup" },
    },
    {
      path: "/reset-password",
      name: "reset-password",
      component: ResetPasswordView,
      meta: { public: true },
    },
    {
      path: "/consent",
      name: "consent",
      component: ConsentView,
      meta: { public: true },
    },
    {
      path: "/",
      component: AppShell,
      children: [
        {
          path: "",
          // Static redirect: staff land on the overview, non-staff are bounced
          // to /activity by the beforeEach guard (which runs after fetchMe
          // loads the authenticated user). A redirect function here would run
          // before auth is loaded and always see isStaff === false.
          redirect: "/overview",
        },
        {
          path: "activity",
          name: "activity",
          component: ActivityView,
          meta: { title: "Activity" },
        },
        {
          path: "overview",
          name: "overview",
          component: OverviewView,
          meta: { title: "Overview", staff: true },
        },
        {
          path: "users",
          name: "users",
          component: UsersView,
          meta: { title: "Users", staff: true },
        },
        {
          path: "clients",
          name: "clients",
          component: ClientsView,
          meta: { title: "Clients", staff: true },
        },
        {
          path: "audit-logs",
          name: "audit-logs",
          component: AuditLogsView,
          meta: { title: "Audit logs", staff: true },
        },
        {
          path: "settings",
          name: "settings",
          component: SettingsView,
          meta: { title: "Settings", admin: true },
        },
        {
          path: "integrations",
          name: "integrations",
          component: IntegrationsView,
          meta: { title: "Integrations", admin: true },
        },
        {
          path: "directory",
          name: "directory",
          component: DirectoryView,
          meta: { title: "Directory sync", admin: true },
        },
      ],
    },
  ],
});

router.beforeEach(async (to) => {
  const auth = useAuthStore();
  if (!auth.loaded) {
    await auth.fetchMe();
  }

  if (auth.isAuthenticated) {
    if (to.path === "/login" || to.path === "/setup") {
      return { path: auth.isStaff ? "/overview" : "/activity" };
    }
    if (to.meta.public) return true;
    if (to.meta.admin && !auth.isAdmin) {
      return { path: auth.isStaff ? "/overview" : "/activity" };
    }
    if (to.meta.staff && !auth.isStaff) {
      return { path: "/activity" };
    }
    return true;
  }

  // Not authenticated: first-run setup takes precedence over login.
  const needsSetup = await auth.loadSetupStatus();
  if (needsSetup) {
    return to.path === "/setup" ? true : { path: "/setup" };
  }

  if (to.meta.public) {
    return to.path === "/setup" ? { path: "/login" } : true;
  }

  return { path: "/login", query: { return_to: to.fullPath } };
});

router.afterEach((to) => {
  const pageTitle = typeof to.meta.title === "string" ? to.meta.title : "";
  document.title = pageTitle ? `${pageTitle} · Signet` : "Signet · Identity";
});
