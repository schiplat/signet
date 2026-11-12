import { defineStore } from "pinia";
import { computed, ref } from "vue";
import {
  login as apiLogin,
  logout as apiLogout,
  me,
  fetchSetupStatus,
  setupAdmin,
  fetchPendingSso,
  confirmPendingSso as apiConfirmPendingSso,
  discardPendingSso as apiDiscardPendingSso,
  type LoginResult,
  type PendingSsoIdentity,
  type PublicUser,
  type UserRole,
} from "@/lib/api";

export const useAuthStore = defineStore("auth", () => {
  const user = ref<PublicUser | null>(null);
  const loaded = ref(false);
  const needsSetup = ref<boolean | null>(null);
  /** A stashed SSO identity awaiting the user's explicit confirm/discard. */
  const pendingSso = ref<PendingSsoIdentity | null>(null);

  const isAuthenticated = computed(() => !!user.value);
  const role = computed<UserRole>(() => user.value?.role ?? "member");
  const isAdmin = computed(() => role.value === "admin");
  const isManager = computed(() => role.value === "manager");
  const isStaff = computed(() => role.value === "admin" || role.value === "manager");
  const canManageUsers = computed(() => isStaff.value);
  const canDeleteUsers = computed(() => isAdmin.value);
  const canManageClients = computed(() => isStaff.value);
  const canDeleteClients = computed(() => isAdmin.value);
  const canViewAudit = computed(() => isStaff.value);
  const canManageSettings = computed(() => isAdmin.value);
  const displayName = computed(
    () => user.value?.display_name || user.value?.email || "?",
  );

  async function fetchMe() {
    try {
      const res = await me();
      user.value = res.user;
      void refreshPendingSso();
    } catch {
      user.value = null;
      pendingSso.value = null;
    } finally {
      loaded.value = true;
    }
  }

  /** A pending SSO bind must be a decision, not an automatic side effect:
   *  the stash survives sign-in, and the shell banner asks the user. */
  async function refreshPendingSso() {
    if (!user.value) {
      pendingSso.value = null;
      return;
    }
    try {
      pendingSso.value = (await fetchPendingSso()).pending;
    } catch {
      pendingSso.value = null;
    }
  }

  async function confirmPendingSso() {
    await apiConfirmPendingSso();
    pendingSso.value = null;
  }

  async function discardPendingSso() {
    try {
      await apiDiscardPendingSso();
    } finally {
      pendingSso.value = null;
    }
  }

  async function login(
    email: string,
    password: string,
    returnTo?: string,
    captchaToken?: string,
  ): Promise<LoginResult> {
    const res = await apiLogin(email, password, returnTo, captchaToken);
    if (res.status === "ok") {
      user.value = res.user;
      loaded.value = true;
      void refreshPendingSso();
    }
    return res;
  }

  function completeLogin(u: PublicUser) {
    user.value = u;
    loaded.value = true;
    void refreshPendingSso();
  }

  async function logout() {
    try {
      await apiLogout();
    } finally {
      user.value = null;
      pendingSso.value = null;
    }
  }

  function setUser(u: PublicUser) {
    user.value = u;
  }

  async function loadSetupStatus(): Promise<boolean> {
    if (needsSetup.value === null) {
      try {
        needsSetup.value = (await fetchSetupStatus()).needs_setup;
      } catch {
        needsSetup.value = false;
      }
    }
    return needsSetup.value;
  }

  async function completeSetup(email: string, password: string, displayName?: string) {
    const res = await setupAdmin({
      email,
      password,
      display_name: displayName,
    });
    if (res.status === "ok") {
      user.value = res.user;
      loaded.value = true;
      needsSetup.value = false;
    }
    return res;
  }

  return {
    user,
    loaded,
    needsSetup,
    pendingSso,
    isAuthenticated,
    role,
    isAdmin,
    isManager,
    isStaff,
    canManageUsers,
    canDeleteUsers,
    canManageClients,
    canDeleteClients,
    canViewAudit,
    canManageSettings,
    displayName,
    fetchMe,
    refreshPendingSso,
    confirmPendingSso,
    discardPendingSso,
    login,
    completeLogin,
    logout,
    setUser,
    loadSetupStatus,
    completeSetup,
  };
});
