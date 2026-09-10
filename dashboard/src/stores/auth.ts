import { defineStore } from "pinia";
import { computed, ref } from "vue";
import {
  login as apiLogin,
  logout as apiLogout,
  me,
  fetchSetupStatus,
  setupAdmin,
  type LoginResult,
  type PublicUser,
  type UserRole,
} from "@/lib/api";

export const useAuthStore = defineStore("auth", () => {
  const user = ref<PublicUser | null>(null);
  const loaded = ref(false);
  const needsSetup = ref<boolean | null>(null);

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
    } catch {
      user.value = null;
    } finally {
      loaded.value = true;
    }
  }

  async function login(email: string, password: string, returnTo?: string): Promise<LoginResult> {
    const res = await apiLogin(email, password, returnTo);
    if (res.status === "ok") {
      user.value = res.user;
      loaded.value = true;
    }
    return res;
  }

  function completeLogin(u: PublicUser) {
    user.value = u;
    loaded.value = true;
  }

  async function logout() {
    try {
      await apiLogout();
    } finally {
      user.value = null;
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
    login,
    completeLogin,
    logout,
    setUser,
    loadSetupStatus,
    completeSetup,
  };
});
