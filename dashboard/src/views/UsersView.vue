<script setup lang="ts">
import { Plus, Trash2, UserRound } from "@lucide/vue";
import { computed, onMounted, ref, watch } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import SortableTh from "@/components/ui/SortableTh.vue";
import TablePagination from "@/components/ui/TablePagination.vue";
import UiButton from "@/components/ui/UiButton.vue";
import { useClientPagination } from "@/composables/useClientPagination";
import { useClientSort } from "@/composables/useClientSort";
import {
  batchDisableUsers,
  checkEmail,
  checkPhone,
  checkUsername,
  createUser,
  deleteUser,
  disableUser,
  enableUser,
  listUsers,
  resetUserMfa,
  revokeUserSessions,
  updateUser,
  type AdminUser,
  type PublicUser,
  type UserRole,
} from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const users = ref<AdminUser[]>([]);
const loading = ref(true);
const error = ref("");
const showCreate = ref(false);
const editing = ref<PublicUser | null>(null);
const creating = ref(false);
const saving = ref(false);
const searchQuery = ref("");
const selected = ref<Set<string>>(new Set());
const batching = ref(false);

const formEmail = ref("");
const formUsername = ref("");
const formPassword = ref("");
const formDisplayName = ref("");
const formRole = ref<UserRole>("member");
const formGroups = ref("");
const formPhone = ref("");
const formMustChangePassword = ref(false);

const editEmail = ref("");
const editUsername = ref("");
const editDisplayName = ref("");
const editRole = ref<UserRole>("member");
const editPassword = ref("");
const editStatus = ref("active");
const editMfaRequired = ref(false);
const editMustChangePassword = ref(false);
const editGroups = ref("");
const editPhone = ref("");

const roleOptions = computed(() => {
  if (auth.isAdmin) return ["admin", "manager", "member"] as UserRole[];
  return ["manager", "member"] as UserRole[];
});

const filteredUsers = computed(() => {
  const q = searchQuery.value.trim().toLowerCase();
  if (!q) return users.value;
  return users.value.filter((u) => {
    const sso = u.sso_identities
      .flatMap((i) => [i.display_name, i.provider_code, i.provider_type])
      .join(" ");
    const origin = u.provisioned_via ?? "";
    return [u.email, u.username ?? "", u.display_name, u.status, u.role, sso, origin]
      .join(" ")
      .toLowerCase()
      .includes(q);
  });
});

const { sorted, toggleSort, sortIndicator } = useClientSort(filteredUsers, {
  initialKey: "created_at",
  initialDir: "desc",
  getValue: (row, key) => {
    switch (key) {
      case "email":
        return row.email;
      case "display_name":
        return row.display_name;
      case "role":
        return row.role;
      case "status":
        return row.status;
      case "created_at":
        return row.created_at;
      default:
        return "";
    }
  },
});

const { page, pageSize, pageCount, total, pageItems, rangeLabel } =
  useClientPagination(sorted);

const selectableOnPage = computed(() =>
  pageItems.value.filter(
    (u) =>
      u.status === "active" &&
      u.id !== auth.user?.id &&
      (auth.isAdmin || u.role !== "admin"),
  ),
);

const allPageSelected = computed(
  () =>
    selectableOnPage.value.length > 0 &&
    selectableOnPage.value.every((u) => selected.value.has(u.id)),
);

const selectedCount = computed(() => selected.value.size);

watch(searchQuery, () => {
  selected.value = new Set();
});

const emailCheckState = ref<"idle" | "checking" | "exists" | "ok">("idle");
let emailCheckTimer: ReturnType<typeof setTimeout> | undefined;

watch(formEmail, (val) => {
  if (emailCheckTimer) clearTimeout(emailCheckTimer);
  const email = val.trim();
  if (!email || !email.includes("@")) {
    emailCheckState.value = "idle";
    return;
  }
  emailCheckState.value = "checking";
  emailCheckTimer = setTimeout(async () => {
    try {
      const { exists } = await checkEmail(email);
      emailCheckState.value = exists ? "exists" : "ok";
    } catch {
      emailCheckState.value = "idle";
    }
  }, 350);
});

const phoneCheckState = ref<"idle" | "checking" | "exists" | "ok">("idle");
let phoneCheckTimer: ReturnType<typeof setTimeout> | undefined;

watch(formPhone, (val) => {
  if (phoneCheckTimer) clearTimeout(phoneCheckTimer);
  const phone = val.trim();
  if (!phone) {
    phoneCheckState.value = "idle";
    return;
  }
  phoneCheckState.value = "checking";
  phoneCheckTimer = setTimeout(async () => {
    try {
      const { exists } = await checkPhone(phone);
      phoneCheckState.value = exists ? "exists" : "ok";
    } catch {
      phoneCheckState.value = "idle";
    }
  }, 350);
});

const editPhoneCheckState = ref<"idle" | "checking" | "exists" | "ok">("idle");
let editPhoneCheckTimer: ReturnType<typeof setTimeout> | undefined;

watch(editPhone, (val) => {
  if (editPhoneCheckTimer) clearTimeout(editPhoneCheckTimer);
  const phone = val.trim();
  const original = editing.value?.phone ?? "";
  if (!phone || phone === original) {
    editPhoneCheckState.value = "idle";
    return;
  }
  editPhoneCheckState.value = "checking";
  editPhoneCheckTimer = setTimeout(async () => {
    try {
      const { exists } = await checkPhone(phone, editing.value?.id);
      editPhoneCheckState.value = exists ? "exists" : "ok";
    } catch {
      editPhoneCheckState.value = "idle";
    }
  }, 350);
});

const usernameCheckState = ref<"idle" | "checking" | "exists" | "ok">("idle");
let usernameCheckTimer: ReturnType<typeof setTimeout> | undefined;

watch(formUsername, (val) => {
  if (usernameCheckTimer) clearTimeout(usernameCheckTimer);
  const username = val.trim();
  if (!username) {
    usernameCheckState.value = "idle";
    return;
  }
  usernameCheckState.value = "checking";
  usernameCheckTimer = setTimeout(async () => {
    try {
      const { exists } = await checkUsername(username);
      usernameCheckState.value = exists ? "exists" : "ok";
    } catch {
      usernameCheckState.value = "idle";
    }
  }, 350);
});

const editUsernameCheckState = ref<"idle" | "checking" | "exists" | "ok">("idle");
let editUsernameCheckTimer: ReturnType<typeof setTimeout> | undefined;

watch(editUsername, (val) => {
  if (editUsernameCheckTimer) clearTimeout(editUsernameCheckTimer);
  const username = val.trim();
  const original = editing.value?.username ?? "";
  if (!username || username === original) {
    editUsernameCheckState.value = "idle";
    return;
  }
  editUsernameCheckState.value = "checking";
  editUsernameCheckTimer = setTimeout(async () => {
    try {
      const { exists } = await checkUsername(username);
      editUsernameCheckState.value = exists ? "exists" : "ok";
    } catch {
      editUsernameCheckState.value = "idle";
    }
  }, 350);
});

async function refresh() {
  users.value = await listUsers();
  selected.value = new Set(
    [...selected.value].filter((id) =>
      users.value.some((u) => u.id === id && u.status === "active"),
    ),
  );
}

onMounted(async () => {
  try {
    if (!auth.user) await auth.fetchMe();
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load users";
  } finally {
    loading.value = false;
  }
});

function canMutate(u: PublicUser) {
  if (auth.isAdmin) return true;
  return u.role !== "admin";
}

function splitGroups(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function openCreate() {
  formEmail.value = "";
  formUsername.value = "";
  formPassword.value = "";
  formDisplayName.value = "";
  formRole.value = "member";
  formGroups.value = "";
  formPhone.value = "";
  formMustChangePassword.value = false;
  emailCheckState.value = "idle";
  phoneCheckState.value = "idle";
  usernameCheckState.value = "idle";
  showCreate.value = true;
}

function openEdit(u: PublicUser) {
  editing.value = u;
  editEmail.value = u.email;
  editUsername.value = u.username ?? "";
  editDisplayName.value = u.display_name;
  editRole.value = u.role;
  editPassword.value = "";
  editStatus.value = u.status;
  editMfaRequired.value = u.mfa_required;
  editMustChangePassword.value = u.must_change_password;
  editGroups.value = (u.groups || []).join(", ");
  editPhone.value = u.phone ?? "";
  editPhoneCheckState.value = "idle";
  editUsernameCheckState.value = "idle";
}

function toggleOne(id: string, checked: boolean) {
  const next = new Set(selected.value);
  if (checked) next.add(id);
  else next.delete(id);
  selected.value = next;
}

function togglePage(checked: boolean) {
  const next = new Set(selected.value);
  for (const u of selectableOnPage.value) {
    if (checked) next.add(u.id);
    else next.delete(u.id);
  }
  selected.value = next;
}

async function onCreate() {
  error.value = "";
  creating.value = true;
  try {
    await createUser({
      email: formEmail.value,
      password: formPassword.value,
      username: formUsername.value.trim() || undefined,
      display_name: formDisplayName.value || undefined,
      role: formRole.value,
      groups: splitGroups(formGroups.value),
      phone: formPhone.value.trim() || undefined,
      must_change_password: formMustChangePassword.value,
    });
    showCreate.value = false;
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Create failed";
  } finally {
    creating.value = false;
  }
}

async function onSaveEdit() {
  if (!editing.value) return;
  error.value = "";
  saving.value = true;
  try {
    await updateUser(editing.value.id, {
      email: editEmail.value,
      username: editUsername.value.trim(),
      display_name: editDisplayName.value,
      role: editRole.value,
      status: editStatus.value,
      password: editPassword.value || undefined,
      mfa_required: editMfaRequired.value,
      must_change_password: editMustChangePassword.value,
      groups: splitGroups(editGroups.value),
      phone: editPhone.value.trim(),
    });
    editing.value = null;
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Update failed";
  } finally {
    saving.value = false;
  }
}

async function onDisable(u: PublicUser) {
  error.value = "";
  try {
    await disableUser(u.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Disable failed";
  }
}

async function onEnable(u: PublicUser) {
  error.value = "";
  try {
    await enableUser(u.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Enable failed";
  }
}

async function onRevokeSessions(u: PublicUser) {
  if (!confirm(`Sign out all active sessions for "${u.email}"?`)) return;
  error.value = "";
  try {
    const res = await revokeUserSessions(u.id);
    error.value = "";
    void res;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Revoke sessions failed";
  }
}

async function onResetMfa(u: PublicUser) {
  if (
    !confirm(
      `Reset MFA for "${u.email}"? Their authenticator and recovery codes will be cleared.`,
    )
  ) {
    return;
  }
  error.value = "";
  try {
    await resetUserMfa(u.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Reset MFA failed";
  }
}

async function onDelete(u: PublicUser) {
  if (!confirm(`Delete user "${u.email}"? This cannot be undone.`)) return;
  error.value = "";
  try {
    await deleteUser(u.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Delete failed";
  }
}

async function onBatchDisable() {
  if (selectedCount.value === 0) return;
  if (!confirm(`Freeze ${selectedCount.value} selected user(s)?`)) return;
  error.value = "";
  batching.value = true;
  try {
    await batchDisableUsers([...selected.value]);
    selected.value = new Set();
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Batch disable failed";
  } finally {
    batching.value = false;
  }
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Users"
      description="Manage Signet accounts. Freeze/edit for staff; delete is admin-only."
    >
      <template #actions>
        <UiButton
          v-if="selectedCount > 0"
          size="sm"
          variant="destructive"
          :disabled="batching"
          @click="onBatchDisable"
        >
          {{ batching ? "Freezing…" : `Freeze selected (${selectedCount})` }}
        </UiButton>
        <UiButton size="sm" @click="openCreate">
          <Plus class="h-4 w-4" />
          New User
        </UiButton>
      </template>
    </PageHeader>

    <p v-if="error" class="field-error">{{ error }}</p>

    <div v-if="loading" class="py-12 text-center text-sm text-muted-foreground">Loading…</div>
    <div v-else class="overflow-hidden rounded-xl border border-border/50 bg-card shadow-sm">
      <div
        v-if="users.length === 0"
        class="flex flex-col items-center justify-center py-16 text-muted-foreground"
      >
        <UserRound class="mb-3 h-10 w-10 text-muted-foreground/20" />
        <p class="text-sm">No users</p>
      </div>
      <template v-else>
        <div class="border-b border-border/30 px-5 py-3">
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Search users…"
            class="w-full max-w-xs rounded-lg border border-border/60 bg-background px-3 py-1.5 text-xs outline-none transition-colors focus:border-primary/50 focus:ring-1 focus:ring-primary/10"
          />
        </div>

        <div
          v-if="filteredUsers.length === 0"
          class="px-5 py-12 text-center text-sm text-muted-foreground"
        >
          No users match “{{ searchQuery }}”
        </div>
        <template v-else>
          <div class="overflow-x-auto">
            <table class="w-full text-[13px]">
              <thead>
                <tr class="border-b border-border/30 bg-muted/10">
                  <th class="w-10 px-5 py-2.5 text-left">
                    <input
                      type="checkbox"
                      class="rounded"
                      :checked="allPageSelected"
                      :disabled="selectableOnPage.length === 0"
                      @change="togglePage(($event.target as HTMLInputElement).checked)"
                    />
                  </th>
                  <SortableTh
                    label="Email"
                    column="email"
                    :indicator="sortIndicator('email')"
                    @toggle="toggleSort"
                  />
                  <SortableTh
                    label="Name"
                    column="display_name"
                    :indicator="sortIndicator('display_name')"
                    @toggle="toggleSort"
                  />
                  <th class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                    Phone
                  </th>
                  <SortableTh
                    label="Role"
                    column="role"
                    :indicator="sortIndicator('role')"
                    @toggle="toggleSort"
                  />
                  <th class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                    MFA
                  </th>
                  <th class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                    SSO
                  </th>
                  <SortableTh
                    label="Status"
                    column="status"
                    :indicator="sortIndicator('status')"
                    @toggle="toggleSort"
                  />
                  <th class="w-52 px-5 py-2.5 text-right text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-border/20">
                <tr
                  v-for="u in pageItems"
                  :key="u.id"
                  :class="
                    u.status === 'disabled'
                      ? 'bg-destructive/[0.04] text-muted-foreground hover:bg-destructive/[0.07]'
                      : 'hover:bg-muted/5'
                  "
                >
                  <td class="px-5 py-3">
                    <input
                      type="checkbox"
                      class="rounded"
                      :disabled="
                        u.status !== 'active' || u.id === auth.user?.id || !canMutate(u)
                      "
                      :checked="selected.has(u.id)"
                      @change="toggleOne(u.id, ($event.target as HTMLInputElement).checked)"
                    />
                  </td>
                  <td
                    class="px-5 py-3 font-semibold"
                    :class="u.status === 'disabled' && 'line-through decoration-destructive/40'"
                  >
                    {{ u.email }}
                    <div
                      v-if="u.username"
                      class="text-[11px] font-normal text-muted-foreground"
                    >
                      @{{ u.username }}
                    </div>
                    <span
                      v-if="u.status === 'disabled'"
                      class="ml-2 align-middle text-[10px] font-semibold uppercase tracking-[0.06em] text-destructive"
                    >
                      Frozen
                    </span>
                  </td>
                  <td class="px-5 py-3 text-xs">{{ u.display_name }}</td>
                  <td class="px-5 py-3 text-xs">{{ u.phone || "—" }}</td>
                  <td class="px-5 py-3 text-xs">{{ u.role }}</td>
                  <td class="px-5 py-3 text-xs">
                    <span
                      v-if="u.totp_enabled"
                      class="inline-flex items-center rounded-md bg-primary/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-primary"
                      title="TOTP authenticator bound"
                    >
                      Enabled
                    </span>
                    <span
                      v-else-if="u.mfa_required"
                      class="inline-flex items-center rounded-md bg-amber-500/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-amber-700"
                      title="MFA required by policy"
                    >
                      Required
                    </span>
                    <span v-else class="text-muted-foreground">Off</span>
                  </td>
                  <td class="px-5 py-3 text-xs">
                    <div
                      v-if="u.provisioned_via === 'sso_jit' || u.sso_identities.length"
                      class="flex flex-wrap items-center gap-1"
                    >
                      <span
                        v-if="u.provisioned_via === 'sso_jit'"
                        class="inline-flex items-center rounded-md bg-sky-500/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-sky-700 dark:text-sky-400"
                        title="Account was created by SSO JIT provisioning"
                      >
                        SSO origin
                      </span>
                      <span
                        v-for="i in u.sso_identities"
                        :key="i.provider_code"
                        class="inline-flex items-center rounded-md bg-muted px-1.5 py-0.5 text-[11px] font-medium text-foreground"
                        :title="`Linked ${i.provider_type}: ${i.provider_code}`"
                      >
                        {{ i.display_name }}
                      </span>
                      <span
                        v-if="!u.has_password && u.sso_identities.length"
                        class="text-[10px] text-muted-foreground"
                        title="No local password set"
                      >
                        SSO-only
                      </span>
                    </div>
                    <span v-else class="text-muted-foreground">—</span>
                  </td>
                  <td class="px-5 py-3 text-xs">
                    <span
                      :class="
                        u.status === 'disabled'
                          ? 'inline-flex items-center rounded-md bg-destructive/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-destructive'
                          : 'text-foreground'
                      "
                    >
                      {{ u.status === "disabled" ? "frozen" : u.status }}
                    </span>
                  </td>
                  <td class="space-x-1 whitespace-nowrap px-5 py-3 text-right">
                    <UiButton
                      v-if="canMutate(u)"
                      variant="ghost"
                      size="sm"
                      @click="openEdit(u)"
                    >
                      Edit
                    </UiButton>
                    <UiButton
                      v-if="u.status === 'active' && u.id !== auth.user?.id && canMutate(u)"
                      variant="ghost"
                      size="sm"
                      @click="onDisable(u)"
                    >
                      Freeze
                    </UiButton>
                    <UiButton
                      v-if="u.status === 'disabled' && canMutate(u)"
                      variant="ghost"
                      size="sm"
                      @click="onEnable(u)"
                    >
                      Unfreeze
                    </UiButton>
                    <UiButton
                      v-if="u.status === 'active' && canMutate(u)"
                      variant="ghost"
                      size="sm"
                      title="Sign out all active sessions"
                      @click="onRevokeSessions(u)"
                    >
                      Revoke sessions
                    </UiButton>
                    <UiButton
                      v-if="auth.isAdmin && u.totp_enabled"
                      variant="ghost"
                      size="sm"
                      title="Reset 2FA"
                      @click="onResetMfa(u)"
                    >
                      Reset 2FA
                    </UiButton>
                    <UiButton
                      v-if="auth.canDeleteUsers && u.id !== auth.user?.id"
                      variant="ghost"
                      size="sm"
                      title="Delete"
                      @click="onDelete(u)"
                    >
                      <Trash2 class="h-3.5 w-3.5 text-destructive" />
                      Delete
                    </UiButton>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
          <TablePagination
            v-model:page="page"
            v-model:page-size="pageSize"
            :total="total"
            :page-count="pageCount"
            :range-label="rangeLabel"
          />
        </template>
      </template>
    </div>

    <Teleport to="body">
      <div
        v-if="showCreate"
        class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      >
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="showCreate = false" />
        <div
          class="relative z-10 my-auto w-full max-w-md max-h-[calc(100dvh-2rem)] overflow-y-auto overscroll-contain rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-5 text-[15px] font-semibold">New User</h3>
          <form class="space-y-4" @submit.prevent="onCreate">
            <div>
              <label class="mb-1 block text-[12px] font-medium">Email <span class="text-red-500">*</span></label>
              <input v-model="formEmail" type="email" required class="field-input" />
              <p v-if="emailCheckState === 'exists'" class="mt-1 text-[11px] text-red-500">
                This email is already registered.
              </p>
              <p v-else-if="emailCheckState === 'checking'" class="mt-1 text-[11px] text-muted-foreground">
                Checking…
              </p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Username</label>
              <input v-model="formUsername" class="field-input" placeholder="Optional login name" />
              <p v-if="usernameCheckState === 'exists'" class="mt-1 text-[11px] text-red-500">
                This username is already taken.
              </p>
              <p v-else-if="usernameCheckState === 'checking'" class="mt-1 text-[11px] text-muted-foreground">
                Checking…
              </p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Display name</label>
              <input v-model="formDisplayName" class="field-input" />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Phone</label>
              <input v-model="formPhone" class="field-input" placeholder="e.g. +86 138 0000 0000" />
              <p v-if="phoneCheckState === 'exists'" class="mt-1 text-[11px] text-red-500">
                This phone is already registered.
              </p>
              <p v-else-if="phoneCheckState === 'checking'" class="mt-1 text-[11px] text-muted-foreground">
                Checking…
              </p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Password <span class="text-red-500">*</span></label>
              <input
                v-model="formPassword"
                type="password"
                required
                minlength="10"
                title="10+ characters with upper, lower case and a digit"
                class="field-input"
              />
            </div>
            <label class="flex items-start gap-2 text-sm">
              <input v-model="formMustChangePassword" type="checkbox" class="mt-0.5 rounded" />
              <span>
                <span class="block text-[12px] font-medium">Require password change</span>
                <span class="type-meta">Force this user to set a new password on first login</span>
              </span>
            </label>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Role</label>
              <select v-model="formRole" class="field-input">
                <option v-for="r in roleOptions" :key="r" :value="r">{{ r }}</option>
              </select>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Groups</label>
              <input
                v-model="formGroups"
                placeholder="comma-separated, e.g. eng, ops"
                class="field-input"
              />
            </div>
            <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
              <UiButton type="button" variant="ghost" size="sm" @click="showCreate = false">Cancel</UiButton>
              <UiButton
                type="submit"
                size="sm"
                :disabled="creating || emailCheckState === 'exists' || phoneCheckState === 'exists' || usernameCheckState === 'exists'"
              >
                {{ creating ? "Creating…" : "Create" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <Teleport to="body">
      <div
        v-if="editing"
        class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      >
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="editing = null" />
        <div
          class="relative z-10 my-auto w-full max-w-md max-h-[calc(100dvh-2rem)] overflow-y-auto overscroll-contain rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-5 text-[15px] font-semibold">Edit User</h3>
          <form class="space-y-4" @submit.prevent="onSaveEdit">
            <div>
              <label class="mb-1 block text-[12px] font-medium">Email</label>
              <input v-model="editEmail" type="email" required class="field-input" />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Username</label>
              <input v-model="editUsername" class="field-input" placeholder="Optional login name" />
              <p v-if="editUsernameCheckState === 'exists'" class="mt-1 text-[11px] text-red-500">
                This username is already taken.
              </p>
              <p v-else-if="editUsernameCheckState === 'checking'" class="mt-1 text-[11px] text-muted-foreground">
                Checking…
              </p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Display name</label>
              <input v-model="editDisplayName" required class="field-input" />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Phone</label>
              <input v-model="editPhone" class="field-input" placeholder="e.g. +86 138 0000 0000" />
              <p v-if="editPhoneCheckState === 'exists'" class="mt-1 text-[11px] text-red-500">
                This phone is already registered.
              </p>
              <p v-else-if="editPhoneCheckState === 'checking'" class="mt-1 text-[11px] text-muted-foreground">
                Checking…
              </p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Role</label>
              <select v-model="editRole" class="field-input">
                <option v-for="r in roleOptions" :key="r" :value="r">{{ r }}</option>
              </select>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Status</label>
              <select v-model="editStatus" class="field-input">
                <option value="active">active</option>
                <option value="disabled">frozen</option>
              </select>
            </div>
            <label class="flex items-start gap-2 text-sm">
              <input v-model="editMfaRequired" type="checkbox" class="mt-0.5 rounded" />
              <span>
                <span class="block text-[12px] font-medium">Require MFA</span>
                <span class="type-meta">Force authenticator setup on next login if not enabled</span>
              </span>
            </label>
            <label class="flex items-start gap-2 text-sm">
              <input v-model="editMustChangePassword" type="checkbox" class="mt-0.5 rounded" />
              <span>
                <span class="block text-[12px] font-medium">Require password change</span>
                <span class="type-meta">Force this user to set a new password on next login</span>
              </span>
            </label>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Groups</label>
              <input
                v-model="editGroups"
                placeholder="comma-separated, e.g. eng, ops"
                class="field-input"
              />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">New password</label>
              <input
                v-model="editPassword"
                type="password"
                minlength="10"
                placeholder="Leave blank to keep"
                title="10+ characters with upper, lower case and a digit"
                class="field-input"
              />
            </div>
            <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
              <UiButton type="button" variant="ghost" size="sm" @click="editing = null">Cancel</UiButton>
              <UiButton type="submit" size="sm" :disabled="saving || editPhoneCheckState === 'exists' || editUsernameCheckState === 'exists'">
                {{ saving ? "Saving…" : "Save" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>
  </div>
</template>
