<script setup lang="ts">
import { Check, Copy, Download, LogOut, Power, PowerOff, ShieldCheck, Trash2, Upload, UserRound, UserRoundX } from "@lucide/vue";
import { computed, onMounted, ref, watch } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UsersToolbar from "@/components/directory/UsersToolbar.vue";
import RowActionsMenu, { type RowActionItem } from "@/components/ui/RowActionsMenu.vue";
import SortableTh from "@/components/ui/SortableTh.vue";
import TablePagination from "@/components/ui/TablePagination.vue";
import UiButton from "@/components/ui/UiButton.vue";
import { buttonClass } from "@/components/ui/button";
import { useServerList } from "@/composables/useServerList";
import { confirm } from "@/lib/confirm";
import {
  USERS_EXPORT_URL,
  batchDisableUsers,
  checkEmail,
  checkPhone,
  checkUsername,
  createUser,
  deleteUser,
  disableUser,
  enableUser,
  importUsers,
  listUsers,
  resetUserMfa,
  removeGroupMember,
  revokeUserSessions,
  updateUser,
  type AdminUser,
  type AdminUserSortKey,
  type ImportUserRow,
  type PublicUser,
  type UserRole,
} from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();

const props = withDefaults(
  defineProps<{
    /** Rendered inside Directory: no page header, compact action row. */
    embedded?: boolean;
    /** A group uuid, or "ungrouped"; absent means every user. */
    groupId?: string | null;
    includeDescendants?: boolean;
    /** Prefills the new-user form with the selected group's name. */
    groupName?: string | null;
    groupSource?: "local" | "scim" | "directory" | null;
    /** Bumped by the parent after membership writes to force a reload. */
    refreshKey?: number;
  }>(),
  {
    embedded: false,
    groupId: null,
    includeDescendants: false,
    groupName: null,
    groupSource: null,
    refreshKey: 0,
  },
);
const emit = defineEmits<{ membershipChanged: [] }>();

const showCreate = ref(false);
const editing = ref<PublicUser | null>(null);
const creating = ref(false);
const saving = ref(false);
const searchQuery = ref("");
const selected = ref<Set<string>>(new Set());
const batching = ref(false);
const importing = ref(false);
const importInput = ref<HTMLInputElement | null>(null);
const importSummary = ref<string | null>(null);
const showImport = ref(false);
const pendingFileName = ref("");
const pendingUsers = ref<ImportUserRow[] | null>(null);
const importPreview = ref<Awaited<ReturnType<typeof importUsers>> | null>(null);
const importError = ref("");

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

const {
  page,
  pageSize,
  pageCount,
  total,
  pageItems,
  rangeLabel,
  loading,
  initialLoading,
  error,
  toggleSort,
  sortIndicator,
  reload,
} =
  useServerList<AdminUser>({
    load: async ({ q, sort, dir, limit, offset }) => {
      const { users: rows, total: matched } = await listUsers({
        q,
        sort: sort as AdminUserSortKey,
        dir,
        limit,
        offset,
        group_id: props.groupId,
        include_descendants: props.includeDescendants,
      });
      return { items: rows, total: matched };
    },
    initialSort: "created_at",
    initialDir: "desc",
    search: searchQuery,
  });

// The directory tree is the filter: a new node starts a new result set.
watch(
  () => [props.groupId, props.includeDescendants] as const,
  () => {
    page.value = 1;
    void reload();
  },
);
watch(
  () => props.refreshKey,
  () => void reload(),
);

const exportUrl = computed(() => {
  const qs = new URLSearchParams();
  if (props.groupId) qs.set("group_id", props.groupId);
  if (props.includeDescendants) qs.set("include_descendants", "true");
  const suffix = qs.toString();
  return suffix ? `${USERS_EXPORT_URL}?${suffix}` : USERS_EXPORT_URL;
});

defineExpose({ reload });

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
  await reload();
  // Only the page that just came back can be checked: an id it shows as no
  // longer selectable is dropped, and selections made on other pages are left
  // alone rather than guessed about. The old version filtered against the whole
  // table, which is exactly what this list no longer holds.
  const visible = new Map(pageItems.value.map((u) => [u.id, u.status === "active"]));
  selected.value = new Set([...selected.value].filter((id) => visible.get(id) !== false));
}

onMounted(async () => {
  try {
    if (!auth.user) await auth.fetchMe();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load users";
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
  formGroups.value = props.groupName ?? "";
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

/** Which row's email was copied last, and the timer that clears the tick. */
const copiedId = ref<string | null>(null);
let copiedTimer: ReturnType<typeof setTimeout> | undefined;

async function copyEmail(u: PublicUser) {
  try {
    await navigator.clipboard.writeText(u.email);
    copiedId.value = u.id;
    if (copiedTimer) clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      copiedId.value = null;
    }, 1500);
  } catch {
    /* clipboard unavailable — nothing to tell the operator that matters */
  }
}

/** The uid line under the email copies the id, the same tick feedback. */
async function copyUid(u: PublicUser) {
  try {
    await navigator.clipboard.writeText(u.id);
    copiedId.value = u.id;
    if (copiedTimer) clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      copiedId.value = null;
    }, 1500);
  } catch {
    /* clipboard unavailable */
  }
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

/**
 * How an authority that froze an account is shown.
 *
 * The label answers "who did this to my user", which is the first question at
 * the list level; the title adds what it would take to release it, which is the
 * second. `directory` is deliberately generic — which source it is belongs on
 * the directory page, and a per-row lookup would be a query per user.
 */
function heldBy(u: PublicUser, by: PublicUser["disabled_by"][number]) {
  switch (by) {
    case "local":
      return { label: "admin", title: "Frozen by an administrator — Unfreeze clears this" };
    case "directory":
      return {
        label: "directory",
        title:
          "Disabled by directory sync because the account was missing upstream. " +
          "It comes back when the source lists it again" +
          (u.local_disabled ? ", and after the local freeze is cleared" : ""),
      };
    default:
      return {
        label: "scim",
        title: "Disabled by the SCIM client. Only that client can re-activate it",
      };
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
  if (
    !(await confirm({
      title: "Revoke all sessions?",
      message: `Every active sign-in for "${u.email}" will be signed out.`,
      confirmText: "Revoke",
      danger: true,
    }))
  ) {
    return;
  }
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
    !(await confirm({
      title: "Reset MFA?",
      message: `The authenticator and recovery codes for "${u.email}" will be cleared. They will have to set up 2FA again on next sign-in.`,
      confirmText: "Reset MFA",
      danger: true,
    }))
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
  if (
    !(await confirm({
      title: "Delete user?",
      message: `"${u.email}" will be permanently removed. This cannot be undone.`,
      confirmText: "Delete",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  try {
    await deleteUser(u.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Delete failed";
  }
}

function openImport() {
  importError.value = "";
  importPreview.value = null;
  pendingUsers.value = null;
  pendingFileName.value = "";
  if (importInput.value) importInput.value.value = "";
  showImport.value = true;
}

function closeImport() {
  showImport.value = false;
  importError.value = "";
  importPreview.value = null;
  pendingUsers.value = null;
  if (importInput.value) importInput.value.value = "";
}

async function onImportFile(event: Event) {
  importError.value = "";
  importPreview.value = null;
  pendingUsers.value = null;
  const input = event.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;
  pendingFileName.value = file.name;

  importing.value = true;
  try {
    let parsed: unknown;
    try {
      parsed = JSON.parse(await file.text());
    } catch {
      importError.value = "The file is not valid JSON";
      return;
    }
    // Accept either a bare array or `{ users: [...] }`.
    const users = Array.isArray(parsed)
      ? parsed
      : (parsed as { users?: unknown }).users;
    if (!Array.isArray(users)) {
      importError.value = 'Expected a JSON array of users, or {"users": [...]}';
      return;
    }
    if (users.length === 0) {
      importError.value = "The file contains no users";
      return;
    }
    // Validate the whole batch first: dry_run runs every gate server-side and
    // writes nothing, so a bad file is caught before any account changes.
    const preview = await importUsers(users as ImportUserRow[], false, true);
    if (preview.errors.length) {
      importError.value =
        `${preview.errors.length} problem row(s) found; nothing was written. ` +
        preview.errors
          .slice(0, 5)
          .map((e) => `row ${e.row}: ${e.error}`)
          .join("; ");
      return;
    }
    pendingUsers.value = users as ImportUserRow[];
    importPreview.value = preview;
  } catch (e) {
    importError.value = e instanceof Error ? e.message : "Import preview failed";
  } finally {
    importing.value = false;
    if (importInput.value) importInput.value.value = "";
  }
}

async function commitImport() {
  if (!pendingUsers.value) return;
  importError.value = "";
  importing.value = true;
  try {
    const res = await importUsers(pendingUsers.value, false);
    importSummary.value = `Created ${res.created.length}, skipped ${res.skipped.length}, failed ${res.errors.length}`;
    if (res.errors.length) {
      error.value = res.errors
        .slice(0, 5)
        .map((e) => `row ${e.row}: ${e.error}`)
        .join("; ");
    }
    closeImport();
    await refresh();
  } catch (e) {
    importError.value = e instanceof Error ? e.message : "Import failed";
  } finally {
    importing.value = false;
  }
}

// Row actions: Edit stays inline (frequent); the rest live in the menu.
function rowActions(u: PublicUser): RowActionItem[] {
  if (!canMutate(u)) return [];
  const items: RowActionItem[] = [];
  if (u.status === "active" && u.id !== auth.user?.id) {
    items.push({ key: "disable", label: "Freeze", icon: PowerOff });
  }
  if (u.status === "disabled" && u.can_enable) {
    items.push({ key: "enable", label: "Unfreeze", icon: Power });
  }
  if (u.status === "active") {
    items.push({
      key: "revoke",
      label: "Revoke sessions",
      icon: LogOut,
      title: "Sign out all active sessions",
    });
  }
  if (auth.isAdmin && u.totp_enabled) {
    items.push({ key: "reset-mfa", label: "Reset 2FA", icon: ShieldCheck });
  }
  if (
    props.groupId &&
    props.groupId !== "ungrouped" &&
    props.groupSource === "local" &&
    canMutate(u)
  ) {
    items.push({
      key: "remove-group",
      label: "Remove from this group",
      icon: UserRoundX,
    });
  }
  if (auth.canDeleteUsers && u.id !== auth.user?.id) {
    items.push({
      key: "delete",
      label: "Delete",
      icon: Trash2,
      danger: true,
      separator: true,
    });
  }
  return items;
}

function onRowAction(u: PublicUser, key: string) {
  if (key === "disable") void onDisable(u);
  else if (key === "enable") void onEnable(u);
  else if (key === "revoke") void onRevokeSessions(u);
  else if (key === "reset-mfa") void onResetMfa(u);
  else if (key === "delete") void onDelete(u);
  else if (key === "remove-group") void onRemoveFromGroup(u);
}

async function onRemoveFromGroup(u: PublicUser) {
  if (!props.groupId) return;
  error.value = "";
  try {
    await removeGroupMember(props.groupId, u.id);
    await reload();
    emit("membershipChanged");
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Remove from group failed";
  }
}

async function onBatchDisable() {
  if (selectedCount.value === 0) return;
  if (
    !(await confirm({
      title: "Freeze selected users?",
      message: `${selectedCount.value} account(s) will be frozen and signed out.`,
      confirmText: "Freeze",
      danger: true,
    }))
  ) {
    return;
  }
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
      v-if="!embedded"
      title="Users"
      description="Manage Signet accounts. Freeze/edit for staff; delete is admin-only."
    >
      <template #actions>
        <UsersToolbar
          :selected-count="selectedCount"
          :batching="batching"
          :export-url="exportUrl"
          @freeze="onBatchDisable"
          @import-json="openImport"
          @create="openCreate"
        />
      </template>
    </PageHeader>

    <p v-if="error" class="field-error">{{ error }}</p>
    <p v-if="importSummary" class="type-meta text-[12px]">{{ importSummary }}</p>

    <div
      v-if="initialLoading"
      class="py-12 text-center text-sm text-muted-foreground"
    >
      Loading…
    </div>
    <div
      v-else
      class="surface-card overflow-hidden transition-opacity"
      :class="loading ? 'opacity-60' : ''"
    >
      <div
        class="flex flex-wrap items-center justify-between gap-2 border-b border-border/30 px-5 py-3"
      >
        <input
          v-model="searchQuery"
          type="search"
          placeholder="Search users…"
          class="w-full max-w-xs rounded-lg border border-border/60 bg-background px-3 py-1.5 text-xs outline-none transition-colors focus:border-primary/50 focus:ring-1 focus:ring-primary/10"
        />
        <UsersToolbar
          v-if="embedded"
          :selected-count="selectedCount"
          :batching="batching"
          :export-url="exportUrl"
          @freeze="onBatchDisable"
          @import-json="openImport"
          @create="openCreate"
        />
      </div>

      <div
        v-if="total === 0 && !searchQuery.trim()"
        class="flex flex-col items-center justify-center py-16 text-muted-foreground"
      >
        <UserRound class="mb-3 h-10 w-10 text-muted-foreground/20" />
        <p class="text-sm">No users</p>
      </div>
      <div
        v-else-if="pageItems.length === 0"
        class="px-5 py-12 text-center text-sm text-muted-foreground"
      >
        No users match “{{ searchQuery }}”
      </div>
      <template v-else>
          <div class="overflow-x-auto">
            <table class="w-full text-[13px]">
              <thead>
                <tr class="border-b border-border/50">
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
                  <SortableTh
                    label="Role"
                    column="role"
                    :indicator="sortIndicator('role')"
                    @toggle="toggleSort"
                  />
                  <th class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                    MFA
                  </th>
                  <th class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                    SSO
                  </th>
                  <SortableTh
                    label="Status"
                    column="status"
                    :indicator="sortIndicator('status')"
                    @toggle="toggleSort"
                  />
                  <th class="px-5 py-2.5 text-right text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="u in pageItems"
                  :key="u.id"
                  :class="
                    u.status === 'disabled'
                      ? 'border-b border-border/40 bg-destructive/[0.04] text-muted-foreground last:border-0 hover:bg-destructive/[0.07]'
                      : 'border-b border-border/40 last:border-0 hover:bg-muted/5'
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
                    <span class="inline-flex items-center gap-1.5">
                      {{ u.email }}
                      <span
                        v-if="u.email_verified"
                        class="ml-1 align-middle text-[10px] text-muted-foreground"
                        title="Email verified"
                      >✓</span>
                      <button
                        type="button"
                        class="rounded p-1 text-muted-foreground/60 transition-colors hover:bg-muted/40 hover:text-foreground"
                        :title="copiedId === u.id ? 'Copied' : 'Copy email'"
                        :aria-label="copiedId === u.id ? 'Copied' : 'Copy email'"
                        @click="copyEmail(u)"
                      >
                        <Check v-if="copiedId === u.id" class="h-3.5 w-3.5 text-primary" />
                        <Copy v-else class="h-3.5 w-3.5" />
                      </button>
                    </span>
                    <!-- The login alias (second way to sign in, next to the
                         email). Only shown when it actually says something
                         the email does not. -->
                    <div
                      v-if="u.username && u.username !== u.email.split('@')[0]"
                      class="truncate text-[11px] font-normal text-muted-foreground"
                      :title="`username: ${u.username}`"
                    >
                      username: {{ u.username }}
                    </div>
                    <!-- The immutable id (used by SCIM, OIDC `sub`, audit
                         lookups). monospace + truncated so a full UUID does
                         not stretch the column; full value on hover. -->
                    <div
                      class="cursor-pointer truncate font-mono text-[10px] text-muted-foreground/70 hover:text-foreground"
                      :title="`id: ${u.id}${copiedId === u.id ? ' (copied)' : ''} — click to copy`"
                      role="button"
                      tabindex="0"
                      @click.stop="copyUid(u)"
                      @keydown.enter.stop="copyUid(u)"
                    >
                      id: {{ u.id }}
                    </div>
                    <span
                      v-if="u.status === 'disabled'"
                      class="ml-2 align-middle text-[10px] font-semibold uppercase tracking-[0.06em] text-destructive"
                    >
                      Frozen
                    </span>
                  </td>
                  <td class="px-5 py-3 text-xs">{{ u.display_name }}</td>
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
                    <div v-if="u.status === 'disabled'" class="flex flex-wrap items-center gap-1">
                      <span
                        v-for="by in u.disabled_by"
                        :key="by"
                        class="inline-flex items-center rounded-md bg-destructive/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-destructive"
                        :title="heldBy(u, by).title"
                      >
                        {{ heldBy(u, by).label }}
                      </span>
                      <span
                        v-if="!u.can_enable"
                        class="text-[10px] text-muted-foreground"
                        title="Only the authority that froze the account can release it"
                      >
                        upstream
                      </span>
                    </div>
                    <span v-else class="text-foreground">{{ u.status }}</span>
                  </td>
                  <td class="whitespace-nowrap px-5 py-3 text-right align-middle">
                    <div class="flex items-center justify-end gap-1">
                    <UiButton
                      v-if="canMutate(u)"
                      variant="ghost"
                      size="sm"
                      class="text-[13px] font-normal"
                      @click="openEdit(u)"
                    >
                      Edit
                    </UiButton>
                    <!-- An Unfreeze that an upstream would override is not
                         offered: it returns 200, changes nothing, and the only
                         thing the operator learns is that the button lies. The
                         hold stays visible inline — it is state, not an action. -->
                    <span
                      v-if="u.status === 'disabled' && canMutate(u) && !u.can_enable"
                      class="text-[13px] text-muted-foreground"
                      :title="`Disabled by ${u.disabled_by.join(', ')} — releasing the local hold would not bring the account back`"
                    >
                      Held upstream
                    </span>
                    <RowActionsMenu
                      v-if="rowActions(u).length"
                      :items="rowActions(u)"
                      label="More actions"
                      @select="(key) => onRowAction(u, key)"
                    />
                    </div>
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
        v-if="showImport"
        class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      >
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="closeImport" />
        <div
          class="relative z-10 my-auto w-full max-w-md max-h-[calc(100dvh-2rem)] overflow-y-auto overscroll-contain rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-5 text-[15px] font-semibold">Import users from JSON</h3>

          <div class="space-y-3">
            <div>
              <p class="mb-1 block text-[12px] font-medium">1. Get the template</p>
              <p class="type-meta mb-2">
                Only <span class="font-medium text-foreground">email</span> is
                required; <code class="rounded bg-muted px-1 py-0.5 text-[11px]">username</code>,
                <code class="rounded bg-muted px-1 py-0.5 text-[11px]">display_name</code>,
                <code class="rounded bg-muted px-1 py-0.5 text-[11px]">role</code>
                (member/manager/admin),
                <code class="rounded bg-muted px-1 py-0.5 text-[11px]">groups</code>,
                <code class="rounded bg-muted px-1 py-0.5 text-[11px]">phone</code> and
                <code class="rounded bg-muted px-1 py-0.5 text-[11px]">password</code>
                are optional. Omit password for a passwordless (SSO/reset) account.
              </p>
              <a
                href="/users-import-template.json"
                download
                :class="buttonClass('secondary', 'sm')"
              >
                <Download class="h-4 w-4" />
                Download template
              </a>
            </div>

            <div>
              <p class="mb-1 block text-[12px] font-medium">2. Upload the filled-in file</p>
              <input
                ref="importInput"
                type="file"
                accept="application/json,.json"
                class="hidden"
                @change="onImportFile"
              />
              <UiButton
                type="button"
                variant="secondary"
                size="sm"
                :disabled="importing"
                @click="importInput?.click()"
              >
                <Upload class="h-4 w-4" />
                Choose JSON file…
              </UiButton>
              <span v-if="pendingFileName" class="ml-2 text-[12px] text-muted-foreground">
                {{ pendingFileName }}
              </span>
            </div>
          </div>

          <p v-if="importError" class="field-error mt-4">{{ importError }}</p>

          <div
            v-if="importPreview"
            class="mt-4 rounded-xl border border-border/50 bg-muted/40 p-3 text-[12px]"
          >
            Preview OK — would create
            {{ importPreview.created.length }}<template v-if="importPreview.updated.length">,
            update {{ importPreview.updated.length }}</template><template v-if="importPreview.skipped.length">,
            skip {{ importPreview.skipped.length }}</template>.
            Nothing is written until you confirm.
          </div>

          <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
            <UiButton type="button" variant="ghost" size="sm" @click="closeImport">
              Cancel
            </UiButton>
            <UiButton
              type="button"
              size="sm"
              :disabled="!importPreview || importing"
              @click="commitImport"
            >
              {{ importing ? "Working…" : "Import" }}
            </UiButton>
          </div>
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
              <!-- Saving after an upstream freeze is not a no-op — it clears
                   the local hold — but it does not un-freeze the account, and
                   saying so here is the difference between that and a bug. -->
              <p
                v-if="editing && !editing.can_enable"
                class="type-meta mt-1 text-amber-700 dark:text-amber-400"
              >
                Held by {{ editing.disabled_by.join(" + ") }}: choosing active clears the
                local freeze only, and the account stays frozen until that authority lets go.
              </p>
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
