<script setup lang="ts">
import {
  Building2,
  ChevronRight,
  Plus,
  Search,
  Trash2,
  UserPlus,
  UserRoundX,
  UsersRound,
} from "@lucide/vue";
import { computed, onMounted, ref, watch } from "vue";
import UsersView from "@/views/UsersView.vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import { confirm } from "@/lib/confirm";
import {
  addGroupMembers,
  createGroup,
  deleteGroup,
  listGroups,
  listUsers,
  updateGroup,
  type AdminGroup,
  type AdminUser,
  type GroupKind,
} from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();

// --- tree -----------------------------------------------------------------

const groups = ref<AdminGroup[]>([]);
const loading = ref(true);
const error = ref("");
/// "all" | "ungrouped" | a group uuid.
const selectedKey = ref<string>("all");
const expanded = ref<Set<string>>(new Set());
const includeDescendants = ref(false);
const refreshKey = ref(0);

const allCount = ref(0);
const ungroupedCount = ref(0);

const childrenMap = computed(() => {
  const map = new Map<string | null, AdminGroup[]>();
  for (const g of groups.value) {
    const bucket = map.get(g.parent_id) ?? [];
    bucket.push(g);
    map.set(g.parent_id, bucket);
  }
  for (const bucket of map.values()) {
    bucket.sort((a, b) => a.display_name.localeCompare(b.display_name));
  }
  return map;
});

interface TreeRow {
  group: AdminGroup;
  depth: number;
  hasChildren: boolean;
}

const treeRows = computed<TreeRow[]>(() => {
  const out: TreeRow[] = [];
  const walk = (parent: string | null, depth: number) => {
    for (const group of childrenMap.value.get(parent) ?? []) {
      const children = childrenMap.value.get(group.id) ?? [];
      out.push({ group, depth, hasChildren: children.length > 0 });
      if (expanded.value.has(group.id)) walk(group.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
});

const selectedGroup = computed(() =>
  selectedKey.value === "all" || selectedKey.value === "ungrouped"
    ? null
    : (groups.value.find((g) => g.id === selectedKey.value) ?? null),
);

const userIdFilter = computed(() =>
  selectedKey.value === "all" ? null : selectedKey.value,
);

const selectedHasChildren = computed(
  () => (childrenMap.value.get(selectedKey.value) ?? []).length > 0,
);

const breadcrumb = computed(() => {
  const chain: AdminGroup[] = [];
  let current = selectedGroup.value;
  const seen = new Set<string>();
  while (current && !seen.has(current.id)) {
    seen.add(current.id);
    chain.unshift(current);
    current = current.parent_id
      ? (groups.value.find((g) => g.id === current!.parent_id) ?? null)
      : null;
  }
  return chain;
});

function toggle(id: string) {
  const next = new Set(expanded.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  expanded.value = next;
}

function select(key: string) {
  selectedKey.value = key;
  if (key !== "all" && key !== "ungrouped" && (childrenMap.value.get(key) ?? []).length > 0) {
    expanded.value = new Set(expanded.value).add(key);
  }
}

// A new node is a new result set; the subtree toggle starts off.
watch(selectedKey, () => {
  includeDescendants.value = false;
});

async function refreshGroups() {
  groups.value = await listGroups();
  if (
    selectedKey.value !== "all" &&
    selectedKey.value !== "ungrouped" &&
    !groups.value.some((g) => g.id === selectedKey.value)
  ) {
    selectedKey.value = "all";
  }
  if (expanded.value.size === 0) {
    expanded.value = new Set(
      groups.value.filter((g) => g.parent_id === null).map((g) => g.id),
    );
  }
}

/// The two pseudo nodes' counts. Advisory: a failure leaves the table usable.
async function refreshCounts() {
  try {
    const [all, ungrouped] = await Promise.all([
      listUsers({ limit: 1 }),
      listUsers({ group_id: "ungrouped", limit: 1 }),
    ]);
    allCount.value = all.total;
    ungroupedCount.value = ungrouped.total;
  } catch {
    /* leave the previous counts */
  }
}

onMounted(async () => {
  try {
    await Promise.all([refreshGroups(), refreshCounts()]);
    const first = treeRows.value[0];
    if (first) select(first.group.id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load the directory";
  } finally {
    loading.value = false;
  }
});

async function afterMembershipChange() {
  refreshKey.value += 1;
  await Promise.all([refreshGroups(), refreshCounts()]);
}

// --- group editor ---------------------------------------------------------

const showEditor = ref(false);
const editorMode = ref<"create" | "edit">("create");
const editorKind = ref<GroupKind>("group");
const editorName = ref("");
const editorParent = ref("");
const editorSaving = ref(false);

function openCreate() {
  editorMode.value = "create";
  editorKind.value = "group";
  editorName.value = "";
  const sel = selectedGroup.value;
  editorParent.value = sel
    ? sel.kind === "department"
      ? sel.id
      : (sel.parent_id ?? "")
    : "";
  showEditor.value = true;
}

function openEdit() {
  const sel = selectedGroup.value;
  if (!sel) return;
  editorMode.value = "edit";
  editorKind.value = sel.kind;
  editorName.value = sel.display_name;
  editorParent.value = sel.parent_id ?? "";
  showEditor.value = true;
}

function subtreeIds(id: string): Set<string> {
  const out = new Set<string>([id]);
  const walk = (parent: string) => {
    for (const child of childrenMap.value.get(parent) ?? []) {
      if (!out.has(child.id)) {
        out.add(child.id);
        walk(child.id);
      }
    }
  };
  walk(id);
  return out;
}

const parentOptions = computed(() => {
  const excluded =
    editorMode.value === "edit" && selectedGroup.value
      ? subtreeIds(selectedGroup.value.id)
      : new Set<string>();
  const out: { id: string; label: string }[] = [];
  const walk = (parent: string | null, depth: number) => {
    for (const g of childrenMap.value.get(parent) ?? []) {
      if (excluded.has(g.id)) continue;
      out.push({
        id: g.id,
        label: `${"— ".repeat(depth)}${g.display_name}${g.kind === "department" ? " (department)" : ""}`,
      });
      walk(g.id, depth + 1);
    }
  };
  walk(null, 0);
  return out;
});

async function saveEditor() {
  if (!editorName.value.trim()) return;
  error.value = "";
  editorSaving.value = true;
  try {
    if (editorMode.value === "create") {
      const created = await createGroup({
        name: editorName.value.trim(),
        kind: editorKind.value,
        parent_id: editorParent.value || null,
      });
      await refreshGroups();
      select(created.id);
    } else if (selectedGroup.value) {
      await updateGroup(selectedGroup.value.id, {
        name: editorName.value.trim(),
        kind: editorKind.value,
        parent_id: editorParent.value || null,
        clear_parent: editorParent.value === "",
      });
      await refreshGroups();
    }
    await refreshCounts();
    showEditor.value = false;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    editorSaving.value = false;
  }
}

async function onDeleteGroup() {
  const sel = selectedGroup.value;
  if (!sel) return;
  if (
    !(await confirm({
      title: "Delete group?",
      message:
        `"${sel.display_name}" is tombstoned and its members lose this group. ` +
        `Child groups move up one level and are not deleted.`,
      confirmText: "Delete",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  try {
    await deleteGroup(sel.id);
    selectedKey.value = "all";
    await refreshGroups();
    await refreshCounts();
    refreshKey.value += 1;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Delete failed";
  }
}

// --- add members to the selected group ------------------------------------

const showAddMembers = ref(false);
const userQuery = ref("");
const userResults = ref<AdminUser[]>([]);
const userSearching = ref(false);
let userTimer: ReturnType<typeof setTimeout> | null = null;

function onUserQuery() {
  if (userTimer) clearTimeout(userTimer);
  userTimer = setTimeout(() => void searchUsers(), 250);
}

async function searchUsers() {
  userSearching.value = true;
  try {
    const res = await listUsers({
      q: userQuery.value.trim() || undefined,
      limit: 10,
      sort: "email",
      dir: "asc",
    });
    userResults.value = res.users;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to search users";
  } finally {
    userSearching.value = false;
  }
}

function openAddMembers() {
  userQuery.value = "";
  userResults.value = [];
  showAddMembers.value = true;
  void searchUsers();
}

async function addMember(user: AdminUser) {
  const group = selectedGroup.value;
  if (!group) return;
  error.value = "";
  try {
    await addGroupMembers(group.id, [user.id]);
    userResults.value = userResults.value.filter((u) => u.id !== user.id);
    await afterMembershipChange();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to add member";
  }
}

function sourceLabel(source: AdminGroup["source"]) {
  return source === "scim" ? "SCIM" : source === "directory" ? "Directory" : "Local";
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Directory"
      description="Users and the organisation tree in one place. Pick a department or group to see its members; manage accounts on the right."
    />

    <p v-if="error" class="field-error">{{ error }}</p>

    <div class="grid gap-4 lg:grid-cols-[300px_minmax(0,1fr)]">
      <!-- tree + pseudo nodes -->
      <section class="surface-card h-fit overflow-hidden">
        <div class="flex items-center justify-between px-4 pb-2 pt-4">
          <p class="type-eyebrow">Organization</p>
          <UiButton
            variant="ghost"
            size="sm"
            class="h-7 px-2"
            title="New group or department"
            @click="openCreate"
          >
            <Plus class="h-4 w-4" />
          </UiButton>
        </div>

        <div class="px-2">
          <div
            class="flex cursor-pointer items-center gap-2 rounded-lg py-1.5 pl-2 pr-2 text-[13px] transition-colors"
            :class="
              selectedKey === 'all'
                ? 'bg-muted font-medium text-foreground'
                : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
            "
            @click="select('all')"
          >
            <UsersRound class="h-3.5 w-3.5 shrink-0" />
            <span class="min-w-0 flex-1 truncate">All users</span>
            <span class="text-[10px] tabular-nums text-muted-foreground/70">{{ allCount }}</span>
          </div>
          <div
            class="flex cursor-pointer items-center gap-2 rounded-lg py-1.5 pl-2 pr-2 text-[13px] transition-colors"
            :class="
              selectedKey === 'ungrouped'
                ? 'bg-muted font-medium text-foreground'
                : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
            "
            @click="select('ungrouped')"
          >
            <UserRoundX class="h-3.5 w-3.5 shrink-0" />
            <span class="min-w-0 flex-1 truncate">Ungrouped</span>
            <span class="text-[10px] tabular-nums text-muted-foreground/70">{{
              ungroupedCount
            }}</span>
          </div>
        </div>

        <div class="mx-4 my-2 border-t border-border/40" />

        <div v-if="loading" class="py-8 text-center text-sm text-muted-foreground">Loading…</div>
        <div
          v-else-if="groups.length === 0"
          class="px-4 py-8 text-center text-[12px] text-muted-foreground"
        >
          No groups yet. Create a department to start the tree.
        </div>
        <ul v-else class="space-y-0.5 px-2 pb-3">
          <li v-for="row in treeRows" :key="row.group.id">
            <div
              class="group flex cursor-pointer items-center gap-1.5 rounded-lg py-1.5 pr-2 text-[13px] transition-colors"
              :class="
                selectedKey === row.group.id
                  ? 'bg-muted font-medium text-foreground'
                  : 'text-muted-foreground hover:bg-muted/50 hover:text-foreground'
              "
              :style="{ paddingLeft: `${8 + row.depth * 14}px` }"
              @click="select(row.group.id)"
            >
              <button
                v-if="row.hasChildren"
                type="button"
                class="rounded p-0.5 text-muted-foreground/70 hover:bg-background hover:text-foreground"
                :aria-expanded="expanded.has(row.group.id)"
                :title="expanded.has(row.group.id) ? 'Collapse' : 'Expand'"
                @click.stop="toggle(row.group.id)"
              >
                <ChevronRight
                  class="h-3 w-3 transition-transform"
                  :class="expanded.has(row.group.id) && 'rotate-90'"
                />
              </button>
              <span v-else class="inline-block w-4" />

              <component
                :is="row.group.kind === 'department' ? Building2 : UsersRound"
                class="h-3.5 w-3.5 shrink-0"
                :class="
                  row.group.kind === 'department'
                    ? 'text-primary/70'
                    : 'text-muted-foreground/70'
                "
              />
              <span class="min-w-0 flex-1 truncate">{{ row.group.display_name }}</span>
              <span
                v-if="row.group.source !== 'local'"
                class="rounded bg-muted px-1 py-0.5 text-[9px] font-semibold uppercase tracking-[0.04em] text-muted-foreground"
              >
                {{ sourceLabel(row.group.source) }}
              </span>
              <span
                v-if="row.group.member_count"
                class="shrink-0 text-[10px] tabular-nums text-muted-foreground/70"
              >
                {{ row.group.member_count }}
              </span>
            </div>
          </li>
        </ul>
      </section>

      <!-- active node + full user table -->
      <div class="min-w-0 space-y-4">
        <section class="surface-card px-5 py-4">
          <div v-if="selectedGroup" class="flex flex-wrap items-start justify-between gap-3">
            <div class="min-w-0">
              <p class="text-[11px] text-muted-foreground">
                <template v-for="(crumb, i) in breadcrumb" :key="crumb.id">
                  <span v-if="i > 0" class="px-1 text-muted-foreground/40">/</span>
                  <span :class="i === breadcrumb.length - 1 ? 'text-foreground' : ''">
                    {{ crumb.display_name }}
                  </span>
                </template>
              </p>
              <div class="mt-1 flex flex-wrap items-center gap-2">
                <h2 class="text-base font-semibold tracking-tight">
                  {{ selectedGroup.display_name }}
                </h2>
                <span
                  class="rounded-md bg-muted px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-muted-foreground"
                >
                  {{ selectedGroup.kind }}
                </span>
                <span
                  v-if="selectedGroup.source !== 'local'"
                  class="rounded-md bg-primary/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.06em] text-primary"
                >
                  {{ sourceLabel(selectedGroup.source) }}-managed
                </span>
              </div>
              <p v-if="selectedGroup.source !== 'local'" class="type-meta mt-2 text-[11px]">
                Name, membership and existence are managed by
                {{ sourceLabel(selectedGroup.source) }}. Moving it in the tree is still allowed.
              </p>
            </div>

            <div class="flex flex-wrap items-center gap-2">
              <label
                v-if="selectedHasChildren"
                class="flex items-center gap-1.5 text-[11px] text-muted-foreground"
                title="Include users of all descendant departments/groups"
              >
                <input v-model="includeDescendants" type="checkbox" class="rounded" />
                Include sub-groups
              </label>
              <UiButton size="sm" variant="secondary" @click="openEdit">Edit</UiButton>
              <UiButton
                v-if="selectedGroup.source === 'local'"
                size="sm"
                @click="openAddMembers"
              >
                <UserPlus class="h-3.5 w-3.5" />
                Add members
              </UiButton>
              <UiButton
                v-if="auth.isAdmin"
                size="sm"
                variant="ghost"
                :disabled="selectedGroup.source !== 'local'"
                :title="
                  selectedGroup.source !== 'local'
                    ? 'Owned by SCIM or a directory source; remove it there'
                    : 'Delete this group'
                "
                @click="onDeleteGroup"
              >
                <Trash2 class="h-3.5 w-3.5 text-destructive" />
                Delete
              </UiButton>
            </div>
          </div>

          <div v-else>
            <h2 class="text-base font-semibold tracking-tight">
              {{ selectedKey === "ungrouped" ? "Ungrouped users" : "All users" }}
            </h2>
            <p class="type-meta mt-1">
              {{
                selectedKey === "ungrouped"
                  ? "Accounts that belong to no group or department."
                  : "Every account, regardless of group membership."
              }}
            </p>
          </div>
        </section>

        <UsersView
          embedded
          :group-id="userIdFilter"
          :include-descendants="includeDescendants"
          :group-name="selectedGroup?.display_name ?? null"
          :group-source="selectedGroup?.source ?? null"
          :refresh-key="refreshKey"
          @membership-changed="afterMembershipChange"
        />
      </div>
    </div>

    <!-- group editor -->
    <Teleport to="body">
      <div
        v-if="showEditor"
        class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      >
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="showEditor = false" />
        <div
          class="relative z-10 my-auto w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-4 text-[15px] font-semibold">
            {{ editorMode === "create" ? "New group or department" : "Edit group" }}
          </h3>
          <form class="space-y-4" @submit.prevent="saveEditor">
            <div>
              <label class="mb-1 block text-[12px] font-medium">Name</label>
              <input v-model="editorName" required maxlength="200" class="field-input" />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Kind</label>
              <select v-model="editorKind" class="field-input">
                <option value="group">Group</option>
                <option value="department">Department</option>
              </select>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Parent</label>
              <select v-model="editorParent" class="field-input">
                <option value="">No parent (root)</option>
                <option v-for="opt in parentOptions" :key="opt.id" :value="opt.id">
                  {{ opt.label }}
                </option>
              </select>
              <p class="type-meta mt-1 text-[11px]">
                Moving a node keeps its members and children. Cycles are refused.
              </p>
            </div>
            <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
              <UiButton type="button" variant="ghost" size="sm" @click="showEditor = false">
                Cancel
              </UiButton>
              <UiButton type="submit" size="sm" :disabled="editorSaving">
                {{ editorSaving ? "Saving…" : "Save" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <!-- add members -->
    <Teleport to="body">
      <div
        v-if="showAddMembers"
        class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      >
        <div
          class="absolute inset-0 bg-black/30 backdrop-blur-sm"
          @click="showAddMembers = false"
        />
        <div
          class="relative z-10 my-auto w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-4 text-[15px] font-semibold">
            Add members to {{ selectedGroup?.display_name }}
          </h3>
          <label class="relative block">
            <Search
              class="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground"
            />
            <input
              v-model="userQuery"
              type="search"
              placeholder="Search by email or name…"
              class="field-input pl-9"
              @input="onUserQuery"
            />
          </label>
          <div class="mt-3 max-h-64 overflow-y-auto rounded-xl border border-border/50">
            <div v-if="userSearching" class="py-8 text-center text-xs text-muted-foreground">
              Searching…
            </div>
            <div
              v-else-if="userResults.length === 0"
              class="py-8 text-center text-xs text-muted-foreground"
            >
              No matching users.
            </div>
            <ul v-else class="divide-y divide-border/40">
              <li
                v-for="user in userResults"
                :key="user.id"
                class="flex items-center gap-3 px-4 py-2.5"
              >
                <div class="min-w-0 flex-1">
                  <p class="truncate text-[13px]">{{ user.display_name }}</p>
                  <p class="truncate text-[11px] text-muted-foreground">{{ user.email }}</p>
                </div>
                <UiButton size="sm" variant="secondary" @click="addMember(user)">Add</UiButton>
              </li>
            </ul>
          </div>
          <div class="mt-5 flex justify-end">
            <UiButton size="sm" @click="showAddMembers = false">Done</UiButton>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
