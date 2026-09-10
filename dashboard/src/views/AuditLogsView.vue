<script setup lang="ts">
import { Download, ScrollText } from "@lucide/vue";
import { computed, onMounted, ref, watch } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import SortableTh from "@/components/ui/SortableTh.vue";
import TablePagination from "@/components/ui/TablePagination.vue";
import UiButton from "@/components/ui/UiButton.vue";
import {
  fetchAuditLogs,
  fetchAuditLogFacets,
  auditLogsExportUrl,
  type AuditLogItem,
  type AuditLogFacets,
} from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

const auth = useAuthStore();
const loading = ref(true);
const error = ref("");
const items = ref<AuditLogItem[]>([]);
const total = ref(0);
const page = ref(1);
const pageSize = ref(20);
const searchQuery = ref("");
const actionFilter = ref("");
const clientFilter = ref("");
const browserFilter = ref("");
const osFilter = ref("");
const facets = ref<AuditLogFacets | null>(null);
const sortKey = ref("created_at");
const sortDir = ref<"asc" | "desc">("desc");

const pageCount = computed(() => Math.max(1, Math.ceil(total.value / pageSize.value) || 1));
const rangeLabel = computed(() => {
  if (total.value === 0) return "0 of 0";
  const start = (page.value - 1) * pageSize.value + 1;
  const end = Math.min(page.value * pageSize.value, total.value);
  return `${start}–${end} of ${total.value}`;
});

const actionOptions = computed(() => {
  const base = [
    "",
    "auth.login",
    "auth.password_change",
    "me.profile_update",
    "user.create",
    "user.update",
    "user.disable",
    "user.enable",
    "client.create",
    "client.disable",
    "client.enable",
    "client.rotate_secret",
    "mfa.verify",
    "mfa.enroll",
    "mfa.recovery_use",
    "mfa.recovery_regen",
    "mfa.rebind",
  ];
  if (auth.isAdmin) {
    return [...base, "user.delete", "client.delete", "mfa.reset", "settings.mfa_update"];
  }
  return base;
});

async function load() {
  loading.value = true;
  error.value = "";
  try {
    const res = await fetchAuditLogs({
      q: searchQuery.value.trim() || undefined,
      action: actionFilter.value || undefined,
      client_id: clientFilter.value || undefined,
      browser: browserFilter.value || undefined,
      os: osFilter.value || undefined,
      page: page.value,
      page_size: pageSize.value,
      sort: sortKey.value,
      dir: sortDir.value,
    });
    items.value = res.items;
    total.value = res.total;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load audit logs";
  } finally {
    loading.value = false;
  }
}

function toggleSort(column: string) {
  if (sortKey.value === column) {
    sortDir.value = sortDir.value === "asc" ? "desc" : "asc";
  } else {
    sortKey.value = column;
    sortDir.value = column === "created_at" ? "desc" : "asc";
  }
  void load();
}

function sortIndicator(column: string): "" | "asc" | "desc" {
  if (sortKey.value !== column) return "";
  return sortDir.value;
}

watch([page, pageSize], () => {
  void load();
});

watch([searchQuery, actionFilter, clientFilter, browserFilter, osFilter], () => {
  page.value = 1;
  void load();
});

onMounted(() => {
  void load();
  void fetchAuditLogFacets()
    .then((f) => (facets.value = f))
    .catch(() => {
      // Non-fatal: filter dropdowns just stay empty.
    });
});

function formatTime(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

const detailRow = ref<AuditLogItem | null>(null);

function openDetail(row: AuditLogItem) {
  detailRow.value = row;
}

function prettyDetail(detail: Record<string, unknown>): string {
  try {
    return JSON.stringify(detail, null, 2);
  } catch {
    return String(detail);
  }
}

function deviceLabel(row: AuditLogItem) {
  return [row.browser, row.os].filter(Boolean).join(" / ") || "—";
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Audit logs"
      :description="
        auth.isAdmin
          ? 'Full operational history. Audit records cannot be deleted.'
          : 'Operational history for user and client management (delete events hidden).'
      "
    />

    <p v-if="error" class="field-error">{{ error }}</p>

    <div class="overflow-hidden rounded-xl border border-border/50 bg-card shadow-sm">
      <div class="flex flex-wrap items-center gap-3 border-b border-border/30 px-5 py-3">
        <input
          v-model="searchQuery"
          type="search"
          placeholder="Search actor / IP / action / resource…"
          class="w-full max-w-xs rounded-lg border border-border/60 bg-background px-3 py-1.5 text-xs outline-none transition-colors focus:border-primary/50 focus:ring-1 focus:ring-primary/10"
        />
        <select
          v-model="actionFilter"
          class="h-8 rounded-lg border border-border/60 bg-background px-2 text-xs outline-none"
        >
          <option v-for="a in actionOptions" :key="a || 'all'" :value="a">
            {{ a || "All actions" }}
          </option>
        </select>
        <select
          v-model="clientFilter"
          class="h-8 rounded-lg border border-border/60 bg-background px-2 text-xs outline-none"
        >
          <option value="">All apps</option>
          <option v-for="c in facets?.clients ?? []" :key="c.client_id" :value="c.client_id">
            {{ c.client_id }}{{ c.enabled ? "" : " (disabled)" }}
          </option>
        </select>
        <select
          v-model="browserFilter"
          class="h-8 rounded-lg border border-border/60 bg-background px-2 text-xs outline-none"
        >
          <option value="">All browsers</option>
          <option v-for="b in facets?.browsers ?? []" :key="b" :value="b">{{ b }}</option>
        </select>
        <select
          v-model="osFilter"
          class="h-8 rounded-lg border border-border/60 bg-background px-2 text-xs outline-none"
        >
          <option value="">All OSes</option>
          <option v-for="o in facets?.oses ?? []" :key="o" :value="o">{{ o }}</option>
        </select>
        <a
          :href="
            auditLogsExportUrl({
              q: searchQuery.trim() || undefined,
              action: actionFilter || undefined,
              client_id: clientFilter || undefined,
              browser: browserFilter || undefined,
              os: osFilter || undefined,
            })
          "
          download
          class="ml-auto inline-flex h-8 items-center gap-1.5 rounded-lg border border-border/60 bg-background px-3 text-xs font-medium transition-colors hover:bg-muted"
        >
          <Download class="h-3.5 w-3.5" />
          Export CSV
        </a>
      </div>

      <div v-if="loading" class="py-12 text-center text-sm text-muted-foreground">Loading…</div>
      <div
        v-else-if="items.length === 0"
        class="flex flex-col items-center justify-center py-16 text-muted-foreground"
      >
        <ScrollText class="mb-3 h-10 w-10 text-muted-foreground/20" />
        <p class="text-sm">No audit events</p>
      </div>
      <template v-else>
        <div class="overflow-x-auto">
          <table class="w-full text-[13px]">
            <thead>
              <tr class="border-b border-border/30 bg-muted/10">
                <SortableTh
                  label="Time"
                  column="created_at"
                  :indicator="sortIndicator('created_at')"
                  @toggle="toggleSort"
                />
                <SortableTh
                  label="Actor"
                  column="actor_email"
                  :indicator="sortIndicator('actor_email')"
                  @toggle="toggleSort"
                />
                <SortableTh
                  label="Login IP"
                  column="ip"
                  :indicator="sortIndicator('ip')"
                  @toggle="toggleSort"
                />
                <th class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                  App
                </th>
                <th class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground">
                  Device
                </th>
                <SortableTh
                  label="Action"
                  column="action"
                  :indicator="sortIndicator('action')"
                  @toggle="toggleSort"
                />
                <SortableTh
                  label="Resource"
                  column="resource_type"
                  :indicator="sortIndicator('resource_type')"
                  @toggle="toggleSort"
                />
                <SortableTh
                  label="Resource ID"
                  column="resource_id"
                  :indicator="sortIndicator('resource_id')"
                  @toggle="toggleSort"
                />
              </tr>
            </thead>
            <tbody class="divide-y divide-border/20">
              <tr
                v-for="row in items"
                :key="row.id"
                class="cursor-pointer hover:bg-muted/5"
                @click="openDetail(row)"
              >
                <td class="whitespace-nowrap px-5 py-3 text-xs text-muted-foreground">
                  {{ formatTime(row.created_at) }}
                </td>
                <td class="px-5 py-3 text-xs">
                  <div>{{ row.actor_email || "—" }}</div>
                  <div class="text-muted-foreground">{{ row.actor_role || "" }}</div>
                </td>
                <td class="px-5 py-3 font-mono text-xs">
                  <span
                    :class="
                      row.ip
                        ? 'text-foreground'
                        : 'text-muted-foreground'
                    "
                  >
                    {{ row.ip || "—" }}
                  </span>
                </td>
                <td class="px-5 py-3 text-xs">
                  <span v-if="row.client_id" class="rounded bg-muted/60 px-1.5 py-0.5 font-mono">
                    {{ row.client_id }}
                  </span>
                  <span v-else class="text-muted-foreground">—</span>
                </td>
                <td class="px-5 py-3 text-xs text-muted-foreground">
                  {{ deviceLabel(row) }}
                </td>
                <td class="px-5 py-3 font-mono text-xs">{{ row.action }}</td>
                <td class="px-5 py-3 text-xs">{{ row.resource_type }}</td>
                <td class="max-w-xs truncate px-5 py-3 font-mono text-xs text-muted-foreground">
                  {{ row.resource_id || "—" }}
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
      <div v-if="detailRow" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="detailRow = null" />
        <div
          class="relative z-10 mx-4 max-h-[85vh] w-full max-w-lg overflow-y-auto rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-4 text-[15px] font-semibold">Audit event detail</h3>

          <dl class="space-y-3 text-sm">
            <div>
              <dt class="type-meta text-[11px] uppercase tracking-wide">Time</dt>
              <dd class="mt-0.5">{{ formatTime(detailRow.created_at) }}</dd>
            </div>
            <div>
              <dt class="type-meta text-[11px] uppercase tracking-wide">Action</dt>
              <dd class="mt-0.5 font-mono text-xs">{{ detailRow.action }}</dd>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <dt class="type-meta text-[11px] uppercase tracking-wide">Actor</dt>
                <dd class="mt-0.5">{{ detailRow.actor_email || "—" }}</dd>
                <dd class="text-xs text-muted-foreground">{{ detailRow.actor_role || "" }}</dd>
              </div>
              <div>
                <dt class="type-meta text-[11px] uppercase tracking-wide">Resource</dt>
                <dd class="mt-0.5">{{ detailRow.resource_type }}</dd>
                <dd class="font-mono text-xs text-muted-foreground">{{ detailRow.resource_id || "—" }}</dd>
              </div>
            </div>
            <div class="grid grid-cols-2 gap-3">
              <div>
                <dt class="type-meta text-[11px] uppercase tracking-wide">IP</dt>
                <dd class="mt-0.5 font-mono text-xs">{{ detailRow.ip || "—" }}</dd>
              </div>
              <div>
                <dt class="type-meta text-[11px] uppercase tracking-wide">Device</dt>
                <dd class="mt-0.5 text-xs">{{ deviceLabel(detailRow) }}</dd>
              </div>
            </div>
            <div>
              <dt class="type-meta text-[11px] uppercase tracking-wide">App</dt>
              <dd class="mt-0.5">
                <span
                  v-if="detailRow.client_id"
                  class="rounded bg-muted/60 px-1.5 py-0.5 font-mono text-xs"
                >
                  {{ detailRow.client_id }}
                </span>
                <span v-else class="text-xs text-muted-foreground">—</span>
              </dd>
            </div>
            <div>
              <dt class="type-meta text-[11px] uppercase tracking-wide">User agent</dt>
              <dd class="mt-0.5 break-all font-mono text-[11px] text-muted-foreground">
                {{ detailRow.user_agent || "—" }}
              </dd>
            </div>
            <div>
              <dt class="type-meta text-[11px] uppercase tracking-wide">Detail</dt>
              <dd class="mt-0.5">
                <pre
                  class="max-h-48 overflow-auto rounded-lg border border-border/50 bg-muted/40 p-3 font-mono text-xs leading-5"
                  >{{ prettyDetail(detailRow.detail) }}</pre
                >
              </dd>
            </div>
          </dl>

          <div class="mt-5 flex justify-end border-t border-border/30 pt-4">
            <UiButton type="button" size="sm" @click="detailRow = null">Close</UiButton>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
