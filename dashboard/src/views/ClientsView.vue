<script setup lang="ts">
import { AppWindow, Check, Copy, Plus, Trash2 } from "@lucide/vue";
import { computed, onMounted, ref } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import SortableTh from "@/components/ui/SortableTh.vue";
import TablePagination from "@/components/ui/TablePagination.vue";
import UiButton from "@/components/ui/UiButton.vue";
import { useClientPagination } from "@/composables/useClientPagination";
import { useClientSort } from "@/composables/useClientSort";
import {
  createClient,
  deleteClient,
  disableClient,
  enableClient,
  listClients,
  rotateClientSecret,
  updateClient,
  type AdminClient,
} from "@/lib/api";
import { useAuthStore } from "@/stores/auth";
import { confirm } from "@/lib/confirm";

const auth = useAuthStore();

const clients = ref<AdminClient[]>([]);
const loading = ref(true);
const error = ref("");
const searchQuery = ref("");
const showCreate = ref(false);
const creating = ref(false);
const editing = ref<AdminClient | null>(null);
const saving = ref(false);

const formClientId = ref("");
const formRedirects = ref("");
const formPostLogoutRedirects = ref("");
const formScopes = ref("");
const formPkce = ref(true);
const formIpAllowlist = ref(true);
const formAllowedCidrs = ref("");

const editRedirects = ref("");
const editPostLogoutRedirects = ref("");
const editScopes = ref("");
const editPkce = ref(true);
const editIpAllowlist = ref(true);
const editAllowedCidrs = ref("");

const secretDialog = ref<{ clientId: string; secret: string; title: string } | null>(null);
const rotatingId = ref<string | null>(null);
const copiedField = ref<"id" | "secret" | "both" | null>(null);
let copiedTimer: ReturnType<typeof setTimeout> | null = null;

const filtered = computed(() => {
  const q = searchQuery.value.trim().toLowerCase();
  if (!q) return clients.value;
  return clients.value.filter((c) =>
    [c.client_id, c.enabled ? "enabled" : "disabled", ...c.redirect_uris]
      .join(" ")
      .toLowerCase()
      .includes(q),
  );
});

const { sorted, toggleSort, sortIndicator } = useClientSort(filtered, {
  initialKey: "created_at",
  initialDir: "desc",
  getValue: (row, key) => {
    switch (key) {
      case "client_id":
        return row.client_id;
      case "pkce_required":
        return row.pkce_required ? 1 : 0;
      case "enabled":
        return row.enabled ? 1 : 0;
      case "created_at":
        return row.created_at;
      default:
        return "";
    }
  },
});

const { page, pageSize, pageCount, total, pageItems, rangeLabel } =
  useClientPagination(sorted);

async function refresh() {
  clients.value = await listClients();
}

onMounted(async () => {
  try {
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load clients";
  } finally {
    loading.value = false;
  }
});

function parseLines(raw: string) {
  return raw
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function openCreate() {
  formClientId.value = "";
  formRedirects.value = "";
  formPostLogoutRedirects.value = "";
  formScopes.value = "";
  formPkce.value = true;
  formIpAllowlist.value = true;
  formAllowedCidrs.value = "";
  showCreate.value = true;
}

function openEdit(c: AdminClient) {
  editing.value = c;
  editRedirects.value = c.redirect_uris.join("\n");
  editPostLogoutRedirects.value = (c.post_logout_redirect_uris || []).join("\n");
  editScopes.value = (c.scopes || []).join("\n");
  editPkce.value = c.pkce_required;
  editIpAllowlist.value = c.ip_allowlist_enabled;
  editAllowedCidrs.value = (c.allowed_cidrs || []).join("\n");
}

async function onCreate() {
  error.value = "";
  creating.value = true;
  try {
    const redirect_uris = parseLines(formRedirects.value);
    const post_logout_redirect_uris = parseLines(formPostLogoutRedirects.value);
    const scopes = parseLines(formScopes.value);
    const allowed_cidrs = parseLines(formAllowedCidrs.value);
    const res = await createClient({
      client_id: formClientId.value,
      redirect_uris,
      post_logout_redirect_uris,
      pkce_required: formPkce.value,
      scopes: scopes.length ? scopes : undefined,
      ip_allowlist_enabled: formIpAllowlist.value,
      allowed_cidrs,
    });
    showCreate.value = false;
    secretDialog.value = {
      clientId: res.client.client_id,
      secret: res.client_secret,
      title: "Client registered",
    };
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
    await updateClient(editing.value.id, {
      redirect_uris: parseLines(editRedirects.value),
      post_logout_redirect_uris: parseLines(editPostLogoutRedirects.value),
      pkce_required: editPkce.value,
      scopes: parseLines(editScopes.value),
      ip_allowlist_enabled: editIpAllowlist.value,
      allowed_cidrs: parseLines(editAllowedCidrs.value),
    });
    editing.value = null;
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Update failed";
  } finally {
    saving.value = false;
  }
}

async function onToggle(c: AdminClient) {
  error.value = "";
  try {
    if (c.enabled) await disableClient(c.id);
    else await enableClient(c.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Update failed";
  }
}

async function onRotate(c: AdminClient) {
  if (
    !(await confirm({
      title: "Rotate client secret?",
      message: `"${c.client_id}" gets a new secret and the current one stops working immediately. Update every service using it.`,
      confirmText: "Rotate",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  rotatingId.value = c.id;
  try {
    const res = await rotateClientSecret(c.id);
    secretDialog.value = {
      clientId: res.client.client_id,
      secret: res.client_secret,
      title: "Secret rotated",
    };
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Rotate failed";
  } finally {
    rotatingId.value = null;
  }
}

async function onDelete(c: AdminClient) {
  if (
    !(await confirm({
      title: "Delete client?",
      message: `"${c.client_id}" will be permanently removed. This cannot be undone.`,
      confirmText: "Delete",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  try {
    await deleteClient(c.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Delete failed";
  }
}

async function copyText(text: string, field: "id" | "secret" | "both") {
  try {
    await navigator.clipboard.writeText(text);
    copiedField.value = field;
    if (copiedTimer) clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      copiedField.value = null;
    }, 1500);
  } catch {
    /* ignore */
  }
}

function copyBoth() {
  if (!secretDialog.value) return;
  const { clientId, secret } = secretDialog.value;
  void copyText(`client_id=${clientId}\nclient_secret=${secret}`, "both");
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Clients"
      description="Register OIDC confidential clients (Authorization Code + PKCE). Secrets are shown only once."
    >
      <template #actions>
        <UiButton size="sm" @click="openCreate">
          <Plus class="h-4 w-4" />
          Register Client
        </UiButton>
      </template>
    </PageHeader>

    <p v-if="error" class="field-error">{{ error }}</p>

    <div v-if="loading" class="py-12 text-center text-sm text-muted-foreground">Loading…</div>
    <div v-else class="overflow-hidden rounded-xl border border-border/50 bg-card shadow-sm">
      <div
        v-if="clients.length === 0"
        class="flex flex-col items-center justify-center py-16 text-muted-foreground"
      >
        <AppWindow class="mb-3 h-10 w-10 text-muted-foreground/20" />
        <p class="text-sm">No clients yet</p>
      </div>
      <template v-else>
        <div class="border-b border-border/30 px-5 py-3">
          <input
            v-model="searchQuery"
            type="search"
            placeholder="Search clients…"
            class="w-full max-w-xs rounded-lg border border-border/60 bg-background px-3 py-1.5 text-xs outline-none transition-colors focus:border-primary/50 focus:ring-1 focus:ring-primary/10"
          />
        </div>

        <div
          v-if="filtered.length === 0"
          class="px-5 py-12 text-center text-sm text-muted-foreground"
        >
          No clients match “{{ searchQuery }}”
        </div>
        <template v-else>
          <div class="overflow-x-auto">
            <table class="w-full text-[13px]">
              <thead>
                <tr class="border-b border-border/30 bg-muted/10">
                  <SortableTh
                    label="Client ID"
                    column="client_id"
                    :indicator="sortIndicator('client_id')"
                    @toggle="toggleSort"
                  />
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground"
                  >
                    Redirect URIs
                  </th>
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground"
                  >
                    Scopes
                  </th>
                  <SortableTh
                    label="PKCE"
                    column="pkce_required"
                    :indicator="sortIndicator('pkce_required')"
                    @toggle="toggleSort"
                  />
                  <SortableTh
                    label="Status"
                    column="enabled"
                    :indicator="sortIndicator('enabled')"
                    @toggle="toggleSort"
                  />
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground"
                  >
                    Source IP
                  </th>
                  <th
                    class="w-52 px-5 py-2.5 text-right text-[11px] font-semibold uppercase tracking-[0.06em] text-muted-foreground"
                  >
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody class="divide-y divide-border/20">
                <tr
                  v-for="c in pageItems"
                  :key="c.id"
                  :class="
                    c.enabled
                      ? 'hover:bg-muted/5'
                      : 'bg-destructive/[0.04] text-muted-foreground hover:bg-destructive/[0.07]'
                  "
                >
                  <td
                    class="px-5 py-3 font-mono text-xs font-semibold"
                    :class="!c.enabled && 'line-through decoration-destructive/40'"
                  >
                    {{ c.client_id }}
                    <span
                      v-if="!c.enabled"
                      class="ml-2 align-middle text-[10px] font-semibold uppercase tracking-[0.06em] text-destructive"
                    >
                      Disabled
                    </span>
                  </td>
                  <td class="max-w-md px-5 py-3 text-xs text-muted-foreground">
                    <div class="space-y-0.5">
                      <p v-for="uri in c.redirect_uris" :key="uri" class="truncate font-mono">
                        {{ uri }}
                      </p>
                      <template v-if="(c.post_logout_redirect_uris || []).length">
                        <p class="pt-1 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground/60">
                          Logout
                        </p>
                        <p
                          v-for="uri in c.post_logout_redirect_uris"
                          :key="'lo-' + uri"
                          class="truncate font-mono"
                        >
                          {{ uri }}
                        </p>
                      </template>
                    </div>
                  </td>
                  <td class="max-w-xs px-5 py-3 text-xs text-muted-foreground">
                    <span class="font-mono text-[11px]">{{ (c.scopes || []).join(", ") }}</span>
                  </td>
                  <td class="px-5 py-3 text-xs">{{ c.pkce_required ? "required" : "optional" }}</td>
                  <td class="px-5 py-3 text-xs">
                    <span
                      :class="
                        c.enabled
                          ? 'text-foreground'
                          : 'inline-flex items-center rounded-md bg-destructive/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-destructive'
                      "
                    >
                      {{ c.enabled ? "enabled" : "disabled" }}
                    </span>
                  </td>
                  <td class="px-5 py-3 text-xs">
                    <template v-if="c.ip_allowlist_enabled">
                      <span class="font-medium">Allowlist</span>
                      <span class="mt-0.5 block font-mono text-[11px] text-muted-foreground">
                        {{ (c.allowed_cidrs || []).join(", ") || "(empty)" }}
                      </span>
                    </template>
                    <span v-else class="text-muted-foreground">Unrestricted</span>
                  </td>
                  <td class="space-x-1 whitespace-nowrap px-5 py-3 text-right">
                    <UiButton variant="ghost" size="sm" @click="openEdit(c)">Edit</UiButton>
                    <UiButton
                      variant="ghost"
                      size="sm"
                      :disabled="rotatingId === c.id"
                      @click="onRotate(c)"
                    >
                      Rotate
                    </UiButton>
                    <UiButton variant="ghost" size="sm" @click="onToggle(c)">
                      {{ c.enabled ? "Disable" : "Enable" }}
                    </UiButton>
                    <UiButton
                      v-if="auth.canDeleteClients"
                      variant="ghost"
                      size="sm"
                      @click="onDelete(c)"
                    >
                      <Trash2 class="h-3.5 w-3.5 text-destructive" />
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
      <div v-if="showCreate" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="showCreate = false" />
        <div
          class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-5 text-[15px] font-semibold">Register Client</h3>
          <form class="space-y-4" @submit.prevent="onCreate">
            <div>
              <label class="mb-1 block text-[12px] font-medium">
                Client ID <span class="text-red-500">*</span>
              </label>
              <input
                v-model="formClientId"
                required
                pattern="[a-zA-Z0-9_-]+"
                placeholder="my-app"
                class="field-input font-mono text-sm"
              />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">
                Redirect URIs <span class="text-red-500">*</span>
              </label>
              <textarea
                v-model="formRedirects"
                required
                rows="3"
                placeholder="http://localhost:3000/auth/callback"
                class="field-input min-h-[5.5rem] resize-y py-2 font-mono text-xs"
              />
              <p class="type-meta mt-1">One URI per line</p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">
                Post-logout Redirect URIs
              </label>
              <textarea
                v-model="formPostLogoutRedirects"
                rows="2"
                placeholder="http://localhost:3000/"
                class="field-input min-h-[3.5rem] resize-y py-2 font-mono text-xs"
              />
              <p class="type-meta mt-1">One URI per line (RP-initiated logout)</p>
            </div>
            <label class="flex items-center gap-2 text-sm">
              <input v-model="formPkce" type="checkbox" class="rounded" />
              Require PKCE (S256)
            </label>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Scopes</label>
              <textarea
                v-model="formScopes"
                rows="2"
                placeholder="openid&#10;profile&#10;email"
                class="field-input min-h-[3.5rem] resize-y py-2 font-mono text-xs"
              />
              <p class="type-meta mt-1">One per line (defaults to openid profile email)</p>
            </div>
            <label class="flex items-start gap-2 text-sm">
              <input v-model="formIpAllowlist" type="checkbox" class="mt-0.5 rounded" />
              <span>
                <span class="block text-[12px] font-medium">Restrict by source IP</span>
                <span class="type-meta">Default on. Only listed IPs/CIDRs may call authorize/token.</span>
              </span>
            </label>
            <div v-if="formIpAllowlist">
              <label class="mb-1 block text-[12px] font-medium">
                Allowed IPs / CIDRs <span class="text-red-500">*</span>
              </label>
              <textarea
                v-model="formAllowedCidrs"
                required
                rows="3"
                placeholder="10.0.0.0/8&#10;203.0.113.10"
                class="field-input min-h-[5rem] resize-y py-2 font-mono text-xs"
              />
            </div>
            <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
              <UiButton type="button" variant="ghost" size="sm" @click="showCreate = false">
                Cancel
              </UiButton>
              <UiButton type="submit" size="sm" :disabled="creating">
                {{ creating ? "Registering…" : "Register" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="editing" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="editing = null" />
        <div
          class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-5 text-[15px] font-semibold">Edit {{ editing.client_id }}</h3>
          <form class="space-y-4" @submit.prevent="onSaveEdit">
            <div>
              <label class="mb-1 block text-[12px] font-medium">Redirect URIs</label>
              <textarea
                v-model="editRedirects"
                required
                rows="3"
                class="field-input min-h-[5.5rem] resize-y py-2 font-mono text-xs"
              />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">
                Post-logout Redirect URIs
              </label>
              <textarea
                v-model="editPostLogoutRedirects"
                rows="2"
                placeholder="http://localhost:3000/"
                class="field-input min-h-[3.5rem] resize-y py-2 font-mono text-xs"
              />
              <p class="type-meta mt-1">One URI per line (RP-initiated logout)</p>
            </div>
            <label class="flex items-center gap-2 text-sm">
              <input v-model="editPkce" type="checkbox" class="rounded" />
              Require PKCE (S256)
            </label>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Scopes</label>
              <textarea
                v-model="editScopes"
                rows="2"
                placeholder="openid&#10;profile&#10;email"
                class="field-input min-h-[3.5rem] resize-y py-2 font-mono text-xs"
              />
              <p class="type-meta mt-1">One per line. Must include openid.</p>
            </div>
            <div class="rounded-lg bg-muted/50 px-3 py-2 text-xs text-muted-foreground">
              <span class="font-medium text-foreground">Grant types:</span>
              <span class="font-mono">{{ (editing.grant_types || []).join(", ") }}</span>
            </div>
            <label class="flex items-start gap-2 text-sm">
              <input v-model="editIpAllowlist" type="checkbox" class="mt-0.5 rounded" />
              <span>
                <span class="block text-[12px] font-medium">Restrict by source IP</span>
                <span class="type-meta">Turn off to allow any source IP for this client.</span>
              </span>
            </label>
            <div v-if="editIpAllowlist">
              <label class="mb-1 block text-[12px] font-medium">Allowed IPs / CIDRs</label>
              <textarea
                v-model="editAllowedCidrs"
                required
                rows="3"
                placeholder="10.0.0.0/8"
                class="field-input min-h-[5rem] resize-y py-2 font-mono text-xs"
              />
            </div>
            <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
              <UiButton type="button" variant="ghost" size="sm" @click="editing = null">Cancel</UiButton>
              <UiButton type="submit" size="sm" :disabled="saving">
                {{ saving ? "Saving…" : "Save" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <Teleport to="body">
      <div v-if="secretDialog" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="secretDialog = null" />
        <div
          class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-2 text-[15px] font-semibold">{{ secretDialog.title }}</h3>
          <p class="type-meta mb-4">
            Copy the client secret now — it will not be shown again.
          </p>
          <div class="space-y-3">
            <div>
              <p class="type-label mb-1">Client ID</p>
              <div class="flex items-start gap-2 rounded-lg bg-muted px-3 py-2">
                <p class="min-w-0 flex-1 break-all font-mono text-xs">
                  {{ secretDialog.clientId }}
                </p>
                <UiButton
                  type="button"
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 shrink-0"
                  :title="copiedField === 'id' ? 'Copied' : 'Copy client ID'"
                  @click="copyText(secretDialog.clientId, 'id')"
                >
                  <Check v-if="copiedField === 'id'" class="h-3.5 w-3.5" />
                  <Copy v-else class="h-3.5 w-3.5" />
                </UiButton>
              </div>
            </div>
            <div>
              <p class="type-label mb-1">Client Secret</p>
              <div class="flex items-start gap-2 rounded-lg bg-muted px-3 py-2">
                <p class="min-w-0 flex-1 break-all font-mono text-xs">
                  {{ secretDialog.secret }}
                </p>
                <UiButton
                  type="button"
                  variant="ghost"
                  size="icon"
                  class="h-7 w-7 shrink-0"
                  :title="copiedField === 'secret' ? 'Copied' : 'Copy client secret'"
                  @click="copyText(secretDialog.secret, 'secret')"
                >
                  <Check v-if="copiedField === 'secret'" class="h-3.5 w-3.5" />
                  <Copy v-else class="h-3.5 w-3.5" />
                </UiButton>
              </div>
            </div>
          </div>
          <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
            <UiButton type="button" variant="ghost" size="sm" @click="copyBoth">
              <Check v-if="copiedField === 'both'" class="h-3.5 w-3.5" />
              <Copy v-else class="h-3.5 w-3.5" />
              {{ copiedField === "both" ? "Copied" : "Copy both" }}
            </UiButton>
            <UiButton type="button" size="sm" @click="secretDialog = null">Done</UiButton>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
