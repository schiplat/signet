<script setup lang="ts">
import { AppWindow, KeyRound, Plus, Power, PowerOff, Trash2 } from "@lucide/vue";
import { computed, onMounted, ref } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import ClientSecretDialog from "@/components/ui/ClientSecretDialog.vue";
import RowActionsMenu, { type RowActionItem } from "@/components/ui/RowActionsMenu.vue";
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
const formGrants = ref<string[]>(["authorization_code", "refresh_token"]);
const formExtraClaims = ref("");
const formBackchannel = ref("");
const formIpAllowlist = ref(false);
const formAdvancedOpen = ref(false);
const formAllowedCidrs = ref("");

const editRedirects = ref("");
const editPostLogoutRedirects = ref("");
const editScopes = ref("");
const editGrants = ref<string[]>([]);
const editExtraClaims = ref("");
const editBackchannel = ref("");
const editIpAllowlist = ref(true);
const editAllowedCidrs = ref("");

const secretDialog = ref<{
  clientId: string;
  secret: string;
  title: string;
  client: Pick<AdminClient, "redirect_uris" | "post_logout_redirect_uris" | "scopes">;
} | null>(null);
const rotatingId = ref<string | null>(null);

// Row actions live in the shared menu component: the table wrapper is an
// overflow container, so its teleported menu is the only placement that is
// not clipped.
function rowActions(c: AdminClient): RowActionItem[] {
  const items: RowActionItem[] = [
    {
      key: "rotate",
      label: rotatingId.value === c.id ? "Rotating…" : "Rotate secret",
      icon: KeyRound,
      disabled: rotatingId.value === c.id,
    },
    {
      key: "toggle",
      label: c.enabled ? "Disable" : "Enable",
      icon: c.enabled ? PowerOff : Power,
    },
  ];
  if (auth.canDeleteClients) {
    items.push({ key: "delete", label: "Delete", icon: Trash2, danger: true, separator: true });
  }
  return items;
}

function onRowAction(c: AdminClient, key: string) {
  if (key === "rotate") void onRotate(c);
  else if (key === "toggle") void onToggle(c);
  else if (key === "delete") void onDelete(c);
}

// Test drive builds an absolute authorize URL against the real issuer; the
// public discovery document is the one source of truth (an operator may have
// set a SIGNET_PUBLIC_BASE_URL different from the dashboard origin).
const issuer = ref("");

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
  // Best-effort: the test-drive authorize URL needs the issuer; discovery is
  // public.
  try {
    const res = await fetch("/.well-known/openid-configuration");
    const doc = await res.json();
    if (typeof doc.issuer === "string") issuer.value = doc.issuer;
  } catch {
    /* fall back to the dashboard origin */
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
  formGrants.value = ["authorization_code", "refresh_token"];
  formExtraClaims.value = "";
  formBackchannel.value = "";
  formIpAllowlist.value = false;
  formAllowedCidrs.value = "";
  formAdvancedOpen.value = false;
  showCreate.value = true;
}

function openEdit(c: AdminClient) {
  editing.value = c;
  editRedirects.value = c.redirect_uris.join("\n");
  editPostLogoutRedirects.value = (c.post_logout_redirect_uris || []).join("\n");
  editScopes.value = (c.scopes || []).join("\n");
  editGrants.value = c.grant_types || [];
  editExtraClaims.value = c.extra_claims
    ? JSON.stringify(c.extra_claims, null, 2)
    : "";
  editBackchannel.value = c.backchannel_logout_uri || "";
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
    let extra: Record<string, unknown> | null = null;
    if (formExtraClaims.value.trim()) {
      try {
        extra = JSON.parse(formExtraClaims.value);
      } catch {
        error.value = "Extra claims must be valid JSON";
        creating.value = false;
        return;
      }
    }
    const res = await createClient({
      client_id: formClientId.value,
      redirect_uris,
      post_logout_redirect_uris,
      grant_types: formGrants.value,
      extra_claims: extra,
      backchannel_logout_uri: formBackchannel.value.trim() || null,
      scopes: scopes.length ? scopes : undefined,
      ip_allowlist_enabled: formIpAllowlist.value,
      allowed_cidrs,
    });
    showCreate.value = false;
    secretDialog.value = {
      clientId: res.client.client_id,
      secret: res.client_secret,
      title: "Client registered",
      client: res.client,
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
    let extra: Record<string, unknown> | null = null;
    if (editExtraClaims.value.trim()) {
      try {
        extra = JSON.parse(editExtraClaims.value);
      } catch {
        error.value = "Extra claims must be valid JSON";
        saving.value = false;
        return;
      }
    }
    await updateClient(editing.value.id, {
      redirect_uris: parseLines(editRedirects.value),
      post_logout_redirect_uris: parseLines(editPostLogoutRedirects.value),
      grant_types: editGrants.value,
      extra_claims: extra,
      backchannel_logout_uri: editBackchannel.value.trim() || null,
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
      client: res.client,
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

const B64URL = (buf: ArrayBuffer | Uint8Array) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

/// Full authorize round trip against this client, in a new tab: PKCE pair and
/// state minted here, redirect to the always-permitted test-callback URI. The
/// result page shows what passed (auth/consent/redirect/scope) and what still
/// needs a real integration (token endpoint + secret).
async function onTestDrive(c: AdminClient) {
  const verifier = B64URL(crypto.getRandomValues(new Uint8Array(32)));
  const challenge = B64URL(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  );
  const state = B64URL(crypto.getRandomValues(new Uint8Array(16)));
  const base = (issuer.value || window.location.origin).replace(/\/$/, "");
  const scope = ["openid", ...(c.scopes || [])]
    .filter((s, i, a) => a.indexOf(s) === i)
    .join(" ");
  const params = new URLSearchParams({
    response_type: "code",
    client_id: c.client_id,
    redirect_uri: `${base}/oauth/test-callback/${encodeURIComponent(c.client_id)}`,
    scope,
    state,
    nonce: crypto.randomUUID(),
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  window.open(`${base}/oauth/authorize?${params}`, "_blank", "noopener");
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
    <div v-else class="surface-card overflow-hidden">
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
                <tr class="border-b border-border/50">
                  <SortableTh
                    label="Client ID"
                    column="client_id"
                    :indicator="sortIndicator('client_id')"
                    @toggle="toggleSort"
                  />
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80"
                  >
                    Name
                  </th>
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80"
                  >
                    Owner
                  </th>
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80"
                  >
                    Redirect URIs
                  </th>
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80"
                  >
                    Scopes
                  </th>
                  <SortableTh
                    label="Status"
                    column="enabled"
                    :indicator="sortIndicator('enabled')"
                    @toggle="toggleSort"
                  />
                  <th
                    class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80"
                  >
                    Source IP
                  </th>
                  <th
                    class="px-5 py-2.5 text-right text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80"
                  >
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                <tr
                  v-for="c in pageItems"
                  :key="c.id"
                  :class="
                    c.enabled
                      ? 'border-b border-border/40 last:border-0 hover:bg-muted/5'
                      : 'border-b border-border/40 bg-destructive/[0.04] text-muted-foreground last:border-0 hover:bg-destructive/[0.07]'
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
                  <td class="px-5 py-3 text-xs">
                    <span v-if="c.client_name" class="font-medium">{{ c.client_name }}</span>
                    <span v-else class="text-muted-foreground">—</span>
                  </td>
                  <td class="px-5 py-3 text-xs">
                    <span v-if="c.owner_email" class="break-all">{{ c.owner_email }}</span>
                    <span v-else class="text-muted-foreground" title="Created by an administrator">
                      —
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
                  <td class="whitespace-nowrap px-5 py-3 text-right align-middle">
                    <div class="flex items-center justify-end gap-1">
                    <UiButton
                      v-if="c.enabled"
                      variant="ghost"
                      size="sm"
                      class="text-[13px] font-normal"
                      :title="'Run a full authorize round trip against this client in a new tab'"
                      @click="onTestDrive(c)"
                    >
                      Test drive
                    </UiButton>
                    <UiButton variant="ghost" size="sm" class="text-[13px] font-normal" @click="openEdit(c)">
                      Edit
                    </UiButton>
                    <RowActionsMenu
                      :items="rowActions(c)"
                      label="More actions"
                      @select="(key) => onRowAction(c, key)"
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
      </template>
    </div>

    <Teleport to="body">
      <div v-if="showCreate" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="showCreate = false" />
        <div
          class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-1 text-[15px] font-semibold">Register Client</h3>
          <p class="type-meta mb-5">
            Fields marked <span class="text-red-500">*</span> are required. Everything else has a
            safe default.
          </p>
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
            <button
              type="button"
              class="flex w-full items-center justify-between rounded-lg border border-border/40 px-3 py-2 text-left text-[12px] font-medium text-muted-foreground transition-colors hover:bg-muted/40 hover:text-foreground"
              @click="formAdvancedOpen = !formAdvancedOpen"
            >
              <span>Advanced options</span>
              <span class="text-[11px]">{{ formAdvancedOpen ? "Hide" : "Show" }}</span>
            </button>

<template v-if="formAdvancedOpen">
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
                <span class="type-meta">Off by default. When on, only listed IPs/CIDRs may call authorize/token.</span>
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
</template>
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
          <p
            v-if="editing.owner_email"
            class="type-meta mb-4 rounded-lg bg-muted/50 px-3 py-2"
          >
            Owned by <span class="font-medium text-foreground">{{ editing.owner_email }}</span> —
            they can edit and delete this app from My apps.
          </p>
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

    <ClientSecretDialog :dialog="secretDialog" @close="secretDialog = null" />
  </div>
</template>
