<script setup lang="ts">
import { onMounted, ref } from "vue";
import { KeyRound, Plus, Trash2 } from "@lucide/vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import ClientSecretDialog, {
  type SecretDialogPayload,
} from "@/components/ui/ClientSecretDialog.vue";
import RowActionsMenu, { type RowActionItem } from "@/components/ui/RowActionsMenu.vue";
import { confirm } from "@/lib/confirm";
import {
  createMyClient,
  deleteMyClient,
  listMyClients,
  rotateMyClientSecret,
  updateMyClient,
  type SelfClient,
} from "@/lib/api";

const apps = ref<SelfClient[]>([]);
const loading = ref(true);
const error = ref("");

// Registration dialog
const showCreate = ref(false);
const creating = ref(false);
const formName = ref("");
const formRedirects = ref("");
const formScopes = ref("");

// Edit dialog — only the two fields an owner may change.
const editing = ref<SelfClient | null>(null);
const saving = ref(false);
const editName = ref("");
const editRedirects = ref("");

const rotatingId = ref<string | null>(null);
const secretDialog = ref<SecretDialogPayload | null>(null);

async function refresh() {
  apps.value = await listMyClients();
}

// Row actions: Edit stays inline (frequent); rotate/delete live in the menu.
function rowActions(c: SelfClient): RowActionItem[] {
  return [
    {
      key: "rotate",
      label: rotatingId.value === c.id ? "Rotating…" : "Rotate secret",
      icon: KeyRound,
      disabled: rotatingId.value === c.id,
    },
    { key: "delete", label: "Delete", icon: Trash2, danger: true, separator: true },
  ];
}

function onRowAction(c: SelfClient, key: string) {
  if (key === "rotate") void onRotate(c);
  else if (key === "delete") void onDelete(c);
}

onMounted(async () => {
  try {
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load your applications";
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

function displayName(c: SelfClient) {
  return c.client_name || c.client_id;
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleDateString(undefined, {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}

function openCreate() {
  formName.value = "";
  formRedirects.value = "";
  formScopes.value = "";
  showCreate.value = true;
}

async function onCreate() {
  error.value = "";
  creating.value = true;
  try {
    const scopes = parseLines(formScopes.value);
    const res = await createMyClient({
      client_name: formName.value,
      redirect_uris: parseLines(formRedirects.value),
      scopes: scopes.length ? scopes : undefined,
    });
    showCreate.value = false;
    secretDialog.value = {
      clientId: res.client.client_id,
      secret: res.client_secret,
      title: "Application registered",
      client: res.client,
    };
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Registration failed";
  } finally {
    creating.value = false;
  }
}

function openEdit(c: SelfClient) {
  editing.value = c;
  editName.value = c.client_name;
  editRedirects.value = c.redirect_uris.join("\n");
}

async function onSaveEdit() {
  if (!editing.value) return;
  error.value = "";
  saving.value = true;
  try {
    await updateMyClient(editing.value.id, {
      client_name: editName.value,
      redirect_uris: parseLines(editRedirects.value),
    });
    editing.value = null;
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Update failed";
  } finally {
    saving.value = false;
  }
}

async function onRotate(c: SelfClient) {
  if (
    !(await confirm({
      title: "Rotate client secret?",
      message: `The current secret for "${displayName(c)}" stops working immediately. Copy the new one when it is shown.`,
      confirmText: "Rotate",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  rotatingId.value = c.id;
  try {
    const res = await rotateMyClientSecret(c.id);
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

async function onDelete(c: SelfClient) {
  if (
    !(await confirm({
      title: "Delete application?",
      message: `"${displayName(c)}" stops working immediately: every outstanding token and user consent for it is removed. This cannot be undone.`,
      confirmText: "Delete",
      danger: true,
    }))
  ) {
    return;
  }
  error.value = "";
  try {
    await deleteMyClient(c.id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Delete failed";
  }
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="My apps"
      description="Register OAuth applications and manage the ones you created. Users decide at sign-in which of them may access their account."
    >
      <template #actions>
        <UiButton size="sm" @click="openCreate">
          <Plus class="h-4 w-4" />
          Register an application
        </UiButton>
      </template>
    </PageHeader>

    <p v-if="error" class="field-error">{{ error }}</p>

    <div
      v-if="loading"
      class="py-12 text-center text-sm text-muted-foreground"
    >
      Loading…
    </div>

    <div
      v-else-if="apps.length === 0"
      class="flex flex-col items-center justify-center py-16 text-muted-foreground"
    >
      <p class="text-sm">No applications yet</p>
      <p class="type-meta mt-1">
        Register one to let an internal system sign users in through this server.
      </p>
    </div>

    <div
      v-else
      class="surface-card overflow-hidden"
    >
      <div class="overflow-x-auto">
        <table class="w-full text-[13px]">
          <thead>
            <tr class="border-b border-border/50">
              <th class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                Application
              </th>
              <th class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                Redirect URIs
              </th>
              <th class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                Scopes
              </th>
              <th class="px-5 py-2.5 text-left text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                Created
              </th>
              <th class="px-5 py-2.5 text-right text-[11px] font-medium uppercase tracking-[0.04em] text-muted-foreground/80">
                Actions
              </th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="c in apps"
              :key="c.id"
              class="border-b border-border/40 transition-colors last:border-0 hover:bg-muted/5"
            >
              <td class="px-5 py-3">
                <p class="font-medium">{{ displayName(c) }}</p>
                <p class="mt-0.5 font-mono text-[11px] text-muted-foreground">
                  {{ c.client_id }}
                </p>
                <p
                  v-if="!c.enabled"
                  class="mt-1 inline-flex items-center rounded-md bg-destructive/10 px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide text-destructive"
                >
                  disabled
                </p>
              </td>
              <td class="max-w-xs px-5 py-3 text-xs text-muted-foreground">
                <span class="block break-all font-mono text-[11px]">
                  {{ c.redirect_uris[0] }}
                </span>
                <span v-if="c.redirect_uris.length > 1" class="text-[11px]">
                  +{{ c.redirect_uris.length - 1 }} more
                </span>
              </td>
              <td class="max-w-xs px-5 py-3 text-xs text-muted-foreground">
                <span class="font-mono text-[11px]">{{ (c.scopes || []).join(", ") }}</span>
              </td>
              <td class="whitespace-nowrap px-5 py-3 text-xs text-muted-foreground">
                {{ formatDate(c.created_at) }}
              </td>
              <td class="whitespace-nowrap px-5 py-3 text-right align-middle">
                    <div class="flex items-center justify-end gap-1">
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
          <h3 class="mb-5 text-[15px] font-semibold">Register an application</h3>
          <form class="space-y-4" @submit.prevent="onCreate">
            <div>
              <label class="mb-1 block text-[12px] font-medium">
                Application name <span class="text-red-500">*</span>
              </label>
              <input
                v-model="formName"
                required
                maxlength="200"
                placeholder="e.g. Internal Ticketing"
                class="field-input"
              />
              <p class="type-meta mt-1">
                Shown to users on the consent screen when they sign in to it.
              </p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">
                Redirect URIs <span class="text-red-500">*</span>
              </label>
              <textarea
                v-model="formRedirects"
                required
                rows="3"
                placeholder="https://app.example.com/callback"
                class="field-input font-mono text-xs"
              />
              <p class="type-meta mt-1">
                One per line (or comma-separated). Must be http(s), no fragment.
              </p>
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Scopes</label>
              <input
                v-model="formScopes"
                placeholder="openid, profile, email (default)"
                class="field-input"
              />
              <p class="type-meta mt-1">Optional — leave empty for the defaults.</p>
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
      <div
        v-if="editing"
        class="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto p-4 sm:items-center"
      >
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="editing = null" />
        <div
          class="relative z-10 my-auto w-full max-w-md max-h-[calc(100dvh-2rem)] overflow-y-auto overscroll-contain rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <h3 class="mb-5 text-[15px] font-semibold">Edit application</h3>
          <form class="space-y-4" @submit.prevent="onSaveEdit">
            <div>
              <label class="mb-1 block text-[12px] font-medium">Application name</label>
              <input v-model="editName" required maxlength="200" class="field-input" />
            </div>
            <div>
              <label class="mb-1 block text-[12px] font-medium">Redirect URIs</label>
              <textarea
                v-model="editRedirects"
                required
                rows="3"
                class="field-input font-mono text-xs"
              />
            </div>
            <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
              <UiButton type="button" variant="ghost" size="sm" @click="editing = null">
                Cancel
              </UiButton>
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
