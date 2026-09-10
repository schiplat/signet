<script setup lang="ts">
import { Check, Copy, Fingerprint, Globe, KeyRound, Link2, Plus, RefreshCw, Send, Trash2, Webhook as WebhookIcon, X } from "@lucide/vue";
import { onMounted, ref } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import {
  createSsoProvider,
  createWebhook,
  deleteSsoProvider,
  deleteWebhook,
  fetchIntegrations,
  fetchSsoCallbackUrl,
  fetchSsoProviders,
  generateScimToken,
  listWebhookDeliveries,
  listWebhooks,
  revokeScimToken,
  setSsoProviderEnabled,
  updateSsoProvider,
  type Integrations,
  type SsoProvider,
  type SsoProviderType,
  type Webhook,
  type WebhookDelivery,
  type WebhookKind,
} from "@/lib/api";

const loading = ref(true);
const error = ref("");

const webhooks = ref<Webhook[]>([]);
const showCreate = ref(false);
const creating = ref(false);
const formUrl = ref("");
const formKind = ref<WebhookKind>("feishu");
const formSecret = ref("");
const formErr = ref("");

const deliveries = ref<WebhookDelivery[]>([]);
const deliveriesFor = ref<Webhook | null>(null);
const deliveriesLoading = ref(false);
const deletingId = ref<string | null>(null);

const integrations = ref<Integrations | null>(null);

const scimWorking = ref(false);
const scimErr = ref("");
const scimToken = ref("");
const showScimToken = ref(false);
const copied = ref(false);

// --- SSO providers ---
const ssoProviders = ref<SsoProvider[]>([]);
const ssoCallbackUrl = ref("");
const ssoShowModal = ref(false);
const ssoSaving = ref(false);
const ssoErr = ref("");
const ssoEditing = ref<string | null>(null); // provider code being edited, null = create
const ssoBusyCode = ref<string | null>(null);

const ssoForm = ref({
  code: "",
  provider_type: "github" as SsoProviderType,
  display_name: "",
  client_id: "",
  client_secret: "",
  issuer_url: "",
  scopes: "",
  enabled: true,
});

const SSO_TYPE_LABELS: Record<SsoProviderType, string> = {
  github: "GitHub",
  google: "Google",
  feishu: "Feishu",
  wechat: "WeChat Open Platform",
  oidc: "Generic OIDC",
};

const SSO_TYPE_BADGES: Record<SsoProviderType, string> = {
  github: "bg-[hsl(217_30%_20%)] text-white",
  google: "bg-[hsl(0_70%_55%)] text-white",
  feishu: "bg-[hsl(211_100%_50%)] text-white",
  wechat: "bg-[hsl(142_70%_40%)] text-white",
  oidc: "bg-primary text-primary-foreground",
};

const SSO_TYPE_SHORTS: Record<SsoProviderType, string> = {
  github: "GH",
  google: "G",
  feishu: "FS",
  wechat: "WX",
  oidc: "ID",
};

function providerBadge(type: SsoProviderType) {
  return SSO_TYPE_BADGES[type] ?? SSO_TYPE_BADGES.oidc;
}

function providerShort(type: SsoProviderType) {
  return SSO_TYPE_SHORTS[type] ?? SSO_TYPE_SHORTS.oidc;
}

function openSsoCreate() {
  ssoEditing.value = null;
  ssoForm.value = {
    code: "",
    provider_type: "github",
    display_name: "",
    client_id: "",
    client_secret: "",
    issuer_url: "",
    scopes: "",
    enabled: true,
  };
  ssoErr.value = "";
  ssoShowModal.value = true;
}

function openSsoEdit(p: SsoProvider) {
  ssoEditing.value = p.code;
  ssoForm.value = {
    code: p.code,
    provider_type: p.provider_type,
    display_name: p.display_name,
    client_id: p.client_id,
    client_secret: "",
    issuer_url: p.issuer_url ?? "",
    scopes: p.scopes ?? "",
    enabled: p.enabled,
  };
  ssoErr.value = "";
  ssoShowModal.value = true;
}

async function onSsoSave() {
  ssoErr.value = "";
  const f = ssoForm.value;
  if (!/^[a-zA-Z0-9_-]+$/.test(f.code)) {
    ssoErr.value = "Code may only contain letters, digits, - and _";
    return;
  }
  if (f.provider_type === "oidc" && !f.issuer_url.trim()) {
    ssoErr.value = "Generic OIDC requires the issuer URL";
    return;
  }
  if (!ssoEditing.value && !f.client_secret.trim()) {
    ssoErr.value = "Client secret is required";
    return;
  }
  ssoSaving.value = true;
  const body = {
    code: f.code,
    provider_type: f.provider_type,
    display_name: f.display_name.trim() || SSO_TYPE_LABELS[f.provider_type],
    client_id: f.client_id.trim(),
    client_secret: f.client_secret.trim() || undefined,
    issuer_url: f.issuer_url.trim() || undefined,
    scopes: f.scopes.trim() || undefined,
    enabled: f.enabled,
  };
  try {
    if (ssoEditing.value) {
      await updateSsoProvider(ssoEditing.value, body);
    } else {
      await createSsoProvider(body);
    }
    ssoShowModal.value = false;
    await refresh();
  } catch (e) {
    ssoErr.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    ssoSaving.value = false;
  }
}

async function onSsoToggle(p: SsoProvider) {
  ssoBusyCode.value = p.code;
  ssoErr.value = "";
  try {
    await setSsoProviderEnabled(p.code, !p.enabled);
    await refresh();
  } catch (e) {
    ssoErr.value = e instanceof Error ? e.message : "Update failed";
  } finally {
    ssoBusyCode.value = null;
  }
}

async function onSsoDelete(p: SsoProvider) {
  if (!window.confirm(`Delete provider "${p.display_name}"? All linked accounts for it will be removed.`)) {
    return;
  }
  ssoBusyCode.value = p.code;
  ssoErr.value = "";
  try {
    await deleteSsoProvider(p.code);
    await refresh();
  } catch (e) {
    ssoErr.value = e instanceof Error ? e.message : "Delete failed";
  } finally {
    ssoBusyCode.value = null;
  }
}

async function refresh() {
  const [w, it, providers] = await Promise.all([
    listWebhooks(),
    fetchIntegrations(),
    fetchSsoProviders().catch(() => null),
  ]);
  webhooks.value = w;
  integrations.value = it;
  if (providers) {
    ssoProviders.value = providers.providers;
    fetchSsoCallbackUrl()
      .then((r) => (ssoCallbackUrl.value = r.callback_url))
      .catch(() => (ssoCallbackUrl.value = ""));
  }
}

onMounted(async () => {
  try {
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load integrations";
  } finally {
    loading.value = false;
  }
});

function openCreate() {
  formUrl.value = "";
  formKind.value = "feishu";
  formSecret.value = "";
  formErr.value = "";
  showCreate.value = true;
}

async function onCreate() {
  formErr.value = "";
  if (!/^https?:\/\//.test(formUrl.value.trim())) {
    formErr.value = "URL must start with http:// or https://";
    return;
  }
  creating.value = true;
  try {
    await createWebhook({
      url: formUrl.value.trim(),
      kind: formKind.value,
      secret: formSecret.value.trim() || undefined,
    });
    showCreate.value = false;
    await refresh();
  } catch (e) {
    formErr.value = e instanceof Error ? e.message : "Create failed";
  } finally {
    creating.value = false;
  }
}

async function onDelete(id: string) {
  deletingId.value = id;
  try {
    await deleteWebhook(id);
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Delete failed";
  } finally {
    deletingId.value = null;
  }
}

async function viewDeliveries(w: Webhook) {
  deliveriesFor.value = w;
  deliveries.value = [];
  deliveriesLoading.value = true;
  try {
    deliveries.value = await listWebhookDeliveries(w.id);
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load deliveries";
  } finally {
    deliveriesLoading.value = false;
  }
}

function kindLabel(k: WebhookKind) {
  return k === "feishu" ? "Feishu" : "Generic";
}

async function onGenerateScimToken() {
  scimErr.value = "";
  scimWorking.value = true;
  try {
    const { token } = await generateScimToken();
    scimToken.value = token;
    showScimToken.value = true;
    await refresh();
  } catch (e) {
    scimErr.value = e instanceof Error ? e.message : "Failed to generate token";
  } finally {
    scimWorking.value = false;
  }
}

async function onRevokeScimToken() {
  scimErr.value = "";
  scimWorking.value = true;
  try {
    await revokeScimToken();
    await refresh();
  } catch (e) {
    scimErr.value = e instanceof Error ? e.message : "Failed to revoke token";
  } finally {
    scimWorking.value = false;
  }
}

async function copyToken() {
  const text = scimToken.value;
  if (!text) return;
  const ok = await copyText(text);
  copied.value = ok;
  if (!ok) {
    scimErr.value = "Copy failed — select the token and copy it manually.";
  }
  window.setTimeout(() => {
    copied.value = false;
  }, 2000);
}

const ssoCopiedCode = ref<string | null>(null);
const ssoPatternCopied = ref(false);

async function copySsoUrl(text: string, key: string) {
  const ok = await copyText(text);
  if (!ok) {
    ssoErr.value = "Copy failed — select the URL and copy it manually.";
    return;
  }
  if (key === "__pattern__") {
    ssoPatternCopied.value = true;
    window.setTimeout(() => {
      ssoPatternCopied.value = false;
    }, 2000);
  } else {
    ssoCopiedCode.value = key;
    window.setTimeout(() => {
      if (ssoCopiedCode.value === key) ssoCopiedCode.value = null;
    }, 2000);
  }
}

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to legacy path */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Integrations"
      description="Outbound webhooks and directory sync. Admin only."
    />

    <p v-if="error" class="field-error">{{ error }}</p>
    <div v-if="loading" class="py-12 text-center text-sm text-muted-foreground">Loading…</div>

    <template v-else>
      <!-- Webhooks -->
      <section class="rounded-xl bg-card p-6 shadow-sm">
        <div class="mb-4 flex items-center justify-between gap-3">
          <div>
            <h2 class="flex items-center gap-2 text-sm font-semibold tracking-tight">
              <WebhookIcon class="h-4 w-4 text-muted-foreground" />
              Webhooks
            </h2>
            <p class="mt-1 text-xs text-muted-foreground">
              Push audit events to an external endpoint. Choose Feishu for a custom-bot
              target with card rendering + signature verification.
            </p>
          </div>
          <UiButton size="sm" @click="openCreate">
            <Plus class="h-3.5 w-3.5" />
            New webhook
          </UiButton>
        </div>

        <div v-if="webhooks.length === 0" class="py-8 text-center text-sm text-muted-foreground">
          No webhooks yet.
        </div>

        <ul v-else class="divide-y divide-border/50">
          <li
            v-for="w in webhooks"
            :key="w.id"
            class="flex items-center justify-between gap-3 py-3"
          >
            <div class="min-w-0">
              <div class="flex items-center gap-2">
                <span
                  class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                  :class="w.kind === 'feishu' ? 'bg-blue-500/10 text-blue-600' : 'bg-muted text-muted-foreground'"
                >
                  {{ kindLabel(w.kind) }}
                </span>
                <span
                  v-if="!w.enabled"
                  class="rounded-full bg-destructive/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-destructive"
                >
                  Disabled
                </span>
              </div>
              <p class="mt-1 truncate font-mono text-xs">{{ w.url }}</p>
              <p class="type-meta mt-0.5 text-[11px]">
                Secret: {{ w.secret_set ? "Configured" : "None" }}
              </p>
            </div>
            <div class="flex shrink-0 items-center gap-2">
              <UiButton variant="ghost" size="sm" @click="viewDeliveries(w)">
                <Send class="h-3.5 w-3.5" />
                Deliveries
              </UiButton>
              <UiButton
                variant="ghost"
                size="icon"
                :disabled="deletingId === w.id"
                @click="onDelete(w.id)"
              >
                <Trash2 class="h-4 w-4 text-destructive" />
              </UiButton>
            </div>
          </li>
        </ul>

        <!-- Deliveries panel -->
        <div
          v-if="deliveriesFor"
          class="mt-4 rounded-xl border border-border/50 bg-muted/30 p-4"
        >
          <div class="mb-2 flex items-center justify-between">
            <p class="text-xs font-medium">Recent deliveries · {{ deliveriesFor.url }}</p>
            <UiButton variant="ghost" size="sm" @click="deliveriesFor = null">Close</UiButton>
          </div>
          <div v-if="deliveriesLoading" class="py-4 text-center text-xs text-muted-foreground">
            Loading…
          </div>
          <ul v-else-if="deliveries.length" class="space-y-1.5">
            <li
              v-for="d in deliveries"
              :key="d.id"
              class="flex items-center justify-between gap-3 text-xs"
            >
              <span class="font-mono text-muted-foreground">{{ d.event_id }}</span>
              <span
                class="rounded-full px-2 py-0.5 text-[10px] font-semibold"
                :class="d.success ? 'bg-emerald-500/10 text-emerald-600' : 'bg-destructive/10 text-destructive'"
              >
                {{ d.status_code ?? "—" }} {{ d.success ? "ok" : "failed" }}
              </span>
              <span class="type-meta">{{ new Date(d.created_at).toLocaleString() }}</span>
            </li>
          </ul>
          <p v-else class="py-4 text-center text-xs text-muted-foreground">No deliveries yet.</p>
        </div>
      </section>

      <!-- Third-party sign-in (SSO providers) -->
      <section class="rounded-xl bg-card p-6 shadow-sm">
        <div class="mb-4 flex items-center justify-between gap-3">
          <div>
            <h2 class="flex items-center gap-2 text-sm font-semibold tracking-tight">
              <Link2 class="h-4 w-4 text-muted-foreground" />
              Third-party sign-in
            </h2>
            <p class="mt-1 text-xs text-muted-foreground">
              Let users register and sign in with GitHub, Google, Feishu, WeChat or any OIDC
              issuer. Register the callback URL below with each provider.
            </p>
          </div>
          <UiButton size="sm" @click="openSsoCreate">
            <Plus class="h-3.5 w-3.5" />
            New provider
          </UiButton>
        </div>

        <div v-if="ssoCallbackUrl" class="mb-4 space-y-1.5 rounded-lg bg-muted/40 px-3 py-2.5">
          <div class="flex items-center gap-2">
            <span class="shrink-0 text-[11px] font-medium text-muted-foreground">URL pattern</span>
            <code class="truncate font-mono text-[11px]">{{ ssoCallbackUrl }}</code>
            <UiButton
              type="button"
              variant="ghost"
              size="icon"
              class="ml-auto shrink-0"
              title="Copy pattern"
              @click="copySsoUrl(ssoCallbackUrl, '__pattern__')"
            >
              <Check v-if="ssoPatternCopied" class="h-3.5 w-3.5 text-emerald-600" />
              <Copy v-else class="h-3.5 w-3.5" />
            </UiButton>
          </div>
          <p class="text-[11px] leading-relaxed text-muted-foreground">
            All providers use the same path:
            <code class="rounded bg-muted px-1">/api/v1/auth/sso/&#123;code&#125;/callback</code>.
            Copy the exact URL under each provider below — do not invent a different format.
          </p>
        </div>

        <p v-if="ssoErr" class="field-error mb-3">{{ ssoErr }}</p>

        <div v-if="ssoProviders.length === 0" class="py-8 text-center text-sm text-muted-foreground">
          No sign-in providers configured yet.
        </div>

        <ul v-else class="divide-y divide-border/50">
          <li
            v-for="p in ssoProviders"
            :key="p.code"
            class="flex flex-col gap-2 py-3 sm:flex-row sm:items-center sm:justify-between"
          >
            <div class="min-w-0 flex-1">
              <div class="flex flex-wrap items-center gap-2">
                <span
                  class="flex h-5 w-5 shrink-0 items-center justify-center rounded text-[9px] font-bold"
                  :class="providerBadge(p.provider_type)"
                >
                  {{ providerShort(p.provider_type) }}
                </span>
                <span class="text-sm font-medium">{{ p.display_name }}</span>
                <span class="type-meta font-mono text-[10px]">{{ p.code }}</span>
                <span
                  v-if="!p.enabled"
                  class="rounded-full bg-destructive/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-destructive"
                >
                  Disabled
                </span>
              </div>
              <p class="type-meta mt-1 text-[11px]">
                {{ SSO_TYPE_LABELS[p.provider_type] }} · {{ p.bindings }}
                {{ p.bindings === 1 ? "linked account" : "linked accounts" }}
                <template v-if="p.provider_type === 'oidc' && p.issuer_url">
                  · {{ p.issuer_url }}
                </template>
              </p>
              <div class="mt-1.5 flex items-center gap-1.5">
                <code class="min-w-0 truncate font-mono text-[10px] text-muted-foreground">{{
                  p.callback_url
                }}</code>
                <UiButton
                  type="button"
                  variant="ghost"
                  size="icon"
                  class="h-6 w-6 shrink-0"
                  title="Copy callback URL"
                  @click="copySsoUrl(p.callback_url, p.code)"
                >
                  <Check
                    v-if="ssoCopiedCode === p.code"
                    class="h-3 w-3 text-emerald-600"
                  />
                  <Copy v-else class="h-3 w-3" />
                </UiButton>
              </div>
            </div>
            <div class="flex shrink-0 items-center gap-2">
              <UiButton variant="ghost" size="sm" :disabled="ssoBusyCode === p.code" @click="onSsoToggle(p)">
                {{ p.enabled ? "Disable" : "Enable" }}
              </UiButton>
              <UiButton variant="ghost" size="sm" @click="openSsoEdit(p)">Edit</UiButton>
              <UiButton
                variant="ghost"
                size="icon"
                :disabled="ssoBusyCode === p.code"
                @click="onSsoDelete(p)"
              >
                <Trash2 class="h-4 w-4 text-destructive" />
              </UiButton>
            </div>
          </li>
        </ul>
      </section>

      <!-- SCIM -->
      <section class="rounded-xl bg-card p-6 shadow-sm">
        <div class="mb-3 flex items-center justify-between gap-3">
          <div>
            <h2 class="flex items-center gap-2 text-sm font-semibold tracking-tight">
              <Globe class="h-4 w-4 text-muted-foreground" />
              SCIM v2 (directory sync)
            </h2>
            <p class="mt-1 text-xs text-muted-foreground">
              Provisioning API consumed by Okta / Entra ID / HR systems. The bearer token is
              stored hashed and shown only once when generated.
            </p>
          </div>
        </div>
        <dl class="space-y-2 text-sm">
          <div class="flex items-center gap-2">
            <dt class="w-32 shrink-0 text-xs text-muted-foreground">Status</dt>
            <dd>
              <span
                class="rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                :class="
                  integrations?.scim.enabled
                    ? 'bg-emerald-500/10 text-emerald-600'
                    : 'bg-destructive/10 text-destructive'
                "
              >
                {{ integrations?.scim.enabled ? "Enabled" : "Not configured" }}
              </span>
            </dd>
          </div>
          <div class="flex items-center gap-2">
            <dt class="w-32 shrink-0 text-xs text-muted-foreground">Endpoint</dt>
            <dd class="font-mono text-xs">{{ integrations?.scim.base_url }}</dd>
          </div>
          <div class="flex items-center gap-2">
            <dt class="w-32 shrink-0 text-xs text-muted-foreground">Bearer token</dt>
            <dd class="text-xs">{{ integrations?.scim.token_configured ? "Configured" : "Missing" }}</dd>
          </div>
        </dl>

        <div class="mt-4 flex items-center gap-2">
          <UiButton
            size="sm"
            :disabled="scimWorking"
            @click="onGenerateScimToken"
          >
            <KeyRound v-if="!integrations?.scim.enabled" class="h-3.5 w-3.5" />
            <RefreshCw v-else class="h-3.5 w-3.5" />
            {{ integrations?.scim.enabled ? "Rotate token" : "Generate token" }}
          </UiButton>
          <UiButton
            v-if="integrations?.scim.enabled"
            variant="ghost"
            size="sm"
            :disabled="scimWorking"
            @click="onRevokeScimToken"
          >
            <Trash2 class="h-3.5 w-3.5 text-destructive" />
            Revoke
          </UiButton>
        </div>
        <p v-if="scimErr" class="field-error mt-2">{{ scimErr }}</p>
      </section>

      <!-- WebAuthn -->
      <section class="rounded-xl bg-card p-6 shadow-sm">
        <div class="mb-3">
          <h2 class="flex items-center gap-2 text-sm font-semibold tracking-tight">
            <Fingerprint class="h-4 w-4 text-muted-foreground" />
            WebAuthn / Passkeys
          </h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Relying-party identity used during passkey ceremonies. Set
            <code class="rounded bg-muted px-1">SIGNET_WEBAUTHN_RP_ID</code> /
            <code class="rounded bg-muted px-1">SIGNET_WEBAUTHN_RP_ORIGIN</code> for production.
          </p>
        </div>
        <dl class="space-y-2 text-sm">
          <div class="flex items-center gap-2">
            <dt class="w-32 shrink-0 text-xs text-muted-foreground">RP ID</dt>
            <dd class="font-mono text-xs">{{ integrations?.webauthn.rp_id }}</dd>
          </div>
          <div class="flex items-center gap-2">
            <dt class="w-32 shrink-0 text-xs text-muted-foreground">RP origin</dt>
            <dd class="font-mono text-xs">{{ integrations?.webauthn.rp_origin }}</dd>
          </div>
        </dl>
      </section>
    </template>

    <!-- Create webhook modal -->
    <Teleport to="body">
      <div v-if="showCreate" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!creating && (showCreate = false)" />
        <div class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
          <h2 class="mb-4 text-base font-semibold">New webhook</h2>
          <form class="space-y-3.5" @submit.prevent="onCreate">
            <div>
              <label class="type-label mb-1.5 block">Type</label>
              <select v-model="formKind" class="field-input">
                <option value="feishu">Feishu custom bot</option>
                <option value="generic">Generic (raw JSON + HMAC header)</option>
              </select>
            </div>
            <div>
              <label class="type-label mb-1.5 block">Webhook URL</label>
              <input v-model="formUrl" class="field-input" placeholder="https://open.feishu.cn/open-apis/bot/v2/hook/…" required />
              <p v-if="formKind === 'feishu'" class="type-meta mt-1 text-[11px]">
                Paste the full Feishu custom-bot webhook URL.
              </p>
            </div>
            <div>
              <label class="type-label mb-1.5 block">Signature secret (optional)</label>
              <input v-model="formSecret" class="field-input" placeholder="Only needed if the Feishu bot has signature verification enabled" />
              <p class="type-meta mt-1 text-[11px]">
                For Feishu, only needed if the bot has signature verification enabled.
              </p>
            </div>
            <p v-if="formErr" class="field-error">{{ formErr }}</p>
            <div class="flex justify-end gap-2 pt-1">
              <UiButton type="button" variant="ghost" size="sm" :disabled="creating" @click="showCreate = false">
                Cancel
              </UiButton>
              <UiButton type="submit" size="sm" :disabled="creating">
                {{ creating ? "Creating…" : "Create" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <!-- SCIM token reveal modal -->
    <Teleport to="body">
      <div v-if="showScimToken" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="showScimToken = false" />
        <div class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
          <div class="mb-3 flex items-center justify-between">
            <h2 class="text-base font-semibold">SCIM bearer token</h2>
            <button class="text-muted-foreground hover:text-foreground" @click="showScimToken = false">
              <X class="h-4 w-4" />
            </button>
          </div>
          <p class="type-meta mb-3 text-xs">
            Copy it now — it is shown only once and cannot be retrieved again.
          </p>
          <div class="mb-4 flex items-center gap-2">
            <code class="flex-1 break-all rounded-lg bg-muted px-3 py-2 font-mono text-xs">{{ scimToken }}</code>
            <UiButton size="sm" variant="outline" :class="copied ? 'text-emerald-600' : ''" @click="copyToken">
              <Check v-if="copied" class="h-3.5 w-3.5" />
              <Copy v-else class="h-3.5 w-3.5" />
              {{ copied ? "Copied" : "Copy" }}
            </UiButton>
          </div>
          <div class="flex justify-end">
            <UiButton size="sm" @click="showScimToken = false">Done</UiButton>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- SSO provider create/edit modal -->
    <Teleport to="body">
      <div v-if="ssoShowModal" class="fixed inset-0 z-50 flex items-center justify-center">
        <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="!ssoSaving && (ssoShowModal = false)" />
        <div class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl">
          <h2 class="mb-4 text-base font-semibold">
            {{ ssoEditing ? "Edit sign-in provider" : "New sign-in provider" }}
          </h2>
          <form class="space-y-3.5" @submit.prevent="onSsoSave">
            <div class="grid grid-cols-2 gap-3">
              <div>
                <label class="type-label mb-1.5 block">Type</label>
                <select v-model="ssoForm.provider_type" class="field-input" :disabled="!!ssoEditing">
                  <option value="github">GitHub</option>
                  <option value="google">Google</option>
                  <option value="feishu">Feishu</option>
                  <option value="wechat">WeChat Open Platform</option>
                  <option value="oidc">Generic OIDC</option>
                </select>
                <p
                  v-if="ssoForm.provider_type === 'feishu'"
                  class="type-meta mt-1.5 text-[11px] text-amber-700 dark:text-amber-400"
                >
                  Feishu must return email for first-time link / login. Enable
                  contact:user.email:readonly (and contact:user.employee:readonly for
                  enterprise_email), publish the app, then retry.
                </p>
                <p
                  v-else-if="ssoForm.provider_type === 'wechat'"
                  class="type-meta mt-1.5 text-[11px]"
                >
                  WeChat Open Platform does not provide email; users link via pending
                  password bind or an already-signed-in session.
                </p>
              </div>
              <div>
                <label class="type-label mb-1.5 block">Code (URL slug)</label>
                <input
                  v-model="ssoForm.code"
                  class="field-input"
                  placeholder="github"
                  pattern="[a-zA-Z0-9_-]+"
                  :disabled="!!ssoEditing"
                  required
                />
              </div>
            </div>
            <div>
              <label class="type-label mb-1.5 block">Display name</label>
              <input
                v-model="ssoForm.display_name"
                class="field-input"
                :placeholder="SSO_TYPE_LABELS[ssoForm.provider_type]"
              />
            </div>
            <div>
              <label class="type-label mb-1.5 block">Client ID</label>
              <input v-model="ssoForm.client_id" class="field-input" placeholder="App / client ID from the provider" required />
            </div>
            <div>
              <label class="type-label mb-1.5 block">
                Client secret {{ ssoEditing ? "(leave blank to keep current)" : "" }}
              </label>
              <input
                v-model="ssoForm.client_secret"
                type="password"
                class="field-input"
                :placeholder="ssoEditing ? '••••••••••' : 'Client secret'"
                :required="!ssoEditing"
                autocomplete="new-password"
              />
            </div>
            <div v-if="ssoForm.provider_type === 'oidc'">
              <label class="type-label mb-1.5 block">Issuer URL</label>
              <input
                v-model="ssoForm.issuer_url"
                class="field-input"
                placeholder="https://sso.example.com/realms/main"
                required
              />
              <p class="type-meta mt-1 text-[11px]">
                Discovery is read from issuer + /.well-known/openid-configuration
              </p>
            </div>
            <div>
              <label class="type-label mb-1.5 block">Scopes (optional)</label>
              <input
                v-model="ssoForm.scopes"
                class="field-input"
                placeholder="Leave blank for provider defaults"
              />
            </div>
            <label class="flex items-center gap-2 text-sm">
              <input v-model="ssoForm.enabled" type="checkbox" class="rounded" />
              Enabled (visible on the login page)
            </label>
            <p v-if="ssoErr" class="field-error">{{ ssoErr }}</p>
            <div class="flex justify-end gap-2 pt-1">
              <UiButton type="button" variant="ghost" size="sm" :disabled="ssoSaving" @click="ssoShowModal = false">
                Cancel
              </UiButton>
              <UiButton type="submit" size="sm" :disabled="ssoSaving">
                {{ ssoSaving ? "Saving…" : ssoEditing ? "Save changes" : "Create provider" }}
              </UiButton>
            </div>
          </form>
        </div>
      </div>
    </Teleport>
  </div>
</template>
