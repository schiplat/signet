<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import {
  createApiToken,
  fetchApiTokens,
  fetchMfaSettings,
  fetchRuntimeSettings,
  fetchSignInSettings,
  fetchSsoSettings,
  me,
  revokeApiToken,
  updateMfaSettings,
  updateRuntimeSettings,
  updateSignInSettings,
  updateSsoSettings,
  type ApiToken,
  type RuntimeSettings,
} from "@/lib/api";
import { joinList, splitList } from "@/lib/directoryMapping";

const loading = ref(true);
const error = ref("");

const mfaSaving = ref(false);
const mfaSaved = ref(false);
const requiredGlobally = ref(false);

const ssoSaving = ref(false);
const ssoSaved = ref(false);
const jitProvision = ref(false);

/**
 * Operational policy. Values here take effect on the next request — no
 * redeploy — and the environment only applies to fields nobody has saved here.
 */
const runtime = ref<RuntimeSettings | null>(null);
const runtimeOverridden = ref<(keyof RuntimeSettings)[]>([]);
const runtimeSaving = ref(false);
const runtimeSaved = ref(false);
const runtimeRows: {
  key: keyof RuntimeSettings;
  label: string;
  hint: string;
  min: number;
  max: number;
}[] = [
  { key: "session_ttl_hours", label: "Session lifetime", hint: "hours a dashboard session stays valid", min: 1, max: 720 },
  { key: "auth_code_ttl_secs", label: "Authorization code lifetime", hint: "seconds an OIDC code can be exchanged", min: 30, max: 3600 },
  { key: "access_token_ttl_secs", label: "Access token lifetime", hint: "seconds an access token is accepted", min: 60, max: 86400 },
  { key: "id_token_ttl_secs", label: "ID token lifetime", hint: "seconds an ID token is accepted", min: 60, max: 86400 },
  { key: "refresh_token_ttl_days", label: "Refresh token lifetime", hint: "days a refresh token lives before re-auth", min: 1, max: 365 },
  { key: "max_login_attempts", label: "Login attempts before lockout", hint: "failed passwords charged to the account", min: 1, max: 100 },
  { key: "lockout_minutes", label: "Lockout duration", hint: "minutes the account stays locked", min: 1, max: 1440 },
  { key: "password_min_length", label: "Minimum password length", hint: "characters required for a new password", min: 8, max: 128 },
  { key: "password_history_size", label: "Password history", hint: "previous passwords that cannot be reused (0 = off)", min: 0, max: 24 },
  { key: "audit_retention_days", label: "Audit retention", hint: "days audit rows are kept before the hourly sweep", min: 1, max: 3650 },
  { key: "rate_limit_per_minute", label: "Rate limit", hint: "requests per minute per client IP", min: 1, max: 100000 },
];

const allowlistSaving = ref(false);
const allowlistSaved = ref(false);
/** The list as one editable string; parsed on save, like the source scope rows. */
const allowlistInput = ref("");
const allowlistOrigin = ref<"setting" | "environment" | "unrestricted">("unrestricted");
/** The acting admin's own address, for the warning below the field. */
const ownEmail = ref("");

/** The domain of an address, lowercased, or "" when there is none to read. */
function domainOf(email: string): string {
  const at = email.lastIndexOf("@");
  if (at <= 0 || at === email.length - 1) return "";
  return email.slice(at + 1).trim().toLowerCase();
}

/** The domains as typed, without the save-time validation the server owns. */
const allowlistDomains = computed(() => splitList(allowlistInput.value));

/**
 * Whether saving this list would lock the acting admin out.
 *
 * The server refuses this too, and is the authority; saying it here is what
 * turns a 400 after the fact into something the admin sees while typing. Empty
 * means unrestricted, so it can never lock anyone out.
 */
const allowlistLocksMeOut = computed(() => {
  const domains = allowlistDomains.value;
  if (domains.length === 0 || !ownEmail.value) return false;
  const mine = domainOf(ownEmail.value);
  return !domains.some((allowed) => mine === allowed || mine.endsWith(`.${allowed}`));
});

onMounted(async () => {
  try {
    const [mfa, sso, signIn, who, runtimeRes] = await Promise.all([
      fetchMfaSettings(),
      fetchSsoSettings(),
      fetchSignInSettings(),
      me(),
      fetchRuntimeSettings(),
    ]);
    requiredGlobally.value = mfa.required_globally;
    jitProvision.value = sso.jit_provision;
    allowlistInput.value = joinList(signIn.allowed_email_domains);
    allowlistOrigin.value = signIn.origin;
    ownEmail.value = who.user.email;
    runtime.value = runtimeRes.settings;
    runtimeOverridden.value = runtimeRes.overridden;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load settings";
  } finally {
    loading.value = false;
  }
  // Non-fatal: a token list that fails to load still leaves the settings page
  // usable, with the section showing its own error on save attempts.
  try {
    await refreshApiTokens();
  } catch {
    /* surfaced when the operator interacts with the section */
  }
});

async function onSaveAllowlist() {
  error.value = "";
  allowlistSaved.value = false;
  allowlistSaving.value = true;
  try {
    const domains = allowlistDomains.value;
    // An empty box clears the row rather than storing `[]`, so the environment
    // gets a say again — the two are only the same when nothing is in the
    // environment, and that is not knowable from here.
    const res = await updateSignInSettings(domains.length === 0 ? null : domains);
    allowlistInput.value = joinList(res.allowed_email_domains);
    allowlistOrigin.value = res.origin;
    allowlistSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    allowlistSaving.value = false;
  }
}

async function onSaveMfa() {
  error.value = "";
  mfaSaved.value = false;
  mfaSaving.value = true;
  try {
    const res = await updateMfaSettings({ required_globally: requiredGlobally.value });
    requiredGlobally.value = res.required_globally;
    mfaSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    mfaSaving.value = false;
  }
}

async function onSaveRuntime() {
  if (!runtime.value) return;
  error.value = "";
  runtimeSaved.value = false;
  runtimeSaving.value = true;
  try {
    const res = await updateRuntimeSettings({ ...runtime.value });
    runtime.value = res.settings;
    runtimeOverridden.value = res.overridden;
    runtimeSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    runtimeSaving.value = false;
  }
}

async function onSaveSso() {
  error.value = "";
  ssoSaved.value = false;
  ssoSaving.value = true;
  try {
    const res = await updateSsoSettings({ jit_provision: jitProvision.value });
    jitProvision.value = res.jit_provision;
    ssoSaved.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Save failed";
  } finally {
    ssoSaving.value = false;
  }
}

// --- API tokens (machine credentials) ---
//
// The plaintext is returned by the server exactly once, so it is held in
// `freshToken` and cleared the moment it is copied or dismissed — not kept in
// component state longer than the operator needs it.

const apiTokens = ref<ApiToken[]>([]);
const newTokenName = ref("");
const newTokenExpiryDays = ref<string>("");
const freshToken = ref("");
const tokenWorking = ref(false);

function formatWhen(iso: string): string {
  return new Date(iso).toLocaleString();
}

function copyFreshToken() {
  navigator.clipboard.writeText(freshToken.value).then(
    () => {
      freshToken.value = "";
    },
    () => {
      /* selection copy still works; keep the token visible */
    },
  );
}

async function refreshApiTokens() {
  const res = await fetchApiTokens();
  apiTokens.value = res.tokens;
}

async function onCreateToken() {
  error.value = "";
  const name = newTokenName.value.trim();
  if (!name) return;
  const days = newTokenExpiryDays.value ? Number(newTokenExpiryDays.value) : null;
  if (days !== null && (!Number.isInteger(days) || days < 1 || days > 3650)) {
    error.value = "Expiry must be a whole number of days (1-3650), or empty";
    return;
  }
  tokenWorking.value = true;
  try {
    const res = await createApiToken(name, days);
    freshToken.value = res.token;
    newTokenName.value = "";
    newTokenExpiryDays.value = "";
    await refreshApiTokens();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Token creation failed";
  } finally {
    tokenWorking.value = false;
  }
}

async function onRevokeToken(t: ApiToken) {
  error.value = "";
  tokenWorking.value = true;
  try {
    await revokeApiToken(t.id);
    await refreshApiTokens();
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Revoke failed";
  } finally {
    tokenWorking.value = false;
  }
}
</script>

<template>
  <div class="space-y-6">
    <PageHeader
      title="Settings"
      description="Global Signet configuration. Admin only."
    />

    <p v-if="error" class="field-error">{{ error }}</p>
    <div v-if="loading" class="py-12 text-center text-sm text-muted-foreground">Loading…</div>

    <template v-else>
      <section class="max-w-xl space-y-5 rounded-xl bg-card p-6 shadow-sm">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Security</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Controls whether users without TOTP must enroll before signing in. Users who already
            enabled MFA always verify on login.
          </p>
        </div>

        <label class="flex items-start gap-3 rounded-lg border border-border/40 px-4 py-3">
          <input v-model="requiredGlobally" type="checkbox" class="mt-0.5 rounded" />
          <span>
            <span class="block text-sm font-medium">Require MFA for all users</span>
            <span class="mt-0.5 block text-xs text-muted-foreground">
              When on, every account without an authenticator must enroll at next login. Per-user
              Require MFA still applies when this is off.
            </span>
          </span>
        </label>

        <div class="flex items-center gap-3">
          <UiButton size="sm" :disabled="mfaSaving" @click="onSaveMfa">
            {{ mfaSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="mfaSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section class="max-w-xl space-y-5 rounded-xl bg-card p-6 shadow-sm">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Email domain allowlist</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Only these domains may sign in or be provisioned. Subdomains are included; there are
            no wildcards. Empty allows every domain. Accounts that fall outside keep their data
            and are <em>not</em> disabled — they simply cannot sign in until the list is widened.
          </p>
        </div>

        <div>
          <label class="type-label mb-1.5 block" for="allowlist">
            Allowed domains
          </label>
          <textarea
            id="allowlist"
            v-model="allowlistInput"
            rows="3"
            class="field-input font-mono text-[12px]"
            placeholder="corp.example, partner.example"
          />
          <p class="type-meta mt-1 text-[11px]">
            Comma or newline separated.
            <template v-if="allowlistOrigin === 'environment'">
              Currently in force from <code class="text-[11px]">SIGNET_ALLOWED_EMAIL_DOMAINS</code>;
              saving here overrides it.
            </template>
            <template v-else-if="allowlistOrigin === 'unrestricted'">
              Nothing is restricted right now.
            </template>
          </p>
          <!-- The server refuses this save; warning here is the difference
               between seeing it while typing and a 400 after pressing Save.
               The whitelist never applies to /setup, so an operator cannot
               brick an instance before an admin exists. -->
          <p
            v-if="allowlistLocksMeOut"
            class="type-meta mt-2 text-amber-700 dark:text-amber-400"
          >
            Your own address ({{ ownEmail }}) is not covered, so saving this would refuse your
            next sign-in.
          </p>
        </div>

        <div class="flex items-center gap-3">
          <UiButton
            size="sm"
            :disabled="allowlistSaving || allowlistLocksMeOut"
            @click="onSaveAllowlist"
          >
            {{ allowlistSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="allowlistSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section class="max-w-xl space-y-5 rounded-xl bg-card p-6 shadow-sm">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">Runtime policies</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Token lifetimes, lockout and password policy, audit retention and the global rate
            limit. Changes apply immediately; a field shows <em>env</em> when nothing has been
            saved here and the environment value is in force.
          </p>
        </div>

        <div v-if="runtime" class="space-y-3">
          <label
            v-for="row in runtimeRows"
            :key="row.key"
            class="flex items-start gap-3 rounded-lg border border-border/40 px-4 py-3"
          >
            <span class="flex-1">
              <span class="block text-sm font-medium">{{ row.label }}</span>
              <span class="mt-0.5 block text-xs text-muted-foreground">
                {{ row.hint }} · {{ runtime[row.key] }}
                <template v-if="!runtimeOverridden.includes(row.key)">
                  (from <code class="text-[11px]">env</code>)
                </template>
              </span>
            </span>
            <input
              v-model.number="runtime[row.key]"
              type="number"
              :min="row.min"
              :max="row.max"
              class="field-input w-28 text-right font-mono text-[12px]"
            />
          </label>
        </div>

        <div class="flex items-center gap-3">
          <UiButton size="sm" :disabled="runtimeSaving || !runtime" @click="onSaveRuntime">
            {{ runtimeSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="runtimeSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section class="max-w-xl space-y-5 rounded-xl bg-card p-6 shadow-sm">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">SSO / federation</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            First-login behavior when a third-party identity has a verified email that does not
            match an existing local user.
          </p>
        </div>

        <label class="flex items-start gap-3 rounded-lg border border-border/40 px-4 py-3">
          <input v-model="jitProvision" type="checkbox" class="mt-0.5 rounded" />
          <span>
            <span class="block text-sm font-medium">JIT provision on SSO</span>
            <span class="mt-0.5 block text-xs text-muted-foreground">
              When on, create a local <code class="text-[11px]">member</code> account and link it
              automatically. When off, users must already exist (or bind via password within 15
              minutes). Providers without a verified email never JIT.
            </span>
          </span>
        </label>

        <div class="flex items-center gap-3">
          <UiButton size="sm" :disabled="ssoSaving" @click="onSaveSso">
            {{ ssoSaving ? "Saving…" : "Save" }}
          </UiButton>
          <span v-if="ssoSaved" class="text-xs text-muted-foreground">Saved</span>
        </div>
      </section>

      <section class="max-w-xl space-y-5 rounded-xl bg-card p-6 shadow-sm">
        <div>
          <h2 class="text-sm font-semibold tracking-tight">API tokens</h2>
          <p class="mt-1 text-xs text-muted-foreground">
            Bearer credentials for automation (<code class="text-[11px]">Authorization: Bearer
            …</code> on <code class="text-[11px]">/api/v1/admin/*</code>). A token acts as the
            account that created it: demoting or disabling that account, or revoking the token,
            cuts access on the next call.
          </p>
        </div>

        <!-- Shown once, then gone: the server stores only the digest. -->
        <div v-if="freshToken" class="space-y-2 rounded-lg border border-border/40 px-4 py-3">
          <p class="text-xs text-muted-foreground">
            Copy this token now — it is never shown again.
          </p>
          <code class="block break-all font-mono text-[12px]">{{ freshToken }}</code>
          <div class="flex gap-2">
            <UiButton size="sm" variant="secondary" @click="copyFreshToken">
              Copy
            </UiButton>
            <UiButton size="sm" variant="secondary" @click="freshToken = ''">
              Done
            </UiButton>
          </div>
        </div>

        <div class="space-y-2">
          <label class="type-label block" for="token-name">Token name</label>
          <div class="flex gap-2">
            <input
              id="token-name"
              v-model="newTokenName"
              type="text"
              class="field-input flex-1"
              placeholder="ci-pipeline"
              maxlength="100"
            />
            <input
              v-model="newTokenExpiryDays"
              type="number"
              min="1"
              max="3650"
              class="field-input w-36 text-right font-mono text-[12px]"
              placeholder="days (empty = never)"
            />
            <UiButton size="sm" :disabled="tokenWorking || !newTokenName.trim()" @click="onCreateToken">
              {{ tokenWorking ? "Working…" : "Create" }}
            </UiButton>
          </div>
        </div>

        <div v-if="apiTokens.length" class="space-y-2">
          <div
            v-for="t in apiTokens"
            :key="t.id"
            class="flex items-center gap-3 rounded-lg border border-border/40 px-4 py-3"
          >
            <span class="flex-1">
              <span class="block text-sm font-medium">
                {{ t.name }}
                <span
                  v-if="t.revoked_at"
                  class="ml-1 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                >revoked</span>
                <span
                  v-else-if="t.expires_at && new Date(t.expires_at) < new Date()"
                  class="ml-1 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                >expired</span>
              </span>
              <span class="mt-0.5 block text-xs text-muted-foreground">
                {{ t.user_email }} ·
                last used {{ t.last_used_at ? formatWhen(t.last_used_at) : "never" }} ·
                {{ t.expires_at ? `expires ${formatWhen(t.expires_at)}` : "no expiry" }}
              </span>
            </span>
            <UiButton
              v-if="!t.revoked_at"
              size="sm"
              variant="destructive"
              :disabled="tokenWorking"
              @click="onRevokeToken(t)"
            >
              Revoke
            </UiButton>
          </div>
        </div>
        <p v-else class="text-xs text-muted-foreground">No tokens yet.</p>
      </section>
    </template>
  </div>
</template>
