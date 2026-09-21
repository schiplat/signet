<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import {
  fetchMfaSettings,
  fetchSignInSettings,
  fetchSsoSettings,
  me,
  updateMfaSettings,
  updateSignInSettings,
  updateSsoSettings,
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
    const [mfa, sso, signIn, who] = await Promise.all([
      fetchMfaSettings(),
      fetchSsoSettings(),
      fetchSignInSettings(),
      me(),
    ]);
    requiredGlobally.value = mfa.required_globally;
    jitProvision.value = sso.jit_provision;
    allowlistInput.value = joinList(signIn.allowed_email_domains);
    allowlistOrigin.value = signIn.origin;
    ownEmail.value = who.user.email;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load settings";
  } finally {
    loading.value = false;
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
    </template>
  </div>
</template>
