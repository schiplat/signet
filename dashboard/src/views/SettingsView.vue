<script setup lang="ts">
import { onMounted, ref } from "vue";
import PageHeader from "@/components/ui/PageHeader.vue";
import UiButton from "@/components/ui/UiButton.vue";
import {
  fetchMfaSettings,
  fetchSsoSettings,
  updateMfaSettings,
  updateSsoSettings,
} from "@/lib/api";

const loading = ref(true);
const error = ref("");

const mfaSaving = ref(false);
const mfaSaved = ref(false);
const requiredGlobally = ref(false);

const ssoSaving = ref(false);
const ssoSaved = ref(false);
const jitProvision = ref(false);

onMounted(async () => {
  try {
    const [mfa, sso] = await Promise.all([fetchMfaSettings(), fetchSsoSettings()]);
    requiredGlobally.value = mfa.required_globally;
    jitProvision.value = sso.jit_provision;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Failed to load settings";
  } finally {
    loading.value = false;
  }
});

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
