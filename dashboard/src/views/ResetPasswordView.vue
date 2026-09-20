<script setup lang="ts">
import { nextTick, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import UiButton from "@/components/ui/UiButton.vue";
import { confirmPasswordReset, requestPasswordReset } from "@/lib/api";

const route = useRoute();
const router = useRouter();

type Step = "request" | "confirm" | "done";

const step = ref<Step>("request");
const email = ref("");
const newPassword = ref("");
const confirmPassword = ref("");
const error = ref("");
const loading = ref(false);

const token = typeof route.query.token === "string" ? route.query.token : "";

if (token) {
  step.value = "confirm";
}

// --- Focus management ---
// Steps are rendered with `v-if`, so the target input only exists after the
// re-render triggered by `step` changing; focusing must wait for `nextTick`.
const emailInput = ref<HTMLInputElement | null>(null);
const newPasswordInput = ref<HTMLInputElement | null>(null);

const stepInputs: Partial<Record<Step, () => HTMLInputElement | null>> = {
  request: () => emailInput.value,
  confirm: () => newPasswordInput.value,
};

async function focusStepInput() {
  await nextTick();
  stepInputs[step.value]?.()?.focus();
}

watch(step, focusStepInput);
// `step` may already be "confirm" on mount (reset link with a token), and
// `watch` does not fire for the initial value.
onMounted(focusStepInput);

async function handleRequest() {
  error.value = "";
  loading.value = true;
  try {
    await requestPasswordReset(email.value.trim());
    step.value = "done";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Request failed";
  } finally {
    loading.value = false;
  }
}

async function handleConfirm() {
  error.value = "";
  const pw = newPassword.value;
  if (pw.length < 10 || !/[a-z]/.test(pw) || !/[A-Z]/.test(pw) || !/[0-9]/.test(pw)) {
    error.value = "Password must be at least 10 characters and include upper, lower case and a digit";
    return;
  }
  if (pw !== confirmPassword.value) {
    error.value = "Passwords do not match";
    return;
  }
  loading.value = true;
  try {
    await confirmPasswordReset(token, pw);
    step.value = "done";
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Reset failed";
  } finally {
    loading.value = false;
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background px-4">
    <div class="w-full max-w-sm space-y-6">
      <div class="space-y-1 text-center">
        <div class="mb-3 flex justify-center">
          <span
            class="flex h-10 w-10 items-center justify-center rounded-xl bg-primary text-sm font-semibold tracking-wide text-primary-foreground"
          >
            Sg
          </span>
        </div>
        <h1 class="text-lg font-semibold tracking-tight">Reset password</h1>
        <p class="type-meta">Recover access to your Signet account</p>
      </div>

      <form v-if="step === 'request'" class="space-y-4" @submit.prevent="handleRequest">
        <div class="space-y-1.5">
          <label class="type-label">Email or username</label>
          <input
            ref="emailInput"
            v-model="email"
            type="text"
            autocomplete="username"
            placeholder="you@example.com or username"
            class="field-input"
            required
          />
        </div>
        <p v-if="error" class="field-error">{{ error }}</p>
        <UiButton type="submit" class="w-full" :disabled="loading">
          {{ loading ? "Sending…" : "Send reset link" }}
        </UiButton>
      </form>

      <form v-else-if="step === 'confirm'" class="space-y-4" @submit.prevent="handleConfirm">
        <div class="space-y-1.5">
          <label class="type-label">New password</label>
          <input
            ref="newPasswordInput"
            v-model="newPassword"
            type="password"
            autocomplete="new-password"
            minlength="10"
            class="field-input"
            required
          />
          <p class="type-meta text-[11px]">10+ characters with upper, lower case and a digit.</p>
        </div>
        <div class="space-y-1.5">
          <label class="type-label">Confirm new password</label>
          <input
            v-model="confirmPassword"
            type="password"
            autocomplete="new-password"
            minlength="10"
            class="field-input"
            required
          />
        </div>
        <p v-if="error" class="field-error">{{ error }}</p>
        <UiButton type="submit" class="w-full" :disabled="loading">
          {{ loading ? "Resetting…" : "Reset password" }}
        </UiButton>
      </form>

      <div v-else class="space-y-4 text-center">
        <p class="text-sm text-muted-foreground">
          If an account exists for that address, a reset link has been sent.
        </p>
        <UiButton type="button" class="w-full" @click="router.push({ name: 'login' })">
          Back to sign in
        </UiButton>
      </div>
    </div>
  </div>
</template>
