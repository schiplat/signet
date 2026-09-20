<script setup lang="ts">
import { nextTick, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import UiButton from "@/components/ui/UiButton.vue";
import { fetchSetupStatus } from "@/lib/api";
import { useAuthStore } from "@/stores/auth";

const router = useRouter();
const auth = useAuthStore();

const email = ref("");
const displayName = ref("");
const password = ref("");
const confirm = ref("");
const showPassword = ref(false);
const error = ref("");
const loading = ref(false);

const emailInput = ref<HTMLInputElement | null>(null);

onMounted(async () => {
  await nextTick();
  emailInput.value?.focus();
});

onMounted(async () => {
  try {
    const status = await fetchSetupStatus();
    if (!status.needs_setup) {
      await router.replace("/login");
    }
  } catch {
    /* submit flow will surface errors */
  }
});

async function handleSubmit() {
  error.value = "";
  if (password.value !== confirm.value) {
    error.value = "Passwords do not match";
    return;
  }
  loading.value = true;
  try {
    await auth.completeSetup(
      email.value.trim(),
      password.value,
      displayName.value.trim() || undefined,
    );
    await router.replace("/overview");
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Setup failed";
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
        <h1 class="text-lg font-semibold tracking-tight">Welcome to Signet</h1>
        <p class="type-meta">Create the first administrator account</p>
      </div>

      <form class="space-y-4" @submit.prevent="handleSubmit">
        <div class="space-y-1.5">
          <label class="type-label">Email</label>
          <input
            ref="emailInput"
            v-model="email"
            type="email"
            autocomplete="username"
            placeholder="admin@example.com"
            class="field-input"
            required
          />
        </div>
        <div class="space-y-1.5">
          <label class="type-label">Display name <span class="text-muted-foreground">(optional)</span></label>
          <input
            v-model="displayName"
            type="text"
            autocomplete="name"
            placeholder="Administrator"
            class="field-input"
          />
        </div>
        <div class="space-y-1.5">
          <label class="type-label">Password</label>
          <div class="relative">
            <input
              v-model="password"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="new-password"
              placeholder="Enter password"
              class="field-input pr-14"
              required
            />
            <button
              type="button"
              class="absolute right-2 top-1/2 -translate-y-1/2 cursor-pointer text-[11px] text-muted-foreground transition-colors hover:text-foreground"
              @click="showPassword = !showPassword"
            >
              {{ showPassword ? "Hide" : "Show" }}
            </button>
          </div>
        </div>
        <div class="space-y-1.5">
          <label class="type-label">Confirm password</label>
          <input
            v-model="confirm"
            type="password"
            autocomplete="new-password"
            placeholder="Re-enter password"
            class="field-input"
            required
          />
        </div>
        <div v-if="error" class="field-error">{{ error }}</div>
        <UiButton type="submit" class="w-full" :disabled="loading">
          {{ loading ? "Creating…" : "Create administrator" }}
        </UiButton>
      </form>
    </div>
  </div>
</template>
