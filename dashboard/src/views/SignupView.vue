<script setup lang="ts">
import { computed, nextTick, onMounted, ref } from "vue";
import { useRouter } from "vue-router";
import BrandLogo from "@/components/ui/BrandLogo.vue";
import UiButton from "@/components/ui/UiButton.vue";
import { fetchSignupStatus, signup, type SignupStatus } from "@/lib/api";
import { useCaptcha } from "@/composables/useCaptcha";
import { useBrandingStore } from "@/stores/branding";

const router = useRouter();
const branding = useBrandingStore();

const status = ref<SignupStatus | null>(null);
const loadingStatus = ref(true);
const loadError = ref("");

const displayName = ref("");
const email = ref("");
const password = ref("");
const confirmPassword = ref("");
const showPassword = ref(false);
const submitting = ref(false);
const error = ref("");
const done = ref(false);

const captchaHost = ref<HTMLElement | null>(null);
const captcha = useCaptcha();

const minPasswordLength = computed(() => status.value?.min_password_length ?? 10);
const allowedDomains = computed(() => status.value?.allowed_email_domains ?? []);

async function mountCaptcha() {
  if (!captchaHost.value || !status.value?.enabled) return;
  try {
    await captcha.mount(captchaHost.value);
  } catch {
    /* A broken widget script must not hide the form; the server refuses the
       request with a clear message if the gate is actually on. */
  }
}

onMounted(async () => {
  try {
    status.value = await fetchSignupStatus();
  } catch (e) {
    loadError.value =
      e instanceof Error ? e.message : "Could not load the sign-up form";
  } finally {
    loadingStatus.value = false;
  }
  await nextTick();
  await mountCaptcha();
});

async function handleSubmit() {
  error.value = "";
  if (password.value !== confirmPassword.value) {
    error.value = "Passwords do not match";
    return;
  }
  if (password.value.length < minPasswordLength.value) {
    error.value = `Password must be at least ${minPasswordLength.value} characters`;
    return;
  }
  submitting.value = true;
  try {
    await signup({
      email: email.value.trim(),
      password: password.value,
      display_name: displayName.value.trim() || undefined,
      captcha_token: captcha.take() ?? undefined,
    });
    captcha.reset();
    // Generic on purpose: this screen must not reveal whether the address was
    // new, already registered, or had a request in flight.
    done.value = true;
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Sign-up failed";
    captcha.reset();
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <div class="flex min-h-screen items-center justify-center bg-background px-4">
    <div class="w-full max-w-sm space-y-6">
      <div class="space-y-1 text-center">
        <div class="mb-3 flex justify-center">
          <BrandLogo size-class="h-10 w-10" />
        </div>
        <h1 class="text-lg font-semibold tracking-tight">Create your account</h1>
        <p class="type-meta">Sign up for {{ branding.name }}</p>
      </div>

      <div v-if="loadingStatus" class="py-8 text-center text-sm text-muted-foreground">
        Loading…
      </div>

      <div v-else-if="loadError" class="space-y-4 text-center">
        <p class="field-error">{{ loadError }}</p>
        <UiButton class="w-full" @click="router.push({ name: 'login' })">
          Back to sign in
        </UiButton>
      </div>

      <div v-else-if="!status?.enabled" class="space-y-4 text-center">
        <p class="text-sm text-muted-foreground">
          Public sign-up is not available on this instance. Ask an administrator for an
          account, or sign in if you already have one.
        </p>
        <UiButton class="w-full" @click="router.push({ name: 'login' })">
          Back to sign in
        </UiButton>
      </div>

      <div v-else-if="done" class="space-y-4 text-center">
        <p class="text-sm text-muted-foreground">
          If this address can be registered, a verification link is on its way. Open it to
          activate your account. Check your spam folder if it does not arrive within a few
          minutes.
        </p>
        <UiButton class="w-full" @click="router.push({ name: 'login' })">
          Back to sign in
        </UiButton>
      </div>

      <form v-else class="space-y-4" @submit.prevent="handleSubmit">
        <div class="space-y-1.5">
          <label class="type-label">Display name <span class="font-normal opacity-60">(optional)</span></label>
          <input
            v-model="displayName"
            type="text"
            autocomplete="name"
            maxlength="100"
            placeholder="Ada Lovelace"
            class="field-input"
          />
        </div>

        <div class="space-y-1.5">
          <label class="type-label">Email</label>
          <input
            v-model="email"
            type="email"
            autocomplete="email"
            placeholder="you@example.com"
            class="field-input"
            required
          />
          <p v-if="allowedDomains.length" class="type-meta text-[11px]">
            Only these domains can register: {{ allowedDomains.join(", ") }}
          </p>
        </div>

        <div class="space-y-1.5">
          <label class="type-label">Password</label>
          <div class="relative">
            <input
              v-model="password"
              :type="showPassword ? 'text' : 'password'"
              autocomplete="new-password"
              :minlength="minPasswordLength"
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
          <p class="type-meta text-[11px]">
            At least {{ minPasswordLength }} characters with upper and lower case and a digit.
          </p>
        </div>

        <div class="space-y-1.5">
          <label class="type-label">Confirm password</label>
          <input
            v-model="confirmPassword"
            :type="showPassword ? 'text' : 'password'"
            autocomplete="new-password"
            :minlength="minPasswordLength"
            class="field-input"
            required
          />
        </div>

        <p v-if="error" class="field-error">{{ error }}</p>
        <!-- Renders only when a provider is configured (see useCaptcha). -->
        <div v-show="captcha.enabled.value" ref="captchaHost" class="flex justify-center" />

        <UiButton type="submit" class="w-full" :disabled="submitting">
          {{ submitting ? "Creating account…" : "Create account" }}
        </UiButton>

        <div class="text-center">
          <RouterLink
            to="/login"
            class="text-xs text-muted-foreground hover:text-foreground"
          >
            Already have an account? Sign in
          </RouterLink>
        </div>
      </form>
    </div>
  </div>
</template>
