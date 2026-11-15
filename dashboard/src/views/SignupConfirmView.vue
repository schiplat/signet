<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import BrandLogo from "@/components/ui/BrandLogo.vue";
import UiButton from "@/components/ui/UiButton.vue";
import { confirmSignup } from "@/lib/api";
import { useBrandingStore } from "@/stores/branding";

const route = useRoute();
const router = useRouter();
const branding = useBrandingStore();

const token = ref("");
const submitting = ref(false);
const error = ref("");

onMounted(() => {
  // The email link carries the token in the fragment (`#token=…`), so the
  // browser never sends it to the server, an access log or a proxy. A query
  // fallback keeps hand-written links working.
  const fromHash = new URLSearchParams(route.hash.replace(/^#/, "")).get("token");
  token.value = fromHash || (typeof route.query.token === "string" ? route.query.token : "");
  if (!token.value) {
    error.value = "This link is missing its verification token.";
  }
});

/**
 * The confirmation is a button, not a page-load side effect: mail clients and
 * security scanners prefetch links, and a GET that created the account would
 * spend the single-use token before the recipient ever clicks.
 */
async function handleConfirm() {
  error.value = "";
  submitting.value = true;
  try {
    await confirmSignup(token.value);
    await router.replace({ name: "login", query: { signup: "verified" } });
  } catch (e) {
    error.value = e instanceof Error ? e.message : "Could not activate the account";
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
        <h1 class="text-lg font-semibold tracking-tight">Confirm your email</h1>
        <p class="type-meta">Activate your {{ branding.name }} account</p>
      </div>

      <div class="space-y-4">
        <p class="text-sm leading-relaxed text-muted-foreground">
          Confirm that you own this address to finish creating the account. The link works
          once and expires 30 minutes after the request.
        </p>
        <p v-if="error" class="field-error">{{ error }}</p>

        <UiButton
          type="button"
          class="w-full"
          :disabled="submitting || !token"
          @click="handleConfirm"
        >
          {{ submitting ? "Activating…" : "Activate account" }}
        </UiButton>

        <div class="space-y-2 text-center text-xs text-muted-foreground">
          <p>
            Already activated?
            <RouterLink to="/login" class="hover:text-foreground">Sign in</RouterLink>
          </p>
          <p v-if="error">
            Need a new link?
            <RouterLink to="/signup" class="hover:text-foreground">Start over</RouterLink>
          </p>
        </div>
      </div>
    </div>
  </div>
</template>
