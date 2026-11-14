<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { Check, Copy } from "@lucide/vue";
import UiButton from "./UiButton.vue";

export interface SecretDialogPayload {
  clientId: string;
  secret: string;
  title: string;
  client: {
    redirect_uris: string[];
    post_logout_redirect_uris?: string[];
    scopes: string[];
  };
}

const props = defineProps<{ dialog: SecretDialogPayload | null }>();
const emit = defineEmits<{ close: [] }>();

const copiedField = ref<"id" | "secret" | "both" | "config" | null>(null);
let copiedTimer: ReturnType<typeof setTimeout> | null = null;

// The issuer handed out with the onboarding config. The public discovery
// document is the one source of truth (an operator may have set a
// SIGNET_PUBLIC_BASE_URL different from the dashboard origin).
const issuer = ref("");
const configTab = ref<"env" | "toml">("env");

const envSnippet = computed(() => {
  const d = props.dialog;
  if (!d) return "";
  const lines = [
    `OIDC_ISSUER=${issuer.value || "https://sso.example.com"}`,
    `OIDC_CLIENT_ID=${d.clientId}`,
    `OIDC_CLIENT_SECRET=${d.secret}`,
    `OIDC_REDIRECT_URI=${d.client.redirect_uris[0] ?? ""}`,
    `OIDC_SCOPES=${(d.client.scopes || ["openid"]).join(" ")}`,
  ];
  const postLogout = d.client.post_logout_redirect_uris?.[0];
  if (postLogout) lines.push(`OIDC_POST_LOGOUT_REDIRECT_URI=${postLogout}`);
  return lines.join("\n");
});

const tomlSnippet = computed(() => {
  const d = props.dialog;
  if (!d) return "";
  const scopes = (d.client.scopes || ["openid"]).map((s) => JSON.stringify(s)).join(", ");
  const lines = [
    "[oidc]",
    `issuer = "${issuer.value || "https://sso.example.com"}"`,
    `client_id = "${d.clientId}"`,
    `client_secret = "${d.secret}"`,
    `redirect_uri = "${d.client.redirect_uris[0] ?? ""}"`,
    `scopes = [${scopes}]`,
  ];
  const postLogout = d.client.post_logout_redirect_uris?.[0];
  if (postLogout) lines.push(`post_logout_redirect_uri = "${postLogout}"`);
  return lines.join("\n");
});

onMounted(async () => {
  // Best-effort: the onboarding snippets need the issuer; discovery is public.
  try {
    const res = await fetch("/.well-known/openid-configuration");
    const doc = await res.json();
    if (typeof doc.issuer === "string") issuer.value = doc.issuer;
  } catch {
    /* fall back to the placeholder in the snippets */
  }
});

async function copyText(text: string, field: "id" | "secret" | "both" | "config") {
  try {
    await navigator.clipboard.writeText(text);
    copiedField.value = field;
    if (copiedTimer) clearTimeout(copiedTimer);
    copiedTimer = setTimeout(() => {
      copiedField.value = null;
    }, 1500);
  } catch {
    /* ignore */
  }
}

function copyBoth() {
  if (!props.dialog) return;
  const { clientId, secret } = props.dialog;
  void copyText(`client_id=${clientId}\nclient_secret=${secret}`, "both");
}
</script>

<template>
  <Teleport to="body">
    <div v-if="dialog" class="fixed inset-0 z-50 flex items-center justify-center">
      <div class="absolute inset-0 bg-black/30 backdrop-blur-sm" @click="emit('close')" />
      <div
        class="relative z-10 mx-4 w-full max-w-md rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
      >
        <h3 class="mb-2 text-[15px] font-semibold">{{ dialog.title }}</h3>
        <p class="type-meta mb-4">
          Copy the client secret now — it will not be shown again.
        </p>
        <div class="space-y-3">
          <div>
            <p class="type-label mb-1">Client ID</p>
            <div class="flex items-start gap-2 rounded-lg bg-muted px-3 py-2">
              <p class="min-w-0 flex-1 break-all font-mono text-xs">
                {{ dialog.clientId }}
              </p>
              <UiButton
                type="button"
                variant="ghost"
                size="icon"
                class="h-7 w-7 shrink-0"
                :title="copiedField === 'id' ? 'Copied' : 'Copy client ID'"
                @click="copyText(dialog.clientId, 'id')"
              >
                <Check v-if="copiedField === 'id'" class="h-3.5 w-3.5" />
                <Copy v-else class="h-3.5 w-3.5" />
              </UiButton>
            </div>
          </div>
          <div>
            <p class="type-label mb-1">Client Secret</p>
            <div class="flex items-start gap-2 rounded-lg bg-muted px-3 py-2">
              <p class="min-w-0 flex-1 break-all font-mono text-xs">
                {{ dialog.secret }}
              </p>
              <UiButton
                type="button"
                variant="ghost"
                size="icon"
                class="h-7 w-7 shrink-0"
                :title="copiedField === 'secret' ? 'Copied' : 'Copy client secret'"
                @click="copyText(dialog.secret, 'secret')"
              >
                <Check v-if="copiedField === 'secret'" class="h-3.5 w-3.5" />
                <Copy v-else class="h-3.5 w-3.5" />
              </UiButton>
            </div>
          </div>

          <div class="rounded-lg border border-border/50">
            <div class="flex items-center justify-between border-b border-border/30 px-3 py-2">
              <div class="flex gap-1 text-xs">
                <button
                  type="button"
                  class="rounded-md px-2 py-1"
                  :class="configTab === 'env' ? 'bg-muted font-medium' : 'text-muted-foreground'"
                  @click="configTab = 'env'"
                >
                  .env
                </button>
                <button
                  type="button"
                  class="rounded-md px-2 py-1"
                  :class="configTab === 'toml' ? 'bg-muted font-medium' : 'text-muted-foreground'"
                  @click="configTab = 'toml'"
                >
                  config.toml
                </button>
              </div>
              <UiButton
                type="button"
                variant="ghost"
                size="icon"
                class="h-7 w-7 shrink-0"
                :title="copiedField === 'config' ? 'Copied' : 'Copy snippet'"
                @click="copyText(configTab === 'env' ? envSnippet : tomlSnippet, 'config')"
              >
                <Check v-if="copiedField === 'config'" class="h-3.5 w-3.5" />
                <Copy v-else class="h-3.5 w-3.5" />
              </UiButton>
            </div>
            <pre class="max-h-56 overflow-auto px-3 py-2.5 font-mono text-[11px] leading-5">{{
              configTab === "env" ? envSnippet : tomlSnippet
            }}</pre>
            <p class="border-t border-border/30 px-3 py-2 text-[11px] text-muted-foreground">
              Hand this whole snippet to the subsystem — it already matches this client's
              registered redirect URIs, scopes and logout address. The secret appears only
              here and only once.
            </p>
          </div>
        </div>
        <div class="mt-6 flex justify-end gap-3 border-t border-border/30 pt-5">
          <UiButton type="button" variant="ghost" size="sm" @click="copyBoth">
            <Check v-if="copiedField === 'both'" class="h-3.5 w-3.5" />
            <Copy v-else class="h-3.5 w-3.5" />
            {{ copiedField === "both" ? "Copied" : "Copy ID + secret" }}
          </UiButton>
          <UiButton type="button" size="sm" @click="emit('close')">Done</UiButton>
        </div>
      </div>
    </div>
  </Teleport>
</template>
