<script setup lang="ts">
import { X } from "@lucide/vue";
import { onMounted, onUnmounted } from "vue";
import UiButton from "@/components/ui/UiButton.vue";
import { answerConfirm, pendingConfirm } from "@/lib/confirm";

/**
 * Renders the shared confirm dialog from `lib/confirm`. Mounted once, in
 * `App.vue`; every `confirm(…)` call site teleports into it.
 *
 * Escape means cancel — the native dialog's keyboard contract, kept so muscle
 * memory survives the swap.
 */
function onKeydown(e: KeyboardEvent) {
  if (e.key === "Escape" && pendingConfirm.value) {
    answerConfirm(false);
  }
}

onMounted(() => window.addEventListener("keydown", onKeydown));
onUnmounted(() => window.removeEventListener("keydown", onKeydown));
</script>

<template>
  <Teleport to="body">
    <Transition
      enter-active-class="transition-opacity duration-150"
      leave-active-class="transition-opacity duration-100"
      enter-from-class="opacity-0"
      leave-to-class="opacity-0"
    >
      <div
        v-if="pendingConfirm"
        class="fixed inset-0 z-[60] flex items-center justify-center p-4"
        role="alertdialog"
        aria-modal="true"
        :aria-label="pendingConfirm.options.title"
      >
        <div
          class="absolute inset-0 bg-black/40 backdrop-blur-sm"
          @click="answerConfirm(false)"
        />
        <div
          class="relative z-10 w-full max-w-sm rounded-2xl border border-border/50 bg-card p-6 shadow-2xl"
        >
          <button
            class="absolute right-4 top-4 rounded-lg p-1.5 text-muted-foreground transition-colors hover:bg-muted/30 hover:text-foreground"
            aria-label="Close"
            @click="answerConfirm(false)"
          >
            <X class="h-4 w-4" />
          </button>
          <h3 class="pr-6 text-[15px] font-semibold">
            {{ pendingConfirm.options.title }}
          </h3>
          <p
            v-if="pendingConfirm.options.message"
            class="mt-2 text-[13px] leading-relaxed text-muted-foreground"
          >
            {{ pendingConfirm.options.message }}
          </p>
          <div class="mt-6 flex justify-end gap-3">
            <UiButton variant="ghost" size="sm" @click="answerConfirm(false)">
              {{ pendingConfirm.options.cancelText ?? "Cancel" }}
            </UiButton>
            <UiButton
              :variant="pendingConfirm.options.danger ? 'destructive' : 'default'"
              size="sm"
              @click="answerConfirm(true)"
            >
              {{ pendingConfirm.options.confirmText ?? "Confirm" }}
            </UiButton>
          </div>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
