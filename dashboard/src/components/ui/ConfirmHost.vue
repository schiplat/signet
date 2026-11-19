<script setup lang="ts">
import { X } from "@lucide/vue";
import { nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import UiButton from "@/components/ui/UiButton.vue";
import { answerConfirm, pendingConfirm } from "@/lib/confirm";
import { lockScroll, unlockScroll } from "@/composables/useDialog";

/**
 * Renders the shared confirm dialog from `lib/confirm`. Mounted once, in
 * `App.vue`; every `confirm(…)` call site teleports into it.
 *
 * Escape means cancel — the native dialog's keyboard contract, kept so muscle
 * memory survives the swap.
 *
 * While open it also locks the page scroll (the shared counted lock: a confirm
 * can be raised over another dialog, and whichever closes first must not
 * un-scroll the page beneath the other), moves focus onto Cancel (the
 * non-destructive choice: Enter must not confirm a delete by reflex), returns
 * focus to whatever was focused when it closes, and keeps Tab inside.
 */

const panelEl = ref<HTMLElement | null>(null);
let previouslyFocused: HTMLElement | null = null;

function onKeydown(e: KeyboardEvent) {
  if (!pendingConfirm.value) return;

  if (e.key === "Escape") {
    answerConfirm(false);
    return;
  }
  if (e.key !== "Tab") return;

  const panel = panelEl.value;
  if (!panel) return;
  const nodes = Array.from(
    panel.querySelectorAll<HTMLElement>("button:not([disabled])"),
  );
  if (nodes.length === 0) {
    e.preventDefault();
    panel.focus();
    return;
  }
  const first = nodes[0];
  const last = nodes[nodes.length - 1];
  const active = document.activeElement;
  if (e.shiftKey) {
    if (active === first || !panel.contains(active)) {
      e.preventDefault();
      last.focus();
    }
  } else if (active === last || !panel.contains(active)) {
    e.preventDefault();
    first.focus();
  }
}

/* The dialog is created and destroyed by a ref mutation, not a mount, so the
 * open/close edge is the watcher — not onMounted/onUnmounted. */
watch(pendingConfirm, (pending) => {
  if (pending) {
    previouslyFocused = document.activeElement as HTMLElement | null;
    lockScroll();
    void nextTick(() => {
      // Focus lands on Cancel, not Confirm: Enter must not confirm a delete
      // by reflex. The mark sits on the button because a ref on a component
      // yields the component instance, not the rendered <button>.
      panelEl.value
        ?.querySelector<HTMLElement>("[data-cancel]")
        ?.focus();
    });
    return;
  }
  unlockScroll();
  const target = previouslyFocused;
  previouslyFocused = null;
  if (target && target.isConnected) target.focus();
});

onMounted(() => window.addEventListener("keydown", onKeydown));
onUnmounted(() => {
  window.removeEventListener("keydown", onKeydown);
  unlockScroll();
});
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
          ref="panelEl"
          tabindex="-1"
          class="relative z-10 w-full max-w-sm rounded-2xl border border-border/50 bg-card p-6 shadow-2xl focus:outline-none"
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
            <UiButton data-cancel variant="ghost" size="sm" @click="answerConfirm(false)">
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
