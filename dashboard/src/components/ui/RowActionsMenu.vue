<script setup lang="ts">
import { EllipsisVertical } from "@lucide/vue";
import { onUnmounted, ref, type Component } from "vue";
import UiButton from "./UiButton.vue";

export type RowActionItem = {
  key: string;
  label: string;
  icon?: Component;
  /** Renders the label in the destructive colour. */
  danger?: boolean;
  disabled?: boolean;
  /** A hairline above this item — used to set Delete apart. */
  separator?: boolean;
  title?: string;
};

const props = defineProps<{
  items: RowActionItem[];
  /** Tooltip/accessible name of the trigger button. */
  label?: string;
}>();

const emit = defineEmits<{ select: [key: string] }>();

const open = ref(false);
const pos = ref({ top: 0, left: 0 });
const menuRoot = ref<HTMLElement | null>(null);
const triggerEl = ref<HTMLElement | null>(null);

const MENU_WIDTH = 184; // w-46 equivalent

/// Places the menu against its trigger and reports whether the trigger is
/// still on screen. Re-run on scroll/resize instead of closing, so the menu
/// follows the row rather than vanishing mid-interaction (a click that scrolls
/// the row into view must not dismiss the menu it is about to use).
function position(trigger: HTMLElement): boolean {
  const rect = trigger.getBoundingClientRect();
  const left = Math.min(
    Math.max(8, rect.right - MENU_WIDTH),
    window.innerWidth - MENU_WIDTH - 8,
  );
  // 8px padding + ~36px per item + a separator line's worth of slack.
  const estimatedHeight = 16 + props.items.length * 36;
  const fitsBelow = rect.bottom + 4 + estimatedHeight <= window.innerHeight;
  pos.value = {
    top: fitsBelow ? rect.bottom + 4 : Math.max(8, rect.top - estimatedHeight - 4),
    left,
  };
  return rect.bottom > 0 && rect.top < window.innerHeight;
}

function onDocClick(e: MouseEvent) {
  if (!open.value) return;
  const target = e.target as Node;
  if (menuRoot.value?.contains(target)) return;
  // The trigger runs its own toggle; closing here would make it a no-op.
  if (triggerEl.value?.contains(target)) return;
  close();
}

function onKeydown(e: KeyboardEvent) {
  if (e.key === "Escape") close();
}

function onViewportChange() {
  const trigger = triggerEl.value;
  if (!open.value || !trigger) return;
  if (!position(trigger)) close();
}

function attach() {
  // Capture phase: the click that opened the menu has already passed document
  // capture, so it cannot close the menu in the same dispatch.
  document.addEventListener("click", onDocClick, true);
  document.addEventListener("keydown", onKeydown);
  window.addEventListener("scroll", onViewportChange, true);
  window.addEventListener("resize", onViewportChange);
}

function detach() {
  document.removeEventListener("click", onDocClick, true);
  document.removeEventListener("keydown", onKeydown);
  window.removeEventListener("scroll", onViewportChange, true);
  window.removeEventListener("resize", onViewportChange);
}

function toggle(event: MouseEvent) {
  if (open.value) {
    close();
    return;
  }
  triggerEl.value = event.currentTarget as HTMLElement;
  position(triggerEl.value);
  open.value = true;
  attach();
}

function close() {
  if (!open.value) return;
  open.value = false;
  triggerEl.value = null;
  detach();
}

function choose(item: RowActionItem) {
  if (item.disabled) return;
  close();
  emit("select", item.key);
}

// A row can disappear (refresh after another row's action) while its menu is
// open; the document/window listeners must not outlive the component.
onUnmounted(detach);
</script>

<template>
  <UiButton
    variant="ghost"
    size="icon"
    :title="label ?? 'More actions'"
    aria-haspopup="menu"
    :aria-expanded="open"
    @click="toggle"
  >
    <EllipsisVertical class="h-4 w-4" />
  </UiButton>

  <Teleport to="body">
    <div
      v-if="open"
      ref="menuRoot"
      role="menu"
      class="fixed z-[55] overflow-hidden rounded-xl border border-border bg-background py-1 shadow-lg"
      :style="{ top: `${pos.top}px`, left: `${pos.left}px`, width: `${MENU_WIDTH}px` }"
    >
      <button
        v-for="item in items"
        :key="item.key"
        type="button"
        role="menuitem"
        class="flex w-full items-center gap-2 px-3 py-2 text-left text-[13px] hover:bg-muted disabled:cursor-default disabled:opacity-50 disabled:hover:bg-transparent"
        :class="[
          item.danger ? 'text-destructive hover:bg-destructive/10' : 'text-foreground',
          item.separator && 'border-t border-border/40',
        ]"
        :disabled="item.disabled"
        :title="item.title"
        @click="choose(item)"
      >
        <component
          :is="item.icon"
          v-if="item.icon"
          class="h-3.5 w-3.5 shrink-0"
          :class="item.danger ? '' : 'text-muted-foreground'"
        />
        <span class="truncate">{{ item.label }}</span>
      </button>
    </div>
  </Teleport>
</template>
