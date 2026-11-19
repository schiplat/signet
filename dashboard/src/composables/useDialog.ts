import { nextTick, onUnmounted, watch, type Ref } from "vue";

/**
 * Shared open/close behaviour for the dashboard's hand-written dialogs.
 *
 * The dashboard's dialogs each own their markup (width, padding and scroll
 * rules differ per screen), so this composable carries only the part that is
 * easy to forget and miserable to get wrong:
 *
 * - a counted body-scroll lock: a confirm can be raised on top of a dialog,
 *   and a boolean lock would let whichever closes first un-scroll the page
 *   beneath the other. Scrollbar width is replaced with padding so centred
 *   layouts do not jump sideways when the bar disappears;
 * - focus moved into the panel on open (first field, else the panel itself so
 *   the accessible name is announced), and back to the trigger on close;
 * - a Tab-containment key handler, returned for the panel's `@keydown`.
 *
 * Escape is deliberately not handled here: whether Escape closes a dialog is
 * that dialog's policy (the secret-reveal dialog must not lose a one-time
 * secret to a stray keypress). Bind `@keydown.esc` alongside `onKeydown` when
 * Escape should close.
 *
 * ```
 * const panel = ref<HTMLElement | null>(null);
 * const a11y = useDialog(panel, computed(() => !!detail));
 * <div ref="panel" role="dialog" aria-modal="true" tabindex="-1"
 *      aria-label="Audit event detail" @keydown="a11y.onKeydown">
 * ```
 */

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), ' +
  'select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

const FIELD =
  'input:not([disabled]):not([type="hidden"]), ' +
  'select:not([disabled]), textarea:not([disabled])';

let lockDepth = 0;
let savedOverflow = "";
let savedPaddingRight = "";

function lockScroll() {
  if (lockDepth === 0) {
    savedOverflow = document.body.style.overflow;
    savedPaddingRight = document.body.style.paddingRight;
    const scrollbar = window.innerWidth - document.documentElement.clientWidth;
    document.body.style.overflow = "hidden";
    if (scrollbar > 0) {
      document.body.style.paddingRight = `${scrollbar}px`;
    }
  }
  lockDepth += 1;
}

function unlockScroll() {
  lockDepth = Math.max(0, lockDepth - 1);
  if (lockDepth === 0) {
    document.body.style.overflow = savedOverflow;
    document.body.style.paddingRight = savedPaddingRight;
  }
}

function isVisible(el: HTMLElement): boolean {
  return el.getClientRects().length > 0;
}

export function useDialog(panel: Ref<HTMLElement | null>, isOpen: Ref<unknown>) {
  let previouslyFocused: HTMLElement | null = null;

  function focusFirst() {
    const el = panel.value;
    if (!el) return;
    const field = Array.from(el.querySelectorAll<HTMLElement>(FIELD)).filter(isVisible)[0];
    (field ?? el).focus();
  }

  /** Tab containment. Bind on the panel: `@keydown="a11y.onKeydown"`. */
  function onKeydown(e: KeyboardEvent) {
    if (e.key !== "Tab") return;
    const el = panel.value;
    if (!el) return;
    const nodes = Array.from(el.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(isVisible);
    if (nodes.length === 0) {
      e.preventDefault();
      el.focus();
      return;
    }
    const first = nodes[0];
    const last = nodes[nodes.length - 1];
    const active = document.activeElement;
    if (e.shiftKey) {
      if (active === first || !el.contains(active)) {
        e.preventDefault();
        last.focus();
      }
    } else if (active === last || !el.contains(active)) {
      e.preventDefault();
      first.focus();
    }
  }

  watch(isOpen, (open) => {
    if (open) {
      previouslyFocused = document.activeElement as HTMLElement | null;
      lockScroll();
      void nextTick(focusFirst);
      return;
    }
    unlockScroll();
    const target = previouslyFocused;
    previouslyFocused = null;
    if (target && target.isConnected) target.focus();
  });

  onUnmounted(() => {
    if (isOpen.value) unlockScroll();
  });

  return { onKeydown };
}
