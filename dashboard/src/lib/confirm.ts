import { ref } from "vue";

/**
 * A promise-based in-app confirm dialog.
 *
 * `window.confirm` cannot be styled, blocks the whole tab, and renders its text
 * with the system font — visibly off-brand inside the dashboard. This module
 * keeps the same call shape (`if (!(await confirm(…))) return;`) so call sites
 * read as before, while the dialog itself is the `ConfirmHost` component that
 * `App.vue` mounts once.
 *
 * One dialog at a time: a second `confirm` while one is open resolves the
 * first as cancelled, which is what a blocked native dialog would have
 * implied anyway.
 */

export type ConfirmOptions = {
  title: string;
  /** Body text under the title. */
  message?: string;
  /** Label of the confirming button. Defaults to "Confirm". */
  confirmText?: string;
  /** Label of the dismissing button. Defaults to "Cancel". */
  cancelText?: string;
  /**
   * Marks the confirming button destructive. Set for anything that removes,
   * freezes or rotates — the visual "this cannot be casually undone" cue the
   * native dialog has no room for.
   */
  danger?: boolean;
};

type Pending = {
  options: ConfirmOptions;
  resolve: (ok: boolean) => void;
};

export const pendingConfirm = ref<Pending | null>(null);

/** Shared confirm dialog. Resolves true when the operator confirms. */
export function confirm(options: ConfirmOptions): Promise<boolean> {
  if (pendingConfirm.value) {
    pendingConfirm.value.resolve(false);
  }
  return new Promise((resolve) => {
    pendingConfirm.value = { options, resolve };
  });
}

/** Internal: resolves the open dialog. Used by `ConfirmHost`. */
export function answerConfirm(ok: boolean) {
  if (!pendingConfirm.value) return;
  pendingConfirm.value.resolve(ok);
  pendingConfirm.value = null;
}
