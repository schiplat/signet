import { ref } from "vue";
import { fetchCaptchaChallenge } from "@/lib/api";

/**
 * The CAPTCHA widget lifecycle for the unauthenticated forms.
 *
 * Both supported providers expose the same two globals once their script
 * loads: a `render(el, { sitekey, callback })` and a `reset(widgetId)`. The
 * composable hides which one is behind the page — the view renders a
 * placeholder div, calls `mount()`, and reads `token` when submitting.
 *
 * A consumed token is single-use: after a failed login (or before a second
 * submit) call `reset()`, or the provider will refuse the replay.
 */

export type CaptchaProvider = "turnstile" | "hcaptcha";

const SCRIPT_URLS: Record<CaptchaProvider, string> = {
  turnstile: "https://challenges.cloudflare.com/turnstile/v0/api.js",
  hcaptcha: "https://js.hcaptcha.com/1/api.js",
};

const GLOBALS: Record<CaptchaProvider, string> = {
  turnstile: "turnstile",
  hcaptcha: "hcaptcha",
};

type Renderer = {
  render: (el: HTMLElement, opts: Record<string, unknown>) => string;
  reset: (id: string) => void;
};

/** One script element per provider, shared across mounts. */
const loaded = new Map<CaptchaProvider, Promise<void>>();

function loadScript(provider: CaptchaProvider): Promise<void> {
  let existing = loaded.get(provider);
  if (!existing) {
    existing = new Promise((resolve, reject) => {
      const el = document.createElement("script");
      el.src = SCRIPT_URLS[provider];
      el.async = true;
      el.onload = () => resolve();
      el.onerror = () => reject(new Error("failed to load the CAPTCHA widget script"));
      document.head.appendChild(el);
    });
    loaded.set(provider, existing);
  }
  return existing;
}

function renderer(provider: CaptchaProvider): Renderer {
  const name = GLOBALS[provider];
  const global = window as unknown as Record<string, Renderer | undefined>;
  const r = global[name];
  if (!r) throw new Error("the CAPTCHA widget script has not loaded");
  return r;
}

export function useCaptcha() {
  const enabled = ref(false);
  const provider = ref<CaptchaProvider | null>(null);
  const token = ref("");
  const failed = ref(false);
  let widgetId = "";
  let lastEl: HTMLElement | null = null;

  /** Fetches the challenge config and renders the widget into `el`. */
  async function mount(el: HTMLElement) {
    // Same placeholder already rendered? The step watcher can call this
    // repeatedly; re-render only when the element actually changed (the v-if
    // unmount throws the old widget away with its div).
    if (lastEl === el) return;
    lastEl = el;
    token.value = "";
    const challenge = await fetchCaptchaChallenge();
    if (!challenge.enabled || !challenge.site_key) {
      enabled.value = false;
      return;
    }
    provider.value = challenge.provider as CaptchaProvider;
    await loadScript(provider.value);
    const id = renderer(provider.value).render(el, {
      sitekey: challenge.site_key,
      callback: (t: string) => {
        token.value = t;
        failed.value = false;
      },
      "error-callback": () => {
        failed.value = true;
        token.value = "";
      },
      "expired-callback": () => {
        token.value = "";
      },
    });
    widgetId = id;
    enabled.value = true;
  }

  /** The token for the next request, or null when the widget has none yet. */
  function take(): string | null {
    if (!enabled.value) return null;
    return token.value || null;
  }

  /** A used token cannot be replayed; start a fresh challenge. */
  function reset() {
    token.value = "";
    failed.value = false;
    if (enabled.value && provider.value && widgetId) {
      try {
        renderer(provider.value).reset(widgetId);
      } catch {
        /* the widget may have unmounted with the view */
      }
    }
  }

  return { enabled, provider, failed, mount, take, reset };
}
