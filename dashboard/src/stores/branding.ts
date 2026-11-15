import { defineStore } from "pinia";
import { ref } from "vue";
import { fetchBranding } from "@/lib/api";

/**
 * The product name the instance shows about itself.
 *
 * Loaded once per session from the unauthenticated `/api/v1/branding` and
 * applied to the document title; every brand surface (sign-in, reset, setup,
 * sidebar) binds to the store instead of hardcoding "Signet". A load failure
 * keeps the default — the sign-in page must not depend on this endpoint.
 */
export const useBrandingStore = defineStore("branding", () => {
  const name = ref("Signet");
  /** Versioned logo URL from the public branding endpoint; null = initials. */
  const logoUrl = ref<string | null>(null);
  let started = false;

  async function load() {
    if (started) return;
    started = true;
    try {
      const res = await fetchBranding();
      if (res.name) name.value = res.name;
      logoUrl.value = res.logo_url ?? null;
    } catch {
      /* keep the default */
    }
    // The router composes "<page> · <name>"; a late load must only replace the
    // brand part, never drop the page prefix.
    const suffix = " · Signet";
    if (document.title.endsWith(suffix)) {
      document.title = document.title.slice(0, -suffix.length) + ` · ${name.value}`;
    } else if (document.title === "Signet" || document.title === "Signet · Identity") {
      document.title = name.value;
    }
  }

  return { name, logoUrl, load };
});
