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
  let started = false;

  async function load() {
    if (started) return;
    started = true;
    try {
      const res = await fetchBranding();
      if (res.name) name.value = res.name;
    } catch {
      /* keep the default */
    }
    document.title = name.value;
  }

  return { name, load };
});
