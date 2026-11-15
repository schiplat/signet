<script setup lang="ts">
import { computed } from "vue";
import { useBrandingStore } from "@/stores/branding";

/**
 * The brand mark: the uploaded logo when one is configured, otherwise initials
 * derived from the product name (one word → first letter, two-plus words →
 * first letters of the first two).
 *
 * Every brand surface (sidebar, sign-in, setup, reset, consent) renders this
 * component so a logo change reaches all of them without touching each page.
 */
const props = withDefaults(defineProps<{ sizeClass?: string; muted?: boolean }>(), {
  sizeClass: "h-10 w-10",
  muted: false,
});

const branding = useBrandingStore();

const initials = computed(() => {
  const words = branding.name.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "S";
  if (words.length === 1) return words[0].slice(0, 1).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
});
</script>

<template>
  <img
    v-if="branding.logoUrl"
    :src="branding.logoUrl"
    alt=""
    class="shrink-0 rounded-xl object-contain"
    :class="props.sizeClass"
  />
  <span
    v-else
    class="flex shrink-0 items-center justify-center rounded-xl text-sm font-semibold tracking-wide"
    :class="[props.sizeClass, props.muted ? 'bg-muted text-muted-foreground' : 'bg-primary text-primary-foreground']"
  >
    {{ initials }}
  </span>
</template>
