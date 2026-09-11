<script setup lang="ts">
import type { SsoProviderType } from "@/lib/api";

const props = defineProps<{
  type: SsoProviderType;
  /** Tailwind size classes, e.g. "h-11 w-11" */
  class?: string;
}>();

/** Brand marks live at `/sso-{type}.svg` (allogo). OIDC has no mark → letter badge. */
const BRAND_TYPES = new Set<SsoProviderType>(["feishu", "github", "google", "wechat"]);

const brandSrc = BRAND_TYPES.has(props.type) ? `/sso-${props.type}.svg` : null;
</script>

<template>
  <img
    v-if="brandSrc"
    :src="brandSrc"
    alt=""
    :class="['shrink-0 object-contain', $props.class ?? 'h-11 w-11']"
    width="48"
    height="48"
    draggable="false"
  />
  <span
    v-else
    :class="[
      'flex shrink-0 items-center justify-center rounded-xl bg-primary text-[11px] font-bold text-primary-foreground',
      $props.class ?? 'h-11 w-11',
    ]"
    aria-hidden="true"
  >
    ID
  </span>
</template>
