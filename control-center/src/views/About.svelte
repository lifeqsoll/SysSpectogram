<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, type AppInfo } from '../lib/api';
  import { t } from '../lib/i18n';

  let info = $state<AppInfo | null>(null);
  let error = $state<string | null>(null);

  onMount(async () => {
    try {
      info = await api.appInfo();
    } catch (e) {
      error = errorText(e);
    }
  });

  const DOCS = [
    'README.md',
    'docs/PRODUCT_v1.0.md',
    'docs/CONTROL_CENTER.md',
    'docs/adr/0001-fusion-gating.md',
    'docs/adr/0002-event-spectrogram.md',
    'docs/adr/0003-trust-labels.md',
    'docs/adr/0004-privilege-helper-split.md',
    'docs/adr/0005-signed-bundle-not-git.md',
    'docs/RELEASE_v1.0.0.md',
  ];
</script>

<h1>{t('about.title')}</h1>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}

<div class="grid-2">
  <div class="panel">
    <h2>SysSpectogram</h2>
    <p class="mono">{info?.version ?? '-'}</p>
    <p class="muted mono" style="font-size: 12px">{t('about.root')}: {info?.root ?? '-'}</p>
    <p class="muted mono" style="font-size: 12px">{t('about.socket')}: {info?.helper_socket ?? '-'}</p>
  </div>
  <div class="panel">
    <h2>{t('about.docs')}</h2>
    <ul class="mono" style="padding-left: 18px; margin: 0; font-size: 12.5px">
      {#each DOCS as d (d)}<li>{d}</li>{/each}
    </ul>
  </div>
</div>
