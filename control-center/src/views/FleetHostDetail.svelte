<script lang="ts">
  import { onMount } from 'svelte';
  import { fleet, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { clearLiveHistory } from '../lib/live.svelte';
  import { setActiveHost } from '../lib/state.svelte';
  import Charts from './Charts.svelte';

  let {
    hostId,
    hostLabel = '',
    onBack,
  }: {
    hostId: string;
    hostLabel?: string;
    onBack: () => void;
  } = $props();

  type Tab = 'charts' | 'status' | 'incidents';
  let tab = $state<Tab>('charts');
  let statusJson = $state('');
  let incidents = $state<Record<string, unknown>[]>([]);
  let err = $state<string | null>(null);
  let busy = $state(false);

  async function loadStatus(): Promise<void> {
    busy = true;
    err = null;
    try {
      const r = await fleet.status(hostId);
      statusJson = JSON.stringify(r, null, 2);
    } catch (e) {
      err = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function loadIncidents(): Promise<void> {
    busy = true;
    err = null;
    try {
      const r = await fleet.incidents(hostId, 40);
      incidents = ((r.items as Record<string, unknown>[]) ?? []).slice(0, 40);
    } catch (e) {
      err = errorText(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    setActiveHost(hostId);
    clearLiveHistory();
    void loadStatus();
  });

  $effect(() => {
    if (tab === 'status') void loadStatus();
    if (tab === 'incidents') void loadIncidents();
  });
</script>

<section class="host-detail">
  <div class="row" style="margin-bottom: 12px">
    <button type="button" class="ghost" onclick={onBack}>{t('fleet.hostBack')}</button>
    <h1 style="margin: 0; font-size: 18px">
      {hostLabel || hostId}
      <span class="mono muted" style="font-size: 12px"> · {hostId}</span>
    </h1>
  </div>

  <div class="segmented" style="margin-bottom: 14px">
    <button class:active={tab === 'charts'} onclick={() => (tab = 'charts')}>{t('fleet.hostTabCharts')}</button>
    <button class:active={tab === 'status'} onclick={() => (tab = 'status')}>{t('fleet.hostTabStatus')}</button>
    <button class:active={tab === 'incidents'} onclick={() => (tab = 'incidents')}>{t('fleet.hostTabIncidents')}</button>
  </div>

  {#if err}<div class="notice error" style="margin-bottom: 12px">{err}</div>{/if}
  {#if busy}<p class="muted">{t('common.loading')}</p>{/if}

  {#if tab === 'charts'}
    <Charts embedded={true} />
  {:else if tab === 'status'}
    <pre class="log">{statusJson || '—'}</pre>
  {:else}
    <ul class="incidents">
      {#each incidents as row}
        <li class="mono">
          {String(row.rule_id || row.reason || row.id || JSON.stringify(row).slice(0, 100))}
        </li>
      {/each}
      {#if !incidents.length && !busy}
        <li class="muted">—</li>
      {/if}
    </ul>
  {/if}
</section>

<style>
  .host-detail .incidents {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  .host-detail .incidents li {
    padding: 6px 0;
    border-bottom: 1px solid rgba(148, 178, 230, 0.12);
    font-size: 12px;
  }
</style>
