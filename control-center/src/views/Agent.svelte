<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, type Point } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtNum } from '../lib/format';
  import { live } from '../lib/live.svelte';
  import { ui } from '../lib/state.svelte';
  import { formatValue, type SettingEntry } from '../lib/settings';
  import Chart from '../lib/Chart.svelte';

  let entries = $state<SettingEntry[]>([]);
  let points = $state<Point[]>([]);
  let error = $state<string | null>(null);

  onMount(async () => {
    try {
      entries = (await api.settingsExport()).settings;
    } catch (e) {
      error = errorText(e);
    }
    try {
      points = await api.timeseriesQuery('agent_score', '1h');
    } catch (e) {
      error = errorText(e);
    }
  });

  const current = (key: string) => entries.find((e) => e.key === key)?.current;
  const agentScore = $derived(live.values.agent_score);
  function openSettings(): void {
    ui.section = 'settings';
  }
</script>

<h1>{t('agent.title')}</h1>
<p class="lead">{t('agent.lead')}</p>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}

<div class="cards">
  <div class="panel stat"><div class="label">{t('agent.mode')}</div><div class="value">{formatValue(current('agent.mode'))}</div></div>
  <div class="panel stat"><div class="label">{t('agent.halfLife')}</div><div class="value">{formatValue(current('agent.score_half_life_sec'))} s</div></div>
  <div class="panel stat"><div class="label">{t('agent.spectrogram')}</div><div class="value">{formatValue(current('agent.spectrogram'))}</div></div>
  <div class="panel stat"><div class="label">agent_score</div><div class="value">{fmtNum(agentScore?.value)}</div></div>
</div>

<div style="height: 16px"></div>
<div class="panel">
  <h2>{t('agent.score')}</h2>
  {#if points.length > 1}
    <Chart
      xs={points.map((p) => p.ts)}
      series={[{ label: 'agent_score', color: '#d6a24a', values: points.map((p) => p.avg) }]}
      height={230}
      yRange={[0, 1]}
    />
  {:else}
    <p class="muted">{t('dash.empty')}</p>
  {/if}
</div>

<div style="height: 14px"></div>
<button class="btn" onclick={openSettings}>{t('agent.open')}</button>
