<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, RANGES, type Point, type Range } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtNum, fmtTime } from '../lib/format';
  import { ui } from '../lib/state.svelte';
  import Chart from '../lib/Chart.svelte';

  const METRICS = [
    'host_risk',
    'host_score',
    'agent_score',
    'cpu_percent',
    'mem_percent',
    'swap_percent',
    'net_bytes_recv_per_s',
    'net_bytes_sent_per_s',
    'disk_read_bytes_per_s',
    'disk_write_bytes_per_s',
    'gpu_util_percent',
    'gpu_mem_percent',
  ];

  let metric = $state('host_risk');
  let available = $state<string[]>([]);
  let points = $state<Point[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(false);

  async function load(m: string, r: Range): Promise<void> {
    loading = true;
    error = null;
    try {
      points = await api.timeseriesQuery(m, r);
    } catch (e) {
      error = errorText(e);
      points = [];
    } finally {
      loading = false;
    }
  }

  onMount(async () => {
    try {
      available = await api.timeseriesMetrics();
    } catch {
      available = [];
    }
  });

  // Re-query on metric/range change and poll: fast for 1 h, slower for longer ranges.
  $effect(() => {
    const m = metric;
    const r = ui.range;
    const period = r === '1h' ? 5000 : 60000;
    load(m, r);
    const timer = setInterval(() => load(m, r), period);
    return () => clearInterval(timer);
  });

  const summary = $derived.by(() => {
    if (points.length === 0) return null;
    const avg = points.reduce((s, p) => s + p.avg * p.n, 0) / Math.max(1, points.reduce((s, p) => s + p.n, 0));
    return {
      avg,
      min: Math.min(...points.map((p) => p.min)),
      max: Math.max(...points.map((p) => p.max)),
      n: points.reduce((s, p) => s + p.n, 0),
    };
  });

  const choices = $derived(METRICS.filter((m) => available.length === 0 || available.includes(m)));
</script>

<h1>{t('dash.title')}</h1>
<p class="lead">{t('dash.lead')}</p>

<div class="row" style="margin-bottom: 14px">
  <div class="field">
    <label for="metric" class="muted">{t('dash.metric')}</label>
    <select id="metric" bind:value={metric}>
      {#each choices as m (m)}
        <option value={m}>{m}</option>
      {/each}
    </select>
  </div>
  <div class="field">
    <span class="muted">{t('dash.range')}</span>
    <div class="segmented">
      {#each RANGES as r (r)}
        <button class:active={ui.range === r} onclick={() => (ui.range = r as Range)}>{r}</button>
      {/each}
    </div>
  </div>
  <div class="spacer"></div>
  <button class="btn" onclick={() => load(metric, ui.range)} disabled={loading}>{t('common.refresh')}</button>
</div>

{#if error}
  <div class="notice error">{error}</div>
  <div style="height: 14px"></div>
{/if}

<div class="panel">
  {#if points.length > 1}
    <Chart
      xs={points.map((p) => p.ts)}
      series={[
        { label: t('dash.avg'), color: '#4fb3a5', values: points.map((p) => p.avg) },
        { label: t('dash.min'), color: '#8593a0', values: points.map((p) => p.min), dash: [3, 3] },
        { label: t('dash.max'), color: '#d6a24a', values: points.map((p) => p.max), dash: [3, 3] },
      ]}
      height={340}
    />
  {:else}
    <p class="muted">{t('dash.empty')}</p>
  {/if}
</div>

{#if summary}
  <div style="height: 16px"></div>
  <div class="cards">
    <div class="panel stat"><div class="label">{t('dash.avg')}</div><div class="value">{fmtNum(summary.avg)}</div></div>
    <div class="panel stat"><div class="label">{t('dash.min')}</div><div class="value">{fmtNum(summary.min)}</div></div>
    <div class="panel stat"><div class="label">{t('dash.max')}</div><div class="value">{fmtNum(summary.max)}</div></div>
    <div class="panel stat"><div class="label">{t('dash.samples')}</div><div class="value">{summary.n}</div>
      <div class="age">{fmtTime(points[0].ts)}</div></div>
  </div>
{/if}
