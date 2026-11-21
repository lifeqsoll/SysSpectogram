<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, RANGES, type Point, type Range } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtNum, fmtTime } from '../lib/format';
  import { ui } from '../lib/state.svelte';
  import {
    CHART_POLL_MS,
    DETAIL_MAX_POINTS,
    fetchSeries,
    pageVisible,
  } from '../lib/timeseriesPoll.svelte';
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
  let inFlight = false;
  let loadGen = 0;
  let hadFullLoad = false;
  /** Chart only mounts after the selected metric’s series is ready. */
  let chartReady = $state(false);

  async function load(m: string, r: Range, incremental: boolean): Promise<void> {
    if (ui.section !== 'dashboards') return;
    if (inFlight) return;
    const gen = ++loadGen;
    inFlight = true;
    loading = true;
    error = null;
    if (!incremental) {
      chartReady = false;
      points = [];
      hadFullLoad = false;
    }
    try {
      const next = await fetchSeries(m, r, points, {
        maxPoints: DETAIL_MAX_POINTS,
        incremental: incremental && hadFullLoad,
      });
      if (gen !== loadGen) return;
      // Ignore stale responses if the user already picked another metric.
      if (m !== metric || r !== ui.range) return;
      points = next;
      chartReady = next.length > 1;
      hadFullLoad = true;
    } catch (e) {
      if (gen !== loadGen) return;
      error = errorText(e);
      points = [];
      chartReady = false;
    } finally {
      if (gen === loadGen) loading = false;
      inFlight = false;
    }
  }

  onMount(async () => {
    try {
      available = await api.timeseriesMetrics();
    } catch {
      available = [];
    }
  });

  // Load only while this page is open; on metric change destroy old chart first ({#key}).
  $effect(() => {
    const m = metric;
    const r = ui.range;
    void ui.hostEpoch;
    if (ui.section !== 'dashboards') return;
    if (!pageVisible()) return;

    hadFullLoad = false;
    void load(m, r, false);
    const timer = setInterval(() => {
      if (ui.section !== 'dashboards' || !pageVisible()) return;
      void load(m, r, true);
    }, CHART_POLL_MS);
    return () => clearInterval(timer);
  });

  const summary = $derived.by(() => {
    if (points.length === 0) return null;
    const avg =
      points.reduce((s, p) => s + p.avg * p.n, 0) /
      Math.max(
        1,
        points.reduce((s, p) => s + p.n, 0),
      );
    return {
      avg,
      min: Math.min(...points.map((p) => p.min)),
      max: Math.max(...points.map((p) => p.max)),
      n: points.reduce((s, p) => s + p.n, 0),
    };
  });

  const choices = $derived(METRICS.filter((m) => available.length === 0 || available.includes(m)));
  const chartXs = $derived(points.map((p) => p.ts));
  const avgYs = $derived(points.map((p) => p.avg));
  const minYs = $derived(points.map((p) => p.min));
  const maxYs = $derived(points.map((p) => p.max));
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
  <button class="btn" onclick={() => load(metric, ui.range, false)} disabled={loading}>{t('common.refresh')}</button>
  {#if loading}<span class="muted">{t('common.loading')}</span>{/if}
</div>

{#if error}
  <div class="notice error">{error}</div>
  <div style="height: 14px"></div>
{/if}

<div class="panel">
  {#if chartReady}
    {#key `${metric}:${ui.range}:${ui.hostEpoch}`}
      <Chart
        xs={chartXs}
        legend={true}
        series={[
          { label: t('dash.avg'), color: '#4fb3a5', values: avgYs },
          { label: t('dash.min'), color: '#8593a0', values: minYs, dash: [3, 3] },
          { label: t('dash.max'), color: '#d6a24a', values: maxYs, dash: [3, 3] },
        ]}
        height={340}
      />
    {/key}
  {:else}
    <p class="muted">{loading ? t('common.loading') : t('dash.empty')}</p>
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
