<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, RANGES, type Point, type Range } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtBytes, fmtNum } from '../lib/format';
  import { isRemoteHost, setChartGridMetrics, ui } from '../lib/state.svelte';
  import { live } from '../lib/live.svelte';
  import {
    CHART_POLL_MS,
    DETAIL_MAX_POINTS,
    GRID_MAX_POINTS,
    fetchMany,
    fetchSeries,
    pageVisible,
  } from '../lib/timeseriesPoll.svelte';
  import Chart from '../lib/Chart.svelte';

  type MetricDef = {
    id: string;
    labelKey: string;
    group: 'risk' | 'system' | 'net' | 'disk' | 'gpu';
    unit: 'pct' | 'bytes' | 'score';
  };

  const METRICS: MetricDef[] = [
    { id: 'host_risk', labelKey: 'charts.m.hostRisk', group: 'risk', unit: 'score' },
    { id: 'host_score', labelKey: 'charts.m.hostScore', group: 'risk', unit: 'score' },
    { id: 'agent_score', labelKey: 'charts.m.agentScore', group: 'risk', unit: 'score' },
    { id: 'ml_raw_score', labelKey: 'charts.m.mlRaw', group: 'risk', unit: 'score' },
    { id: 'baseline_z', labelKey: 'charts.m.baselineZ', group: 'risk', unit: 'score' },
    { id: 'threshold', labelKey: 'charts.m.threshold', group: 'risk', unit: 'score' },
    { id: 'alerts_per_min', labelKey: 'charts.m.alerts', group: 'risk', unit: 'score' },
    { id: 'alerts_high_per_min', labelKey: 'charts.m.alertsHigh', group: 'risk', unit: 'score' },
    { id: 'perimeter_events_per_min', labelKey: 'charts.m.perimeter', group: 'risk', unit: 'score' },
    { id: 'cpu_percent', labelKey: 'charts.m.cpu', group: 'system', unit: 'pct' },
    { id: 'mem_percent', labelKey: 'charts.m.mem', group: 'system', unit: 'pct' },
    { id: 'swap_percent', labelKey: 'charts.m.swap', group: 'system', unit: 'pct' },
    { id: 'net_bytes_recv_per_s', labelKey: 'charts.m.netIn', group: 'net', unit: 'bytes' },
    { id: 'net_bytes_sent_per_s', labelKey: 'charts.m.netOut', group: 'net', unit: 'bytes' },
    { id: 'disk_read_bytes_per_s', labelKey: 'charts.m.diskRead', group: 'disk', unit: 'bytes' },
    { id: 'disk_write_bytes_per_s', labelKey: 'charts.m.diskWrite', group: 'disk', unit: 'bytes' },
    { id: 'gpu_util_percent', labelKey: 'charts.m.gpu', group: 'gpu', unit: 'pct' },
    { id: 'gpu_mem_percent', labelKey: 'charts.m.gpuMem', group: 'gpu', unit: 'pct' },
  ];

  const REMOTE_METRIC_IDS = new Set([
    'host_risk',
    'host_score',
    'agent_score',
    'cpu_percent',
    'mem_percent',
    'net_bytes_recv_per_s',
    'net_bytes_sent_per_s',
  ]);

  let { embedded = false }: { embedded?: boolean } = $props();

  let available = $state<string[]>([]);
  let seriesById = $state<Record<string, Point[]>>({});
  let detailPoints = $state<Point[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(false);
  let loadGen = 0;
  let inFlight = false;
  let lastMetricsHost = '';
  let detailId = $state<string | null>(null);
  let showLiveStrip = $state(false);
  let showPicker = $state(false);
  let hadFullLoad = false;

  const choices = $derived(
    METRICS.filter((m) => {
      if (isRemoteHost() && !REMOTE_METRIC_IDS.has(m.id)) return false;
      if (available.length === 0) return m.group !== 'gpu';
      if (m.group === 'gpu' && !available.includes(m.id)) return false;
      return available.includes(m.id) || m.group === 'risk' || m.group === 'system';
    }),
  );

  const gridDefs = $derived(
    choices.filter((m) => ui.chartGridMetrics.includes(m.id)),
  );

  const detail = $derived(
    detailId ? (choices.find((m) => m.id === detailId) ?? null) : null,
  );

  function fmtMetric(m: MetricDef, v: number | null | undefined): string {
    if (v === null || v === undefined || Number.isNaN(v)) return '—';
    if (m.unit === 'bytes') return fmtBytes(v);
    if (m.unit === 'pct') return `${fmtNum(v, 1)}%`;
    return fmtNum(v, 3);
  }

  function liveValue(id: string): number | null {
    const v = live.values[id]?.value;
    return typeof v === 'number' && Number.isFinite(v) ? v : null;
  }

  function chartsActive(): boolean {
    if (embedded) return ui.section === 'fleet';
    return ui.section === 'charts';
  }

  function toggleGridMetric(id: string, on: boolean): void {
    const set = new Set(ui.chartGridMetrics);
    if (on) set.add(id);
    else set.delete(id);
    setChartGridMetrics([...set]);
  }

  async function loadGrid(r: Range, incremental: boolean): Promise<void> {
    if (!chartsActive() || inFlight) return;
    const ids = gridDefs.map((m) => m.id);
    if (!ids.length) {
      seriesById = {};
      return;
    }
    const gen = ++loadGen;
    inFlight = true;
    loading = true;
    error = null;
    try {
      const next = await fetchMany(ids, r, seriesById, {
        maxPoints: GRID_MAX_POINTS,
        incremental: incremental && hadFullLoad,
      });
      if (gen !== loadGen) return;
      if (r !== ui.range) return;
      seriesById = next;
      hadFullLoad = true;
    } catch (e) {
      if (gen !== loadGen) return;
      error = errorText(e);
    } finally {
      if (gen === loadGen) loading = false;
      inFlight = false;
    }
  }

  async function loadDetail(r: Range, mId: string, incremental: boolean): Promise<void> {
    if (!chartsActive() || inFlight) return;
    const gen = ++loadGen;
    inFlight = true;
    loading = true;
    error = null;
    try {
      const next = await fetchSeries(mId, r, detailPoints, {
        maxPoints: DETAIL_MAX_POINTS,
        incremental: incremental && hadFullLoad,
      });
      if (gen !== loadGen) return;
      if (mId !== detailId || r !== ui.range) return;
      detailPoints = next;
      hadFullLoad = true;
    } catch (e) {
      if (gen !== loadGen) return;
      error = errorText(e);
      detailPoints = [];
    } finally {
      if (gen === loadGen) loading = false;
      inFlight = false;
    }
  }

  async function refreshMetrics(force = false): Promise<void> {
    try {
      available = await api.timeseriesMetrics({ force });
    } catch {
      available = [];
    }
  }

  function openDetail(id: string): void {
    detailId = id;
    detailPoints = [];
    hadFullLoad = false;
  }

  function closeDetail(): void {
    detailId = null;
    detailPoints = [];
    hadFullLoad = false;
  }

  onMount(() => {
    void refreshMetrics();
  });

  $effect(() => {
    const r = ui.range;
    const host = ui.activeHostId;
    void ui.hostEpoch;
    void ui.chartGridMetrics.join(',');
    const focused = detailId;

    if (!chartsActive()) return;

    if (host !== lastMetricsHost) {
      lastMetricsHost = host;
      seriesById = {};
      detailPoints = [];
      hadFullLoad = false;
      void refreshMetrics();
    }

    if (!pageVisible()) return;

    const run = () => {
      if (focused) void loadDetail(r, focused, true);
      else void loadGrid(r, true);
    };
    // Full reload on key change (range/host/detail) — reset incremental.
    hadFullLoad = false;
    if (focused) void loadDetail(r, focused, false);
    else void loadGrid(r, false);

    const timer = setInterval(() => {
      if (!chartsActive() || !pageVisible()) return;
      run();
    }, CHART_POLL_MS);
    return () => clearInterval(timer);
  });

  const liveXs = $derived(live.history.map((h) => h.ts));
  const detailNow = $derived(detail ? liveValue(detail.id) : null);
  const detailXs = $derived(detailPoints.map((p) => p.ts));
  const detailYs = $derived(detailPoints.map((p) => p.avg));
</script>

{#if !embedded}
  <h1>{t('charts.title')}</h1>
  <p class="lead">{t('charts.lead')}</p>
{/if}

<div class="row" style="margin-bottom: 14px; flex-wrap: wrap; gap: 8px">
  <div class="segmented">
    {#each RANGES as r (r)}
      <button class:active={ui.range === r} onclick={() => (ui.range = r)}>{r}</button>
    {/each}
  </div>
  {#if detail}
    <button type="button" class="ghost" onclick={closeDetail}>{t('charts.backGrid')}</button>
  {:else}
    <button type="button" class="ghost" onclick={() => (showPicker = !showPicker)}>
      {t('charts.pickMetrics')}
    </button>
  {/if}
  <button
    type="button"
    class="ghost"
    disabled={loading}
    onclick={() => {
      hadFullLoad = false;
      if (detailId) void loadDetail(ui.range, detailId, false);
      else void loadGrid(ui.range, false);
    }}
  >
    {t('common.refresh')}
  </button>
  <label class="check muted" style="font-size: 12px">
    <input type="checkbox" bind:checked={showLiveStrip} />
    {t('live.window')}
  </label>
  {#if loading}<span class="muted">{t('common.loading')}</span>{/if}
</div>

{#if showPicker && !detail}
  <div class="panel chart-picker" style="margin-bottom: 14px">
    <div class="muted" style="margin-bottom: 8px; font-size: 12px">{t('charts.pickMetricsHint')}</div>
    <div class="chart-picker-grid">
      {#each choices as m (m.id)}
        <label class="check">
          <input
            type="checkbox"
            checked={ui.chartGridMetrics.includes(m.id)}
            onchange={(e) => toggleGridMetric(m.id, (e.currentTarget as HTMLInputElement).checked)}
          />
          {t(m.labelKey)}
        </label>
      {/each}
    </div>
  </div>
{/if}

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}

{#if showLiveStrip && live.history.length > 1}
  <div class="panel" style="margin-bottom: 16px">
    <h2>{t('live.window')}</h2>
    {#key `live-${ui.activeHostId}`}
      <Chart
        xs={liveXs}
        yRange={[0, 1]}
        legend={true}
        series={[
          { label: t('charts.m.hostRisk'), color: '#3b82f6', values: live.history.map((h) => h.host_risk ?? 0) },
          { label: t('charts.m.hostScore'), color: '#8fa3c4', values: live.history.map((h) => h.host_score ?? 0), dash: [3, 3] },
          { label: t('charts.m.agentScore'), color: '#f0b35a', values: live.history.map((h) => h.agent_score ?? 0) },
        ]}
      />
    {/key}
  </div>
{/if}

{#if detail}
  <div class="panel chart-card">
    <div class="row" style="margin-bottom: 6px">
      <h2 style="margin: 0">{t(detail.labelKey)}</h2>
      <span class="spacer"></span>
      {#if detailNow !== null}
        <span class="mono chart-now">{fmtMetric(detail, detailNow)} <span class="muted">{t('charts.now')}</span></span>
      {/if}
    </div>
    {#if detailPoints.length > 0}
      {#key `${detail.id}:${ui.range}:${ui.hostEpoch}`}
        <Chart
          xs={detailXs}
          series={[{ label: t(detail.labelKey), color: '#3b82f6', values: detailYs }]}
          height={280}
        />
      {/key}
      <div class="row muted" style="margin-top: 8px; font-size: 12px">
        <span
          >{t('dash.avg')}
          {fmtMetric(detail, detailPoints.reduce((s, p) => s + p.avg, 0) / detailPoints.length)}</span
        >
        <span>{t('dash.max')} {fmtMetric(detail, Math.max(...detailPoints.map((p) => p.max)))}</span>
      </div>
    {:else}
      <p class="muted" style="margin: 8px 0 0">{loading ? t('common.loading') : t('dash.empty')}</p>
    {/if}
  </div>
{:else if gridDefs.length === 0}
  <div class="notice warn">{t('charts.emptyHint')}</div>
{:else}
  {#key `grid:${ui.range}:${ui.hostEpoch}`}
    <div class="charts-grid">
      {#each gridDefs as m (m.id)}
        {@const pts = seriesById[m.id] ?? []}
        {@const xs = pts.map((p) => p.ts)}
        {@const ys = pts.map((p) => p.avg)}
        {@const now = liveValue(m.id)}
        {@const markers = (seriesById['alerts_per_min'] ?? [])
          .filter((p) => p.avg > 0)
          .map((p) => p.ts)
          .slice(-40)}
        <button type="button" class="panel chart-card chart-tile" onclick={() => openDetail(m.id)}>
          <div class="row" style="margin-bottom: 4px">
            <h2 style="margin: 0; font-size: 14px">{t(m.labelKey)}</h2>
            <span class="spacer"></span>
            {#if now !== null}
              <span class="mono chart-now" style="font-size: 12px">{fmtMetric(m, now)}</span>
            {/if}
          </div>
          {#if pts.length > 0}
            <Chart
              xs={xs}
              series={[{ label: t(m.labelKey), color: '#3b82f6', values: ys }]}
              height={140}
              syncKey={`charts-${ui.activeHostId}-${ui.range}`}
              markers={markers}
            />
          {:else}
            <p class="muted" style="margin: 12px 0; font-size: 12px">
              {loading ? t('common.loading') : t('dash.empty')}
            </p>
          {/if}
        </button>
      {/each}
    </div>
  {/key}
{/if}

<style>
  .charts-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 12px;
  }
  .chart-tile {
    text-align: left;
    cursor: pointer;
    border: 1px solid var(--border, #2a3344);
    background: inherit;
    color: inherit;
    width: 100%;
    font: inherit;
  }
  .chart-tile:hover {
    border-color: var(--accent, #3b82f6);
  }
  .chart-picker-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 6px 12px;
  }
</style>
