<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, RANGES, type Point, type Range } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtBytes, fmtNum } from '../lib/format';
  import { isRemoteHost, ui } from '../lib/state.svelte';
  import { live } from '../lib/live.svelte';
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
  let points = $state<Point[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(false);
  let loadGen = 0;
  let inFlight = false;
  let lastMetricsHost = '';
  let metricId = $state('host_risk');
  let showLiveStrip = $state(false);
  let chartReady = $state(false);

  const choices = $derived(
    METRICS.filter((m) => {
      if (isRemoteHost() && !REMOTE_METRIC_IDS.has(m.id)) return false;
      if (available.length === 0) return m.group !== 'gpu';
      if (m.group === 'gpu' && !available.includes(m.id)) return false;
      return available.includes(m.id) || m.group === 'risk' || m.group === 'system';
    }),
  );

  const active = $derived(choices.find((m) => m.id === metricId) ?? choices[0] ?? METRICS[0]);
  const chartXs = $derived(points.map((p) => p.ts));
  const chartYs = $derived(points.map((p) => p.avg));

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

  async function loadOne(r: Range, mId: string): Promise<void> {
    if (!chartsActive() || inFlight) return;
    const gen = ++loadGen;
    inFlight = true;
    loading = true;
    error = null;
    chartReady = false;
    points = [];
    try {
      const next = await api.timeseriesQuery(mId, r);
      if (gen !== loadGen) return;
      if (mId !== metricId || r !== ui.range) return;
      points = next;
      chartReady = next.length > 0;
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

  async function refreshMetrics(): Promise<void> {
    try {
      available = await api.timeseriesMetrics();
    } catch {
      available = [];
    }
  }

  onMount(() => {
    void refreshMetrics();
  });

  $effect(() => {
    const r = ui.range;
    const host = ui.activeHostId;
    const mId = metricId;
    void ui.hostEpoch;

    if (!chartsActive()) return;

    if (host !== lastMetricsHost) {
      lastMetricsHost = host;
      void refreshMetrics();
    }

    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;

    const period = 5000;
    void loadOne(r, mId);
    const timer = setInterval(() => {
      if (!chartsActive()) return;
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      void loadOne(r, mId);
    }, period);
    return () => clearInterval(timer);
  });

  const liveXs = $derived(live.history.map((h) => h.ts));
  const now = $derived(active ? liveValue(active.id) : null);
</script>

{#if !embedded}
  <h1>{t('charts.title')}</h1>
  <p class="lead">{t('charts.lead')}</p>
{/if}

<div class="row" style="margin-bottom: 14px; flex-wrap: wrap; gap: 8px">
  <label class="field" style="margin: 0">
    <span class="muted">{t('dash.metric')}</span>
    <select bind:value={metricId}>
      {#each choices as m (m.id)}
        <option value={m.id}>{t(m.labelKey)}</option>
      {/each}
    </select>
  </label>
  <div class="segmented">
    {#each RANGES as r (r)}
      <button class:active={ui.range === r} onclick={() => (ui.range = r)}>{r}</button>
    {/each}
  </div>
  <button type="button" class="ghost" disabled={loading} onclick={() => loadOne(ui.range, metricId)}>
    {t('common.refresh')}
  </button>
  <label class="check muted" style="font-size: 12px">
    <input type="checkbox" bind:checked={showLiveStrip} />
    {t('live.window')}
  </label>
  {#if loading}<span class="muted">{t('common.loading')}</span>{/if}
</div>

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
{:else if !chartReady && !loading}
  <div class="notice warn" style="margin-bottom: 16px">{t('charts.emptyHint')}</div>
{/if}

{#if active}
  <div class="panel chart-card">
    <div class="row" style="margin-bottom: 6px">
      <h2 style="margin: 0">{t(active.labelKey)}</h2>
      <span class="spacer"></span>
      {#if now !== null}
        <span class="mono chart-now">{fmtMetric(active, now)} <span class="muted">{t('charts.now')}</span></span>
      {/if}
    </div>
    {#if chartReady}
      {#key `${active.id}:${ui.range}:${ui.hostEpoch}`}
        <Chart
          xs={chartXs}
          series={[{ label: t(active.labelKey), color: '#3b82f6', values: chartYs }]}
          height={280}
        />
      {/key}
      <div class="row muted" style="margin-top: 8px; font-size: 12px">
        <span>{t('dash.avg')} {fmtMetric(active, points.reduce((s, p) => s + p.avg, 0) / points.length)}</span>
        <span>{t('dash.max')} {fmtMetric(active, Math.max(...points.map((p) => p.max)))}</span>
      </div>
    {:else}
      <p class="muted" style="margin: 8px 0 0">{loading ? t('common.loading') : t('dash.empty')}</p>
    {/if}
  </div>
{/if}
