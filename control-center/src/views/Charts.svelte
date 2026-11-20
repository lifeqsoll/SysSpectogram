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

  const GROUP_ORDER = ['risk', 'system', 'net', 'disk', 'gpu'] as const;
  const GROUP_LABEL: Record<(typeof GROUP_ORDER)[number], string> = {
    risk: 'charts.groupRisk',
    system: 'charts.groupSystem',
    net: 'charts.groupNet',
    disk: 'charts.groupDisk',
    gpu: 'charts.groupGpu',
  };

  /** When embedded in FleetHostDetail, parent already set activeHostId. */
  let { embedded = false }: { embedded?: boolean } = $props();

  let available = $state<string[]>([]);
  let series = $state<Record<string, Point[]>>({});
  let error = $state<string | null>(null);
  let loading = $state(false);
  let loadGen = 0;

  const visible = $derived(
    METRICS.filter((m) => {
      if (available.length === 0) return m.group !== 'gpu';
      if (m.group === 'gpu' && !available.includes(m.id)) return false;
      return available.includes(m.id) || m.group === 'risk' || m.group === 'system';
    }),
  );

  const groups = $derived(
    GROUP_ORDER.map((g) => ({
      id: g,
      label: t(GROUP_LABEL[g]),
      metrics: visible.filter((m) => m.group === g),
    })).filter((g) => g.metrics.length > 0),
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

  function seriesUnchanged(next: Record<string, Point[]>): boolean {
    const keys = Object.keys(next);
    if (keys.length !== Object.keys(series).length) return false;
    for (const k of keys) {
      const a = series[k] ?? [];
      const b = next[k] ?? [];
      if (a.length !== b.length) return false;
      if (a.length && b.length && (a[a.length - 1].ts !== b[b.length - 1].ts || a[0].ts !== b[0].ts)) {
        return false;
      }
    }
    return true;
  }

  async function loadAll(r: Range): Promise<void> {
    const gen = ++loadGen;
    loading = true;
    error = null;
    try {
      const ids = (visible.length ? visible : METRICS).map((m) => m.id);
      const next = await api.timeseriesQueryMany(ids, r);
      if (gen !== loadGen) return;
      if (!seriesUnchanged(next)) series = next;
    } catch (e) {
      if (gen !== loadGen) return;
      error = errorText(e);
    } finally {
      if (gen === loadGen) loading = false;
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
    const epoch = ui.hostEpoch;
    const host = ui.activeHostId;
    void epoch;
    void host;
    void refreshMetrics();

    const onCharts =
      embedded || ui.section === 'charts' || (ui.section === 'fleet' && embedded);
    if (!onCharts && !embedded) {
      return;
    }

    const visibleDoc =
      typeof document === 'undefined' || document.visibilityState !== 'hidden';
    if (!visibleDoc) return;

    const period = isRemoteHost() ? (r === '1h' ? 15000 : 60000) : r === '1h' ? 5000 : 60000;
    void loadAll(r);
    const timer = setInterval(() => {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      if (!embedded && ui.section !== 'charts' && ui.section !== 'fleet') return;
      void loadAll(r);
    }, period);
    return () => clearInterval(timer);
  });

  const liveXs = $derived(live.history.map((h) => h.ts));
  const anyHistory = $derived(Object.values(series).some((pts) => pts.length > 0));
</script>

{#if !embedded}
  <h1>{t('charts.title')}</h1>
  <p class="lead">{t('charts.lead')}</p>
  {#if isRemoteHost()}
    <div class="notice" style="margin-bottom: 12px">{t('host.remoteHint')} · <span class="mono">{ui.activeHostId}</span></div>
  {/if}
{/if}

<div class="row" style="margin-bottom: 14px">
  <div class="segmented">
    {#each RANGES as r (r)}
      <button class:active={ui.range === r} onclick={() => (ui.range = r)}>{r}</button>
    {/each}
  </div>
  {#if loading}<span class="muted">{t('common.loading')}</span>{/if}
</div>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}

{#if live.history.length > 1}
  <div class="panel" style="margin-bottom: 16px">
    <h2>{t('live.window')}</h2>
    <Chart
      xs={liveXs}
      yRange={[0, 1]}
      series={[
        { label: t('charts.m.hostRisk'), color: '#3b82f6', values: live.history.map((h) => h.host_risk ?? 0) },
        { label: t('charts.m.hostScore'), color: '#8fa3c4', values: live.history.map((h) => h.host_score ?? 0), dash: [3, 3] },
        { label: t('charts.m.agentScore'), color: '#f0b35a', values: live.history.map((h) => h.agent_score ?? 0) },
      ]}
    />
  </div>
{:else if !anyHistory}
  <div class="notice warn" style="margin-bottom: 16px">{t('charts.emptyHint')}</div>
{/if}

{#each groups as g (g.id)}
  <h2 class="charts-group">{g.label}</h2>
  <div class="grid-2" style="margin-bottom: 18px">
    {#each g.metrics as m (m.id)}
      {@const pts = series[m.id] ?? []}
      {@const now = liveValue(m.id)}
      <div class="panel chart-card">
        <div class="row" style="margin-bottom: 6px">
          <h2 style="margin: 0">{t(m.labelKey)}</h2>
          <span class="spacer"></span>
          {#if now !== null}
            <span class="mono chart-now">{fmtMetric(m, now)} <span class="muted">{t('charts.now')}</span></span>
          {/if}
        </div>
        {#if pts.length === 0}
          <p class="muted" style="margin: 8px 0 0">{t('dash.empty')}</p>
        {:else}
          <Chart
            xs={pts.map((p) => p.ts)}
            series={[{ label: t(m.labelKey), color: '#3b82f6', values: pts.map((p) => p.avg) }]}
            height={180}
          />
          <div class="row muted" style="margin-top: 8px; font-size: 12px">
            <span>{t('dash.avg')} {fmtMetric(m, pts.reduce((s, p) => s + p.avg, 0) / pts.length)}</span>
            <span>{t('dash.max')} {fmtMetric(m, Math.max(...pts.map((p) => p.max)))}</span>
          </div>
        {/if}
      </div>
    {/each}
  </div>
{/each}
