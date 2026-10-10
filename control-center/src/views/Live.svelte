<script lang="ts">
  import { live } from '../lib/live.svelte';
  import { t } from '../lib/i18n';
  import { fmtBytes, fmtClock, fmtNum } from '../lib/format';
  import Chart from '../lib/Chart.svelte';

  const CARDS: { metric: string; label: string; kind: 'score' | 'percent' | 'rate' }[] = [
    { metric: 'host_risk', label: 'host_risk', kind: 'score' },
    { metric: 'host_score', label: 'host_score', kind: 'score' },
    { metric: 'agent_score', label: 'agent_score', kind: 'score' },
    { metric: 'cpu_percent', label: 'CPU %', kind: 'percent' },
    { metric: 'mem_percent', label: 'MEM %', kind: 'percent' },
    { metric: 'net_bytes_recv_per_s', label: 'net in', kind: 'rate' },
    { metric: 'net_bytes_sent_per_s', label: 'net out', kind: 'rate' },
  ];

  function show(kind: string, v: number): string {
    if (kind === 'rate') return fmtBytes(v);
    if (kind === 'percent') return v.toFixed(1);
    return fmtNum(v);
  }

  const lastSample = $derived(Math.max(0, ...Object.values(live.values).map((v) => v.ts)));
  const ageSec = $derived(lastSample ? Date.now() / 1000 - lastSample : Infinity);
  const stale = $derived(ageSec > 10);
  const xs = $derived(live.history.map((h) => h.ts));
</script>

<h1>{t('live.title')}</h1>
<p class="lead">
  {#if live.connected}
    {stale ? `${Math.round(ageSec)} s` : fmtClock(lastSample)}
  {:else}
    {t('live.waiting')}
  {/if}
</p>

<div class="cards">
  {#each CARDS as c (c.metric)}
    {@const entry = live.values[c.metric]}
    <div class="panel stat" class:stale={stale}>
      <div class="label">{c.label}</div>
      <div class="value">{entry ? show(c.kind, entry.value) : '-'}</div>
      <div class="age">{entry ? fmtClock(entry.ts) : ''}</div>
    </div>
  {/each}
</div>

<div style="height: 18px"></div>

<div class="panel">
  <h2>{t('live.window')}</h2>
  {#if live.history.length > 1}
    <Chart
      {xs}
      series={[
        { label: 'host_risk', color: '#4fb3a5', values: live.history.map((h) => h.host_risk) },
        { label: 'host_score', color: '#8593a0', values: live.history.map((h) => h.host_score), dash: [3, 3] },
        { label: 'agent_score', color: '#d6a24a', values: live.history.map((h) => h.agent_score) },
      ]}
      height={260}
      yRange={[0, 1]}
    />
  {:else}
    <p class="muted">{t('live.waiting')}</p>
  {/if}
</div>
