<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    api,
    errorText,
    type AppInfo,
    type Incident,
    type Point,
    type StackStatus,
    type StartAllResult,
  } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtNum, fmtTime } from '../lib/format';
  import { live } from '../lib/live.svelte';
  import Chart from '../lib/Chart.svelte';

  let info = $state<AppInfo | null>(null);
  let guard = $state('...');
  let incidents = $state<Incident[]>([]);
  let points = $state<Point[]>([]);
  let error = $state<string | null>(null);
  let stack = $state<StackStatus | null>(null);
  let startResult = $state<StartAllResult | null>(null);
  let startBusy = $state(false);

  async function load(): Promise<void> {
    error = null;
    try {
      info = await api.appInfo();
      guard = (await api.helperStatus()).guard;
    } catch (e) {
      guard = 'unreachable';
      error = errorText(e);
    }
    try {
      stack = await api.stackStatus();
    } catch (e) {
      error = errorText(e);
    }
    try {
      incidents = (await api.incidentsList(200)).sort((a, b) => b.last_ts - a.last_ts).slice(0, 5);
      points = await api.timeseriesQuery('host_risk', '1h');
    } catch (e) {
      error = errorText(e);
    }
  }

  async function startEverything(): Promise<void> {
    startBusy = true;
    startResult = null;
    try {
      startResult = await api.startAll();
    } catch (e) {
      error = errorText(e);
    } finally {
      startBusy = false;
      await load();
    }
  }

  async function stopGuard(): Promise<void> {
    try {
      await api.stopGuard();
    } catch (e) {
      error = errorText(e);
    }
    await load();
  }

  // Pairing code for Telegram /unlock. Shown only on click, hidden after UNLOCK_SHOW_SEC.
  const UNLOCK_SHOW_SEC = 20;
  let unlockCode = $state<string | null>(null);
  let unlockState = $state<'hidden' | 'shown' | 'none'>('hidden');
  let unlockLeft = $state(0);
  let unlockTimer: ReturnType<typeof setInterval> | undefined;

  function stopUnlockTimer(): void {
    if (unlockTimer) {
      clearInterval(unlockTimer);
      unlockTimer = undefined;
    }
  }

  function hideCode(): void {
    stopUnlockTimer();
    unlockCode = null;
    unlockState = 'hidden';
    unlockLeft = 0;
  }

  async function showCode(): Promise<void> {
    error = null;
    try {
      const code = await api.unlockCode();
      stopUnlockTimer();
      if (!code) {
        unlockCode = null;
        unlockState = 'none';
        return;
      }
      unlockCode = code;
      unlockState = 'shown';
      unlockLeft = UNLOCK_SHOW_SEC;
      unlockTimer = setInterval(() => {
        unlockLeft -= 1;
        if (unlockLeft <= 0) hideCode();
      }, 1000);
    } catch (e) {
      error = errorText(e);
    }
  }

  onDestroy(hideCode);

  const startOk = $derived(
    startResult ? startResult.helper.ok && startResult.guard.ok : null,
  );

  onMount(() => {
    load();
    const timer = setInterval(load, 15000);
    return () => clearInterval(timer);
  });

  const guardClass = $derived(guard === 'active' ? 'ok' : guard === 'unreachable' ? 'danger' : 'warn');
  const hostRisk = $derived(live.values.host_risk);
  const agentScore = $derived(live.values.agent_score);
  const severityClass = (s: string) => (s === 'critical' || s === 'high' ? 'danger' : s === 'medium' ? 'warn' : '');
</script>

<h1>{t('nav.overview')}</h1>
<p class="lead">
  {info ? `${t('overview.version')} ${info.version}` : ''}
</p>

{#if error}
  <div class="notice error">{error}</div>
  <div style="height: 14px"></div>
{/if}

<div class="stack">
  <div class="panel">
    <h2>{t('stack.title')}</h2>
    <p class="muted">{t('stack.lead')}</p>
    <div class="row" style="margin-top: 10px">
      <button class="btn primary" onclick={startEverything} disabled={startBusy}>
        {t('stack.start')}
      </button>
      <button class="btn" onclick={stopGuard} disabled={!stack?.guard_running}>
        {t('stack.stopGuard')}
      </button>
      <span class="muted">
        {t('stack.guardApp')}:
        <span class="pill {stack?.guard_running ? 'ok' : ''}">
          {stack?.guard_running ? `${t('stack.running')} (pid ${stack.guard_pid})` : t('stack.stopped')}
        </span>
      </span>
    </div>
    {#if startResult}
      <div style="height: 10px"></div>
      <div class="notice {startOk ? 'ok' : 'error'}">{startOk ? t('stack.done') : t('stack.failed')}</div>
      <div style="height: 6px"></div>
      <div class="mono" style="font-size: 12px">
        helper: {startResult.helper.message}<br />
        guard: {startResult.guard.message}
      </div>
    {/if}
  </div>

  <div class="panel">
    <h2>{t('unlock.title')}</h2>
    <p class="muted">{t('unlock.lead')}</p>
    <div class="row" style="margin-top: 10px">
      <button class="btn" onclick={showCode} disabled={unlockState === 'shown'}>{t('unlock.show')}</button>
      {#if unlockState === 'shown'}
        <button class="btn" onclick={hideCode}>{t('unlock.hide')}</button>
        <span class="muted">{t('unlock.hidesIn')} {unlockLeft} s</span>
      {/if}
    </div>
    {#if unlockState === 'shown' && unlockCode}
      <div class="mono" style="font-size: 32px; letter-spacing: 6px; margin-top: 12px">{unlockCode}</div>
      <p class="muted">{t('unlock.sendHint')}</p>
    {:else if unlockState === 'none'}
      <p class="muted" style="margin-top: 10px">{t('unlock.none')}</p>
    {/if}
  </div>

  <div class="cards">
    <div class="panel stat">
      <div class="label">{t('overview.guard')}</div>
      <div class="value"><span class="pill {guardClass}">{guard}</span></div>
    </div>
    <div class="panel stat">
      <div class="label">{t('live.title')}: host_risk</div>
      <div class="value">{fmtNum(hostRisk?.value)}</div>
    </div>
    <div class="panel stat">
      <div class="label">agent_score</div>
      <div class="value">{fmtNum(agentScore?.value)}</div>
    </div>
    <div class="panel stat">
      <div class="label">{t('overview.lastIncidents')}</div>
      <div class="value">{incidents.length}</div>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <h2>{t('overview.hostRisk1h')}</h2>
      {#if points.length > 1}
        <Chart
          xs={points.map((p) => p.ts)}
          series={[
            { label: 'avg', color: '#4fb3a5', values: points.map((p) => p.avg) },
            { label: 'max', color: '#d6a24a', values: points.map((p) => p.max), dash: [4, 4] },
          ]}
          height={210}
          yRange={[0, 1]}
        />
      {:else}
        <p class="muted">{t('dash.empty')}</p>
      {/if}
    </div>

    <div class="panel">
      <h2>{t('overview.lastIncidents')}</h2>
      {#if incidents.length === 0}
        <p class="muted">{t('overview.noIncidents')}</p>
      {:else}
        <table>
          <tbody>
            {#each incidents as inc (inc.id)}
              <tr>
                <td class="mono">{inc.id.slice(0, 8)}</td>
                <td><span class="pill {severityClass(inc.severity)}">{inc.severity}</span></td>
                <td class="muted">{fmtTime(inc.first_ts)}</td>
                <td>{inc.rules.join(', ')}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  </div>
</div>

