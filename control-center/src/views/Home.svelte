<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import {
    api,
    errorText,
    isTauri,
    type HomeChecklist,
    type HomeDigest,
    type HomeHealth,
    type Incident,
    type StackStatus,
    type StartAllResult,
  } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtNum, fmtTime } from '../lib/format';
  import { live } from '../lib/live.svelte';
  import { ui, type SectionId } from '../lib/state.svelte';

  let guard = $state('...');
  let stack = $state<StackStatus | null>(null);
  let incidents = $state<Incident[]>([]);
  let error = $state<string | null>(null);
  let startResult = $state<StartAllResult | null>(null);
  let startBusy = $state(false);
  let mode = $state('observe');
  let tgOn = $state(false);
  let webOn = $state(false);
  let unlocked = $state(true);
  let health = $state<HomeHealth | null>(null);
  let digest = $state<HomeDigest | null>(null);
  let checklist = $state<HomeChecklist | null>(null);
  let healthBusy = $state(false);
  let protectActive = $state(false);
  let protectBusy = $state(false);
  let protectHint = $state<string | null>(null);
  let lingerOk = $state<boolean | null>(null);

  const UNLOCK_SHOW_SEC = 20;
  let unlockCode = $state<string | null>(null);
  let unlockState = $state<'hidden' | 'shown' | 'none'>('hidden');
  let unlockLeft = $state(0);
  let unlockTimer: ReturnType<typeof setInterval> | undefined;

  function modeLabel(m: string): string {
    const key = `mode.${m}`;
    const mapped = t(key);
    return mapped === key ? m : mapped;
  }

  async function load(): Promise<void> {
    error = null;
    if (!isTauri()) {
      error = 'Open the desktop app (npm run tauri dev), not the browser preview.';
      return;
    }
    try {
      guard = (await api.helperStatus()).guard;
    } catch {
      guard = 'unreachable';
    }
    try {
      stack = await api.stackStatus();
    } catch (e) {
      error = errorText(e);
    }
    try {
      const exp = await api.settingsExport();
      const byKey = Object.fromEntries((exp.settings ?? []).map((s) => [s.key, s.current]));
      mode = String(byKey['response.mode'] ?? 'observe');
      tgOn = Boolean(byKey['telegram.enabled']);
      webOn = Boolean(byKey['web.enabled']);
    } catch {
      /* ignore */
    }
    try {
      const st = await api.controlStatus();
      const status = (st.status ?? st) as Record<string, unknown>;
      unlocked = status.control_unlocked !== false;
    } catch {
      unlocked = true;
    }
    try {
      incidents = (await api.incidentsList(200)).sort((a, b) => b.last_ts - a.last_ts).slice(0, 8);
    } catch (e) {
      error = errorText(e);
    }
    try {
      digest = await api.homeDigest(24, ui.lang);
    } catch {
      digest = null;
    }
    try {
      checklist = await api.homeChecklist();
    } catch {
      checklist = null;
    }
    try {
      health = await api.homeHealth(false);
    } catch {
      health = null;
    }
    try {
      const ps = await api.protectStatus();
      protectActive = Boolean(ps.active || ps.enabled);
      protectHint = typeof ps.hint === 'string' ? ps.hint : null;
      lingerOk = typeof ps.linger === 'boolean' ? ps.linger : null;
    } catch {
      protectActive = false;
      protectHint = null;
      lingerOk = null;
    }
  }

  async function toggleProtect(): Promise<void> {
    protectBusy = true;
    error = null;
    try {
      if (protectActive) await api.protectDisable();
      else {
        const pe = await api.protectEnable();
        if (typeof pe.hint === 'string') protectHint = pe.hint;
      }
    } catch (e) {
      error = errorText(e);
    } finally {
      protectBusy = false;
      await load();
    }
  }

  async function runHealth(ping: boolean): Promise<void> {
    healthBusy = true;
    try {
      health = await api.homeHealth(ping);
    } catch (e) {
      error = errorText(e);
    } finally {
      healthBusy = false;
    }
  }

  async function startEverything(): Promise<void> {
    // Hand off to real protect unit (not session dry-run).
    startBusy = true;
    startResult = null;
    error = null;
    try {
      const pe = await api.protectEnable();
      if (pe.ok === false) {
        error = String(pe.error || pe.detail || 'protect enable failed');
      }
      if (typeof pe.hint === 'string') protectHint = pe.hint;
      startResult = {
        helper: { ok: true, message: 'skipped (background protect)' },
        guard: {
          ok: pe.ok !== false,
          message: pe.ok === false ? String(pe.error || 'failed') : 'systemd --user protect enabled',
        },
      };
    } catch (e) {
      error = errorText(e);
    } finally {
      startBusy = false;
      await load();
    }
  }

  function stopUnlockTimer(): void {
    if (unlockTimer) clearInterval(unlockTimer);
    unlockTimer = undefined;
  }

  function hideCode(): void {
    stopUnlockTimer();
    unlockCode = null;
    unlockState = 'hidden';
    unlockLeft = 0;
  }

  async function showCode(): Promise<void> {
    try {
      const code = await api.unlockCode();
      stopUnlockTimer();
      if (!code) {
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

  onMount(load);
  onDestroy(stopUnlockTimer);

  const running = $derived(Boolean(stack?.guard_running) || guard === 'active');
  const riskNow = $derived(live.values.host_risk?.value ?? live.values.agent_score?.value ?? null);
  const cpuNow = $derived(live.values.cpu_percent?.value ?? null);
  const tips = $derived(
    [
      !running ? { id: 'start', text: t('home.tipStart'), go: null as SectionId | null } : null,
      running && mode === 'observe' ? { id: 'mode', text: t('home.tipMode'), go: 'settings' as SectionId } : null,
      !tgOn ? { id: 'tg', text: t('home.tipTg'), go: 'settings' as SectionId } : null,
      running ? { id: 'charts', text: t('home.tipCharts'), go: 'charts' as SectionId } : null,
    ].filter(Boolean) as { id: string; text: string; go: SectionId | null }[],
  );
</script>

<h1>{t('home.title')}</h1>
<p class="lead">{t('home.lead')}</p>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}

<div class="cards" style="margin-bottom: 16px">
  <div class="panel stat">
    <div class="label">{t('overview.guard')}</div>
    <div class="value">
      <span class="pill" class:ok={running} class:warn={!running}>
        {running ? t('home.protected') : t('home.offline')}
      </span>
    </div>
  </div>
  <div class="panel stat">
    <div class="label">{t('home.mode')}</div>
    <div class="value" style="font-size: 15px; font-family: var(--display)">{modeLabel(mode)}</div>
  </div>
  <div class="panel stat">
    <div class="label">{t('home.riskNow')}</div>
    <div class="value">{riskNow === null ? '—' : fmtNum(riskNow, 3)}</div>
  </div>
  <div class="panel stat">
    <div class="label">{t('home.cpuNow')}</div>
    <div class="value">{cpuNow === null ? '—' : `${fmtNum(cpuNow, 1)}%`}</div>
  </div>
  <div class="panel stat">
    <div class="label">{t('home.telegram')}</div>
    <div class="value"><span class="pill" class:ok={tgOn}>{tgOn ? t('common.on') : t('common.off')}</span></div>
  </div>
  <div class="panel stat">
    <div class="label">{t('home.web')}</div>
    <div class="value"><span class="pill" class:ok={webOn}>{webOn ? t('common.on') : t('common.off')}</span></div>
  </div>
</div>

{#if tips.length}
  <div class="panel stack" style="margin-bottom: 16px">
    <h2>{t('home.next')}</h2>
    {#each tips as tip (tip.id)}
      <div class="row">
        <span class="muted">{tip.text}</span>
        <span class="spacer"></span>
        {#if tip.go}
          <button class="btn" onclick={() => (ui.section = tip.go!)}>{t(`nav.${tip.go}`)}</button>
        {/if}
      </div>
    {/each}
  </div>
{/if}

<div class="panel stack" style="margin-bottom: 16px">
  <div class="row">
    <button class="btn primary" disabled={startBusy} onclick={startEverything}>{t('home.start')}</button>
    <button class="btn" onclick={() => api.stopGuard().then(load)}>{t('stack.stopGuard')}</button>
    <button class="btn" disabled={healthBusy} onclick={() => runHealth(false)}>{t('home.health')}</button>
    <button class="btn" disabled={healthBusy} onclick={() => runHealth(true)}>{t('home.healthPing')}</button>
    <span class="spacer"></span>
    <span class="pill" class:ok={unlocked} class:warn={!unlocked}>
      {unlocked ? 'unlocked' : 'LOCKED'}
    </span>
  </div>
  <div class="notice" class:ok={protectActive} style="margin-top: 8px">
    <div>{protectActive ? t('home.keepAliveActive') : t('home.keepAliveInactive')}</div>
    <p class="muted" style="margin: 6px 0; font-size: 12px">{t('home.keepAlive')}</p>
    {#if lingerOk === false || protectHint}
      <div class="notice warn" style="margin: 8px 0">
        {protectHint || t('home.lingerNeed')}
        <div class="row" style="margin-top: 8px">
          <code class="mono" style="font-size: 12px">loginctl enable-linger $USER</code>
        </div>
      </div>
    {:else if lingerOk === true}
      <p class="muted" style="margin: 6px 0; font-size: 12px">{t('home.lingerOk')}</p>
    {/if}
    <button class="btn" disabled={protectBusy} onclick={toggleProtect}>
      {protectActive ? t('home.keepAliveOff') : t('home.keepAliveOn')}
    </button>
  </div>
  {#if startResult}
    <div class="notice" class:ok={startResult.helper.ok && startResult.guard.ok} class:error={!(startResult.helper.ok && startResult.guard.ok)}>
      helper: {startResult.helper.message}<br />
      guard: {startResult.guard.message}
    </div>
  {/if}
  {#if health}
    <div class="stack" style="gap: 6px">
      {#each health.checks as c (c.id)}
        <div class="row">
          <span class="pill" class:ok={c.ok} class:warn={!c.ok}>{c.ok ? 'ok' : c.severity}</span>
          <span class="muted mono" style="font-size: 12px">{c.id}</span>
          <span>{c.detail}</span>
        </div>
      {/each}
    </div>
  {/if}
  <div>
    <h2>{t('unlock.title')}</h2>
    <p class="muted" style="margin: 0 0 8px">{t('unlock.lead')}</p>
    <div class="row">
      {#if unlockState === 'shown'}
        <code class="mono" style="font-size: 22px; letter-spacing: 0.2em">{unlockCode}</code>
        <button class="btn" onclick={hideCode}>{t('unlock.hide')}</button>
        <span class="muted">{t('unlock.hidesIn')} {unlockLeft}s</span>
      {:else}
        <button class="btn" onclick={showCode}>{t('unlock.show')}</button>
      {/if}
    </div>
    {#if unlockState === 'shown'}
      <p class="muted" style="margin-top: 8px">{t('unlock.sendHint')}</p>
    {:else if unlockState === 'none'}
      <p class="muted" style="margin-top: 8px">{t('unlock.none')}</p>
    {/if}
  </div>
</div>

{#if digest}
  <div class="panel" style="margin-bottom: 16px">
    <h2>{t('home.digest')}</h2>
    <pre class="digest">{digest.text}</pre>
  </div>
{/if}

{#if checklist}
  <div class="panel stack" style="margin-bottom: 16px">
    <h2>{t('home.checklist')} ({checklist.ready}/{checklist.total})</h2>
    {#each checklist.items as it (it.id)}
      <div class="row">
        <span class="pill" class:ok={it.ok} class:warn={!it.ok}>{it.ok ? 'ok' : '…'}</span>
        <div>
          <div>{it.title[ui.lang] || it.title.en}</div>
          {#if !it.ok}<div class="muted" style="font-size: 12px">{it.hint[ui.lang] || it.hint.en}</div>{/if}
        </div>
      </div>
    {/each}
  </div>
{/if}

<div class="panel">
  <h2>{t('home.recent')}</h2>
  {#if incidents.length === 0}
    <p class="muted">{t('overview.noIncidents')}</p>
  {:else}
    {#each incidents as inc (inc.id)}
      <div class="alert-row">
        <div class="row">
          <span class="pill" class:danger={inc.severity === 'high' || inc.severity === 'critical'} class:warn={inc.severity === 'medium'}>{inc.severity}</span>
          <span class="title">{inc.rules?.[0] || inc.reason || inc.id}</span>
          <span class="spacer"></span>
          <span class="muted mono">{fmtTime(inc.last_ts)}</span>
        </div>
        <div class="muted">{inc.reason}</div>
      </div>
    {/each}
  {/if}
  <div class="row" style="margin-top: 12px">
    <button class="btn" onclick={() => (ui.section = 'alerts')}>{t('nav.alerts')}</button>
    <button class="btn" onclick={() => (ui.section = 'charts')}>{t('nav.charts')}</button>
  </div>
</div>
