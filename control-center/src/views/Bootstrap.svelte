<script lang="ts">
  import { api, errorText, type BootstrapStatus } from '../lib/api';
  import { t } from '../lib/i18n';
  import { setLang, ui } from '../lib/state.svelte';
  import type { Lang } from '../lib/settings';

  let status = $state<BootstrapStatus | null>(null);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let log = $state<string>('');
  let done = $state(false);
  let preflight = $state<{
    ready: boolean;
    checks: { id: string; ok: boolean; detail: string }[];
    hints: Record<string, string>;
  } | null>(null);

  async function refresh(): Promise<void> {
    try {
      status = await api.bootstrapStatus();
      if (status.stack_ready) done = true;
    } catch (e) {
      error = errorText(e);
    }
    try {
      preflight = await api.bootstrapPreflight();
    } catch {
      preflight = null;
    }
  }

  async function install(): Promise<void> {
    busy = true;
    error = null;
    log = t('boot.working');
    try {
      const res = await api.bootstrapInstall();
      log = JSON.stringify(res.steps ?? res, null, 2);
      if (res.ok === false) {
        error = String(res.error || 'install failed');
      } else {
        done = Boolean(res.stack_ready) || true;
        await refresh();
      }
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    void refresh();
  });
</script>

<div class="wizard">
  <div class="wizard-card">
    <h1>{t('boot.title')}</h1>
    <p class="lead">{t('boot.lead')}</p>

    <div class="choice-grid" style="margin-bottom: 12px">
      <button class="choice" class:active={ui.lang === 'en'} onclick={() => setLang('en' as Lang)}>
        <div class="title">English</div>
      </button>
      <button class="choice" class:active={ui.lang === 'ru'} onclick={() => setLang('ru' as Lang)}>
        <div class="title">Русский</div>
      </button>
    </div>

    {#if status}
      <div class="notice" style="margin-bottom: 12px">
        <div class="mono muted" style="font-size: 12px">{status.home}</div>
        <div>
          {t('boot.version')}: {status.app_version}
          · {status.stack_ready ? t('boot.ready') : t('boot.needInstall')}
        </div>
      </div>
    {/if}

    {#if preflight}
      <div class="panel stack" style="margin-bottom: 12px">
        <h2 style="margin: 0; font-size: 14px">{t('boot.preflight')}</h2>
        <p class="muted" style="margin: 0; font-size: 12px">{t('boot.depsHint')}</p>
        {#each preflight.checks as c (c.id)}
          <div class="row">
            <span class="pill" class:ok={c.ok} class:warn={!c.ok}>{c.ok ? 'ok' : '…'}</span>
            <span class="mono muted" style="font-size: 12px">{c.id}</span>
            <span>{c.detail}</span>
          </div>
        {/each}
        {#if !preflight.ready}
          <pre class="console" style="margin: 0; font-size: 11px">{preflight.hints.debian}
{preflight.hints.arch}
{preflight.hints.fedora}</pre>
        {/if}
      </div>
    {/if}

    {#if error}<div class="notice error" style="margin-bottom: 12px">{error}</div>{/if}

    {#if done && status?.stack_ready}
      <div class="notice ok" style="margin-bottom: 12px">{t('boot.done')}</div>
      <div class="wizard-actions">
        <button class="btn primary" onclick={() => (ui.bootstrapDone = true)}>{t('ob.next')}</button>
      </div>
    {:else}
      <p class="muted">{t('boot.hint')}</p>
      <div class="wizard-actions">
        <button class="btn primary" disabled={busy || (preflight !== null && !preflight.ready)} onclick={install}>
          {busy ? t('common.loading') : t('boot.install')}
        </button>
      </div>
      {#if log}
        <pre class="console" style="margin-top: 14px; max-height: 200px">{log}</pre>
      {/if}
    {/if}
  </div>
</div>
