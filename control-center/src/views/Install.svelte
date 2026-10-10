<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, type AppInfo } from '../lib/api';
  import { t } from '../lib/i18n';

  let info = $state<AppInfo | null>(null);
  let guard = $state('...');
  let version = $state('');
  let source = $state('');
  let busy = $state(false);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);

  async function refresh(): Promise<void> {
    error = null;
    try {
      guard = (await api.helperStatus()).guard;
    } catch (e) {
      guard = 'unreachable';
      error = errorText(e);
    }
  }

  onMount(async () => {
    try {
      info = await api.appInfo();
      version = info.version;
    } catch (e) {
      error = errorText(e);
    }
    await refresh();
  });

  async function service(action: 'start' | 'stop' | 'restart'): Promise<void> {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.guardService(action);
      notice = `${t('inst.done')} (${action})`;
      await refresh();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function install(): Promise<void> {
    if (!version.trim() || !source.trim()) return;
    busy = true;
    error = null;
    notice = null;
    try {
      await api.installBundle(version.trim(), source.trim());
      notice = `${t('inst.done')} ${version}`;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<h1>{t('inst.title')}</h1>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}
{#if notice}<div class="notice ok">{notice}</div><div style="height: 12px"></div>{/if}

<div class="grid-2">
  <div class="panel">
    <h2>{t('inst.service')}</h2>
    <p>
      <span class="pill {guard === 'active' ? 'ok' : guard === 'unreachable' ? 'danger' : 'warn'}">{guard}</span>
    </p>
    <div class="row">
      <button class="btn" onclick={() => service('start')} disabled={busy}>{t('inst.start')}</button>
      <button class="btn" onclick={() => service('stop')} disabled={busy}>{t('inst.stop')}</button>
      <button class="btn primary" onclick={() => service('restart')} disabled={busy}>{t('inst.restart')}</button>
      <span class="spacer"></span>
      <button class="btn" onclick={refresh} disabled={busy}>{t('common.refresh')}</button>
    </div>
  </div>

  <div class="panel">
    <h2>{t('inst.bundle')}</h2>
    <p class="muted" style="font-size: 12.5px">{t('inst.bundleHelp')}</p>
    <div class="stack" style="gap: 10px">
      <label class="field">
        <span class="muted">{t('inst.version')}</span>
        <input type="text" bind:value={version} placeholder="1.0.0" />
      </label>
      <label class="field">
        <span class="muted">{t('inst.source')}</span>
        <input type="text" bind:value={source} placeholder="/home/you/Downloads/sysspectogram-1.0.0" />
      </label>
      <div class="row">
        <span class="spacer"></span>
        <button class="btn primary" onclick={install} disabled={busy || !version.trim() || !source.trim()}>
          {t('inst.install')}
        </button>
      </div>
    </div>
  </div>
</div>
