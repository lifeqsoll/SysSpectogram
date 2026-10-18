<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { setAdvanced, setLang, setTheme, ui } from '../lib/state.svelte';
  import type { Lang } from '../lib/settings';

  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let busy = $state(false);
  let needsRestart = $state(false);

  let responseMode = $state('observe');
  let neverBan = $state('');
  let telegramEnabled = $state(false);
  let webEnabled = $state(false);
  let botToken = $state('');
  let chatId = $state('');
  let modelPath = $state('');

  const HOME_KEYS = [
    'ui.lang',
    'response.mode',
    'response.never_ban_cidrs',
    'telegram.enabled',
    'web.enabled',
  ] as const;

  async function reload(): Promise<void> {
    try {
      const exp = await api.settingsExport();
      const byKey = Object.fromEntries((exp.settings ?? []).map((s) => [s.key, s.current]));
      responseMode = String(byKey['response.mode'] ?? 'observe');
      {
        const raw = byKey['response.never_ban_cidrs'];
        if (Array.isArray(raw)) neverBan = raw.map(String).filter(Boolean).join('\n');
        else neverBan = String(raw ?? '').replace(/,\s*/g, '\n');
      }
      telegramEnabled = Boolean(byKey['telegram.enabled']);
      webEnabled = Boolean(byKey['web.enabled']);
      const lang = String(byKey['ui.lang'] ?? ui.lang);
      if (lang === 'en' || lang === 'ru') setLang(lang);
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(reload);

  async function applyHome(changes: Record<string, unknown>): Promise<void> {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.settingsApply(changes);
      needsRestart = true;
      notice = t('set.applied');
      await reload();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function saveBasics(): Promise<void> {
    await applyHome({
      'ui.lang': ui.lang,
      'response.mode': responseMode,
      'response.never_ban_cidrs': neverBan.trim(),
      'telegram.enabled': telegramEnabled,
      'web.enabled': webEnabled,
    });
  }

  async function saveEnv(): Promise<void> {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.homeWriteEnv(botToken || undefined, chatId || undefined);
      if (botToken || chatId) {
        await api.settingsApply({ 'telegram.enabled': true });
        telegramEnabled = true;
        needsRestart = true;
      }
      notice = t('set.applied');
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function importModel(): Promise<void> {
    if (!modelPath.trim()) return;
    busy = true;
    error = null;
    notice = null;
    try {
      const res = await api.homeImportModel(modelPath.trim());
      if (res.ok === false) {
        error = String(res.error || 'import failed');
      } else {
        notice = t('set.mlImported');
        needsRestart = true;
      }
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function restartGuard(): Promise<void> {
    try {
      await api.guardService('restart');
      notice = t('inst.done');
      needsRestart = false;
    } catch {
      await api.stopGuard();
      await api.startAll();
      needsRestart = false;
    }
  }

  void HOME_KEYS;
</script>

<h1>{t('set.title')}</h1>
<p class="lead">{t('set.basicLead')}</p>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}
{#if notice}<div class="notice ok">{notice}</div><div style="height: 12px"></div>{/if}
{#if needsRestart}
  <div class="notice warn" style="margin-bottom: 12px">
    {t('common.restartNote')}
    <button class="btn" style="margin-left: 8px" onclick={restartGuard}>{t('common.restartNow')}</button>
  </div>
{/if}

<div class="panel stack" style="margin-bottom: 16px">
  <div class="field">
    <span class="muted">{t('set.language')}</span>
    <div class="segmented">
      <button class:active={ui.lang === 'en'} onclick={() => setLang('en' as Lang)}>EN</button>
      <button class:active={ui.lang === 'ru'} onclick={() => setLang('ru' as Lang)}>RU</button>
    </div>
  </div>
  <div class="field">
    <span class="muted">{t('set.theme')}</span>
    <div class="segmented">
      <button class:active={ui.theme === 'dark'} onclick={() => setTheme('dark')}>{t('set.themeDark')}</button>
      <button class:active={ui.theme === 'light'} onclick={() => setTheme('light')}>{t('set.themeLight')}</button>
    </div>
  </div>
  <div class="field">
    <span class="muted">{t('home.mode')}</span>
    <select bind:value={responseMode}>
      <option value="observe">{t('mode.observe')}</option>
      <option value="shield">{t('mode.shield')}</option>
      <option value="aggressive">{t('mode.aggressive')}</option>
      <option value="isolate">{t('mode.isolate')}</option>
    </select>
    <p class="muted" style="margin: 4px 0 0; font-size: 12px">
      {#if responseMode === 'observe'}{t('mode.observeHint')}
      {:else if responseMode === 'shield'}{t('mode.shieldHint')}
      {:else if responseMode === 'aggressive'}{t('mode.aggressiveHint')}
      {:else}{t('mode.isolateHint')}{/if}
    </p>
  </div>
  <div class="field">
    <label for="neverban">{t('set.neverBan')}</label>
    <textarea
      id="neverban"
      rows="3"
      bind:value={neverBan}
      placeholder={"203.0.113.10\n198.51.100.20/32"}
      autocomplete="off"
    ></textarea>
    <p class="muted" style="margin: 4px 0 0; font-size: 12px; white-space: pre-line">{t('set.neverBanHelp')}</p>
  </div>
  <label class="row">
    <input type="checkbox" bind:checked={telegramEnabled} />
    <span>{t('home.telegram')}</span>
  </label>
  <label class="row">
    <input type="checkbox" bind:checked={webEnabled} />
    <span>{t('home.web')}</span>
  </label>
  <div class="row">
    <button class="btn primary" disabled={busy} onclick={saveBasics}>{t('common.apply')}</button>
  </div>
</div>

<div class="panel stack" style="margin-bottom: 16px">
  <h2>{t('home.telegram')}</h2>
  <div class="field">
    <label for="tok">{t('set.telegramToken')}</label>
    <input id="tok" type="password" bind:value={botToken} autocomplete="off" />
  </div>
  <div class="field">
    <label for="chat">{t('set.telegramChat')}</label>
    <input id="chat" type="text" bind:value={chatId} autocomplete="off" />
  </div>
  <button class="btn" disabled={busy} onclick={saveEnv}>{t('set.saveEnv')}</button>
</div>

<div class="panel stack" style="margin-bottom: 16px">
  <h2>{t('set.mlTitle')}</h2>
  <div class="notice warn">{t('set.mlWarn')}</div>
  <p class="muted">{t('set.mlHow')}</p>
  <div class="field">
    <label for="model">{t('set.mlPath')}</label>
    <input id="model" type="text" bind:value={modelPath} placeholder="/path/to/artifacts/live" />
  </div>
  <button class="btn" disabled={busy || !modelPath.trim()} onclick={importModel}>{t('set.mlImport')}</button>
</div>

<div class="panel stack">
  <label class="row">
    <input type="checkbox" checked={ui.advanced} onchange={(e) => setAdvanced((e.currentTarget as HTMLInputElement).checked)} />
    <span>{t('set.advanced')}</span>
  </label>
  <p class="muted" style="margin: 0">{t('set.advancedHelp')}</p>
  {#if ui.advanced}
    <button class="btn" onclick={() => (ui.section = 'overview')}>{t('nav.overview')}</button>
  {/if}
</div>
