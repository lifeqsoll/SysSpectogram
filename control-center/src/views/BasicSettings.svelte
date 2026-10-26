<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { setAdvanced, setFleetHubOnly, setLang, setTheme, ui } from '../lib/state.svelte';
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
  let detectBusy = $state(false);

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
    <button
      class="btn"
      style="margin-top: 8px"
      disabled={busy || detectBusy}
      onclick={async () => {
        detectBusy = true;
        error = null;
        try {
          const res = await api.detectPublicIp();
          const ip = (res.ip || '').trim();
          if (!ip) throw new Error('empty IP');
          const line = ip.includes('/') ? ip : `${ip}/32`;
          const cur = neverBan
            .split(/[\n,]+/)
            .map((s) => s.trim())
            .filter(Boolean);
          if (!cur.includes(line) && !cur.includes(ip)) cur.push(line);
          neverBan = cur.join('\n');
        } catch (e) {
          error = errorText(e);
        } finally {
          detectBusy = false;
        }
      }}>{detectBusy ? '…' : t('set.detectIp')}</button>
    <button
      class="btn"
      style="margin-top: 8px; margin-left: 8px"
      disabled={busy}
      onclick={async () => {
        busy = true;
        error = null;
        try {
          const { invoke } = await import('@tauri-apps/api/core');
          const res = await invoke<{ ok?: boolean; never_ban_cidrs?: string[]; ip?: string; error?: string }>(
            'home_seed_never_ban',
          );
          if (!res.ok) throw new Error(res.error || 'seed failed');
          const list = res.never_ban_cidrs || [];
          neverBan = list.join('\n');
          notice =
            ui.lang === 'ru'
              ? `never-ban: ${res.ip || '—'} (проверьте NAT)`
              : `never-ban: ${res.ip || '—'} (check NAT)`;
        } catch (e) {
          error = errorText(e);
        } finally {
          busy = false;
        }
      }}>{ui.lang === 'ru' ? 'Записать never-ban' : 'Seed never-ban'}</button>
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
    <button
      class="btn"
      disabled={busy}
      onclick={async () => {
        busy = true;
        error = null;
        notice = null;
        try {
          const res = await api.homeUpdate();
          notice = res.ok === false ? String(res.error || 'update failed') : t('home.update');
          if (res.ok !== false) needsRestart = true;
        } catch (e) {
          error = errorText(e);
        } finally {
          busy = false;
        }
      }}>{t('home.update')}</button>
  </div>
  <p class="muted" style="margin: 8px 0 0; font-size: 12px">{t('home.installHelperHelp')}</p>
  <button
    class="btn"
    disabled={busy}
    onclick={async () => {
      busy = true;
      error = null;
      notice = null;
      try {
        const res = await api.installHelperRelease();
        notice = res.ok === false ? String(res.error || 'helper install failed') : t('home.installHelper');
        if (typeof res.detail === 'string' && res.detail) notice = `${notice}: ${res.detail.slice(0, 200)}`;
      } catch (e) {
        error = errorText(e);
      } finally {
        busy = false;
      }
    }}>{t('home.installHelper')}</button>
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
    <input type="checkbox" checked={ui.fleetHubOnly} onchange={(e) => setFleetHubOnly((e.currentTarget as HTMLInputElement).checked)} />
    <span>{ui.lang === 'ru' ? 'Только Fleet hub (скрыть local protect)' : 'Fleet hub only (hide local protect)'}</span>
  </label>
  <p class="muted" style="margin: 0 0 12px">
    {ui.lang === 'ru'
      ? 'Навигация: Fleet + Settings. Для админ-ПК с несколькими VPS.'
      : 'Nav: Fleet + Settings. For admin PC managing many VPS.'}
  </p>
  <label class="row">
    <input type="checkbox" checked={ui.advanced} onchange={(e) => setAdvanced((e.currentTarget as HTMLInputElement).checked)} />
    <span>{t('set.advanced')}</span>
  </label>
  <p class="muted" style="margin: 0">{t('set.advancedHelp')}</p>
  {#if ui.advanced}
    <button class="btn" onclick={() => (ui.section = 'overview')}>{t('nav.overview')}</button>
  {/if}
</div>
