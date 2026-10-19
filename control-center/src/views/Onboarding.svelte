<script lang="ts">
  import { api, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { setLang, setTheme, ui } from '../lib/state.svelte';
  import type { Lang } from '../lib/settings';

  let step = $state(0);
  let role = $state<'ssh' | 'web' | 'other'>('ssh');
  let protect = $state<'observe' | 'shield' | 'aggressive' | 'isolate'>('observe');
  let neverBan = $state('');
  let skipNeverBan = $state(false);
  let botToken = $state('');
  let chatId = $state('');
  let skipTg = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let finished = $state(false);
  let lingerHint = $state<string | null>(null);

  // lang, theme, role, mode, never-ban, telegram, ml, finish
  const total = 8;

  function next(): void {
    error = null;
    if (step === 3 && protect !== 'observe') {
      skipNeverBan = false;
    }
    if (step === 4 && protect !== 'observe' && !neverBan.trim()) {
      error = t('ob.neverBanNeed');
      return;
    }
    if (step < total - 1) step += 1;
  }

  function trySkipNeverBan(): void {
    if (protect !== 'observe') {
      error = t('ob.neverBanSkipBlocked');
      return;
    }
    const ok = window.confirm(t('ob.neverBanSkipWarn'));
    if (ok) skipNeverBan = !skipNeverBan;
  }
  function back(): void {
    if (step > 0) step -= 1;
  }

  async function finish(): Promise<void> {
    busy = true;
    error = null;
    try {
      if (protect !== 'observe' && !neverBan.trim()) {
        error = t('ob.neverBanNeed');
        busy = false;
        return;
      }
      const changes: Record<string, unknown> = {
        'ui.lang': ui.lang,
        'response.mode': protect,
        'telegram.enabled': !skipTg && Boolean(botToken && chatId),
        'web.enabled': false,
        'agent.enabled': true,
      };
      if (neverBan.trim()) {
        changes['response.never_ban_cidrs'] = neverBan.trim();
      }
      await api.settingsApply(changes);
      if (!skipTg && (botToken || chatId)) {
        await api.homeWriteEnv(botToken || undefined, chatId || undefined);
      }
      await api.onboardingDone();
      // Real background protect (systemd --user), not session dry-run Start.
      const pe = await api.protectEnable();
      if (pe.ok === false) {
        error = String(pe.error || pe.detail || 'protect enable failed');
      } else if (pe.hint) {
        error = null;
      }
      lingerHint = typeof pe.hint === 'string' ? pe.hint : null;
      finished = true;
      ui.onboardingDone = true;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="wizard">
  <div class="wizard-card">
    {#if finished}
      <div class="wizard-step">
        <h1>{t('ob.doneTitle')}</h1>
        <p class="lead">{t('ob.doneLead')}</p>
        <p class="muted">{t('home.keepAliveActive')}</p>
        {#if lingerHint}<div class="notice warn">{lingerHint}</div>{/if}
        <div class="wizard-actions">
          <button class="btn primary" onclick={() => (ui.section = 'home')}>{t('nav.home')}</button>
        </div>
      </div>
    {:else}
      <div class="progress-dots">
        {#each Array(total) as _, i}
          <span class:on={i <= step}></span>
        {/each}
      </div>

      {#if error}<div class="notice error" style="margin-bottom: 12px">{error}</div>{/if}

      {#key step}
      <div class="wizard-step">
        {#if step === 0}
          <h1>{t('ob.s1')}</h1>
          <div class="choice-grid">
            <button class="choice" class:active={ui.lang === 'en'} onclick={() => setLang('en' as Lang)}>
              <div class="title">English</div>
            </button>
            <button class="choice" class:active={ui.lang === 'ru'} onclick={() => setLang('ru' as Lang)}>
              <div class="title">Русский</div>
            </button>
          </div>
        {:else if step === 1}
          <h1>{t('ob.s2')}</h1>
          <div class="choice-grid">
            <button class="choice" class:active={ui.theme === 'light'} onclick={() => setTheme('light')}>
              <div class="title">{t('set.themeLight')}</div>
            </button>
            <button class="choice" class:active={ui.theme === 'dark'} onclick={() => setTheme('dark')}>
              <div class="title">{t('set.themeDark')}</div>
            </button>
          </div>
        {:else if step === 2}
          <h1>{t('ob.s3')}</h1>
          <div class="choice-grid">
            <button class="choice" class:active={role === 'ssh'} onclick={() => (role = 'ssh')}>
              <div class="title">{t('ob.roleSsh')}</div>
            </button>
            <button class="choice" class:active={role === 'web'} onclick={() => (role = 'web')}>
              <div class="title">{t('ob.roleWeb')}</div>
            </button>
            <button class="choice" class:active={role === 'other'} onclick={() => (role = 'other')}>
              <div class="title">{t('ob.roleOther')}</div>
            </button>
          </div>
        {:else if step === 3}
          <h1>{t('ob.s4')}</h1>
          <div class="choice-grid">
            <button class="choice" class:active={protect === 'observe'} onclick={() => (protect = 'observe')}>
              <div class="title">{t('ob.protObserve')}</div>
              <div class="hint">{t('mode.observeHint')}</div>
            </button>
            <button class="choice" class:active={protect === 'shield'} onclick={() => (protect = 'shield')}>
              <div class="title">{t('ob.protShield')}</div>
              <div class="hint">{t('mode.shieldHint')}</div>
            </button>
            <button class="choice" class:active={protect === 'aggressive'} onclick={() => (protect = 'aggressive')}>
              <div class="title">{t('ob.protAggressive')}</div>
              <div class="hint">{t('mode.aggressiveHint')}</div>
            </button>
            <button class="choice" class:active={protect === 'isolate'} onclick={() => (protect = 'isolate')}>
              <div class="title">{t('ob.protIsolate')}</div>
              <div class="hint">{t('mode.isolateHint')}</div>
            </button>
          </div>
        {:else if step === 4}
          <h1>{t('ob.neverBan')}</h1>
          <p class="lead">{t('ob.neverBanLead')}</p>
          <div class="field">
            <textarea
              rows="3"
              bind:value={neverBan}
              placeholder={"203.0.113.10\n198.51.100.20/32"}
              disabled={skipNeverBan}
            ></textarea>
          </div>
          <p class="muted" style="font-size: 12px">curl -4 ifconfig.me</p>
          {#if protect === 'observe'}
            <button class="btn" style="margin-top: 12px" onclick={trySkipNeverBan}>
              {skipNeverBan ? t('ob.neverBanSkipOn') : t('ob.neverBanSkip')}
            </button>
          {:else}
            <p class="notice warn" style="margin-top: 12px">{t('ob.neverBanSkipBlocked')}</p>
          {/if}
        {:else if step === 5}
          <h1>{t('ob.s5')}</h1>
          <p class="lead">{t('set.basicLead')}</p>
          {#if !skipTg}
            <div class="stack">
              <div class="field">
                <label for="tok">{t('set.telegramToken')}</label>
                <input id="tok" type="password" bind:value={botToken} />
              </div>
              <div class="field">
                <label for="chat">{t('set.telegramChat')}</label>
                <input id="chat" type="text" bind:value={chatId} />
              </div>
            </div>
          {/if}
          <button class="btn" style="margin-top: 12px" onclick={() => (skipTg = !skipTg)}>
            {t('ob.tgSkip')}
          </button>
        {:else if step === 6}
          <h1>{t('ob.s6')}</h1>
          <div class="notice warn">{t('set.mlWarn')}</div>
          <p class="muted" style="margin-top: 12px">{t('set.mlHow')}</p>
          <p class="muted">{t('ob.mlSkip')}</p>
        {:else}
          <h1>{t('ob.finish')}</h1>
          <p class="lead">{t('ob.doneLead')}</p>
        {/if}
      </div>
      {/key}

      <div class="wizard-actions">
        {#if step > 0}
          <button class="btn" onclick={back}>{t('ob.back')}</button>
        {/if}
        <span class="spacer"></span>
        {#if step < total - 1}
          <button class="btn primary" onclick={next}>{t('ob.next')}</button>
        {:else}
          <button class="btn primary" disabled={busy} onclick={finish}>{t('ob.finish')}</button>
        {/if}
      </div>
    {/if}
  </div>
</div>
