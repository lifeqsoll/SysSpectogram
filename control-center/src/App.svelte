<script lang="ts">
  import { onMount } from 'svelte';
  import { ADVANCED_SECTIONS, SIMPLE_SECTIONS, applyThemeToDom, setLang as setLangState, ui } from './lib/state.svelte';
  import { t } from './lib/i18n';
  import { live, startLive } from './lib/live.svelte';
  import { api } from './lib/api';
  import type { Lang } from './lib/settings';

  async function setLang(lang: Lang): Promise<void> {
    setLangState(lang);
    try {
      await api.settingsApply({ 'ui.lang': lang });
    } catch {
      /* overlay may be unavailable before helper — UI lang still updates */
    }
  }
  import Icon from './lib/Icon.svelte';
  import brandMark from './assets/brand-mark.svg?raw';
  import Home from './views/Home.svelte';
  import Fleet from './views/Fleet.svelte';
  import Charts from './views/Charts.svelte';
  import Alerts from './views/Alerts.svelte';
  import BasicSettings from './views/BasicSettings.svelte';
  import Onboarding from './views/Onboarding.svelte';
  import Bootstrap from './views/Bootstrap.svelte';
  import Overview from './views/Overview.svelte';
  import Live from './views/Live.svelte';
  import Dashboards from './views/Dashboards.svelte';
  import Incidents from './views/Incidents.svelte';
  import Agent from './views/Agent.svelte';
  import Perimeter from './views/Perimeter.svelte';
  import Settings from './views/Settings.svelte';
  import Scenarios from './views/Scenarios.svelte';
  import Lab from './views/Lab.svelte';
  import Install from './views/Install.svelte';
  import Logs from './views/Logs.svelte';
  import About from './views/About.svelte';

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const VIEWS: Record<string, any> = {
    home: Home,
    fleet: Fleet,
    charts: Charts,
    alerts: Alerts,
    settings: BasicSettings,
    overview: Overview,
    live: Live,
    dashboards: Dashboards,
    incidents: Incidents,
    agent: Agent,
    perimeter: Perimeter,
    settingsAdvanced: Settings,
    scenarios: Scenarios,
    lab: Lab,
    install: Install,
    logs: Logs,
    about: About,
  };

  const View = $derived(VIEWS[ui.section] ?? Home);

  const iconFor = (s: string): string => {
    if (s === 'home') return 'overview';
    if (s === 'fleet') return 'perimeter';
    if (s === 'charts') return 'dashboards';
    if (s === 'alerts') return 'incidents';
    if (s === 'settingsAdvanced') return 'settings';
    return s;
  };

  let lastNotifiedRisk = 0;
  let lastNotifiedIncident = '';

  async function maybeNotifyCritical(): Promise<void> {
    try {
      if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
        await Notification.requestPermission();
      }
      if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;

      const risk = live.values.host_risk?.value ?? live.values.agent_score?.value ?? 0;
      const now = Date.now() / 1000;
      if (risk >= 0.85 && now - lastNotifiedRisk > 120) {
        lastNotifiedRisk = now;
        new Notification('SysSpectogram', {
          body: ui.lang === 'ru' ? `Высокий риск хоста: ${risk.toFixed(2)}` : `High host risk: ${risk.toFixed(2)}`,
        });
      }

      const incs = await api.incidentsList(20);
      const crit = incs
        .filter((i) => i.severity === 'critical' || i.severity === 'high')
        .sort((a, b) => b.last_ts - a.last_ts)[0];
      if (crit && crit.id !== lastNotifiedIncident && now - crit.last_ts < 300) {
        lastNotifiedIncident = crit.id;
        new Notification('SysSpectogram', {
          body: crit.reason || crit.rules?.[0] || crit.id,
        });
      }
    } catch {
      /* ignore */
    }
  }

  onMount(() => {
    applyThemeToDom();
    startLive().catch((e) => console.error('live subscription failed', e));
    api
      .bootstrapStatus()
      .then((st) => {
        // Dev checkout or already-installed stack skips the bootstrap screen.
        ui.bootstrapDone = Boolean(st.dev_checkout || st.stack_ready);
      })
      .catch(() => {
        ui.bootstrapDone = true;
      });
    api
      .onboardingStatus()
      .then((st) => {
        ui.onboardingDone = Boolean(st.done);
      })
      .catch(() => {
        ui.onboardingDone = true;
      });
    const timer = setInterval(() => {
      void maybeNotifyCritical();
    }, 15000);
    return () => clearInterval(timer);
  });

  $effect(() => {
    applyThemeToDom();
  });
</script>

{#if !ui.bootstrapDone}
  <Bootstrap />
{:else if !ui.onboardingDone}
  <Onboarding />
{:else}
  <div class="shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="mark" aria-hidden="true">{@html brandMark}</span>
        <div>
          <div class="name">{t('app.name')}</div>
          <div class="sub">{t('app.subtitleSimple')}</div>
        </div>
      </div>
      <nav aria-label="Sections">
        {#each SIMPLE_SECTIONS as s (s)}
          <button class:active={ui.section === s} onclick={() => (ui.section = s)}>
            <Icon name={iconFor(s)} size={18} />
            <span>{t(`nav.${s}`)}</span>
          </button>
        {/each}
        {#if ui.advanced}
          <div class="nav-label">Advanced</div>
          {#each ADVANCED_SECTIONS as s (s)}
            <button class:active={ui.section === s} onclick={() => (ui.section = s)}>
              <Icon name={iconFor(s)} size={18} />
              <span>{t(`nav.${s}`)}</span>
            </button>
          {/each}
        {/if}
      </nav>
      <div class="lang">
        <button class:active={ui.lang === 'en'} onclick={() => setLang('en')}>EN</button>
        <button class:active={ui.lang === 'ru'} onclick={() => setLang('ru')}>RU</button>
      </div>
    </aside>
    <main>
      <View />
    </main>
  </div>
{/if}
