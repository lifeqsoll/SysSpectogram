<script lang="ts">
  import { onMount } from 'svelte';
  import { SECTIONS, setLang, ui } from './lib/state.svelte';
  import { t } from './lib/i18n';
  import { startLive } from './lib/live.svelte';
  import Icon from './lib/Icon.svelte';
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

  const VIEWS = {
    overview: Overview,
    live: Live,
    dashboards: Dashboards,
    incidents: Incidents,
    agent: Agent,
    perimeter: Perimeter,
    settings: Settings,
    scenarios: Scenarios,
    lab: Lab,
    install: Install,
    logs: Logs,
    about: About,
  } as const;

  const View = $derived(VIEWS[ui.section]);

  onMount(() => {
    startLive().catch((e) => console.error('live subscription failed', e));
  });
</script>

<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <span class="mark"></span>
      <div>
        <div class="name">{t('app.name')}</div>
        <div class="sub">{t('app.subtitle')}</div>
      </div>
    </div>
    <nav aria-label="Sections">
      {#each SECTIONS as s (s)}
        <button class:active={ui.section === s} onclick={() => (ui.section = s)}>
          <Icon name={s} size={18} />
          <span>{t(`nav.${s}`)}</span>
        </button>
      {/each}
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
