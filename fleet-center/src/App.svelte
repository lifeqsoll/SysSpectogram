<script lang="ts">
  import { onMount } from 'svelte';
  import { loadGraph } from './lib/fleet';
  import type { ConfirmKind, Edge, Group, Host, Profile } from './lib/types';
  import ConfirmModal from './views/ConfirmModal.svelte';
  import EdgePanel from './views/EdgePanel.svelte';
  import HostShell from './views/HostShell.svelte';
  import Overview from './views/Overview.svelte';
  import PairWizard from './views/PairWizard.svelte';

  let lang = $state<'en' | 'ru'>('en');
  let loading = $state(true);
  let err = $state('');
  let primary = $state<string | null>(null);
  let hosts = $state<Host[]>([]);
  let edges = $state<Edge[]>([]);
  let profiles = $state<Profile[]>([]);
  let groups = $state<Group[]>([]);
  let dependents = $state<Record<string, string[]>>({});

  /** Force pair wizard even when hosts exist (N≥2 add button). */
  let forceWizard = $state(false);
  /** Drill-down host when N≥2. */
  let selected = $state<Host | null>(null);

  let confirmOpen = $state(false);
  let confirmKind = $state<ConfirmKind>('L3');
  let confirmPending: (() => Promise<void>) | null = null;

  const n = $derived(hosts.length);
  const mode = $derived(
    forceWizard || n === 0 ? 'empty' : n === 1 && !selected ? 'single' : selected ? 'host' : 'multi',
  );

  function requestConfirm(kind: ConfirmKind, run: () => Promise<void>) {
    confirmKind = kind;
    confirmPending = run;
    confirmOpen = true;
  }

  async function acceptConfirm() {
    const fn = confirmPending;
    confirmOpen = false;
    confirmPending = null;
    if (fn) await fn();
  }

  function confirmMessage(): string {
    if (confirmKind === 'EDGE') {
      return lang === 'ru'
        ? 'Включит Cloudflare Under Attack на зоне из .env. Введите EDGE.'
        : 'Enables Cloudflare Under Attack on the .env zone. Type EDGE.';
    }
    if (confirmKind === 'PROFILE') {
      return lang === 'ru'
        ? 'Запушит настройки профиля на выбранный scope по SSH. Введите PROFILE.'
        : 'Pushes profile settings to the selected scope over SSH. Type PROFILE.';
    }
    const scopeHint =
      mode === 'multi'
        ? lang === 'ru'
          ? `хостов: ${hosts.length}`
          : `hosts: ${hosts.length}`
        : selected
          ? selected.id
          : hosts[0]?.id || '—';
    return lang === 'ru'
      ? `${scopeHint}. Введите ${confirmKind} для продолжения.`
      : `${scopeHint}. Type ${confirmKind} to continue.`;
  }

  async function refresh() {
    loading = true;
    err = '';
    try {
      const r = await loadGraph();
      if (!r.ok && r.error) throw new Error(r.error);
      primary = r.primary_host_id ?? null;
      hosts = r.hosts || [];
      edges = r.edges || [];
      profiles = r.profiles || [];
      groups = r.groups || [];
      dependents = r.dependents || {};
      forceWizard = false;
      if (selected && !hosts.find((h) => h.id === selected?.id)) {
        selected = null;
      }
    } catch (e) {
      err = String(e);
      hosts = [];
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void refresh();
  });
</script>

<div class="app">
  <header class="top">
    <div>
      <strong>SysSpectogram Fleet Hub</strong>
      <span class="muted"> · {n} host{n === 1 ? '' : 's'}</span>
    </div>
    <div class="lang">
      <button type="button" class:active={lang === 'en'} onclick={() => (lang = 'en')}>EN</button>
      <button type="button" class:active={lang === 'ru'} onclick={() => (lang = 'ru')}>RU</button>
    </div>
  </header>

  <main>
    <EdgePanel {lang} {requestConfirm} />

    {#if loading}
      <p class="muted">…</p>
    {:else if err && n === 0}
      <p class="err">{err}</p>
      <PairWizard {lang} ondone={refresh} />
    {:else if mode === 'empty'}
      <PairWizard
        {lang}
        ondone={async () => {
          forceWizard = false;
          await refresh();
        }}
      />
      {#if n > 0}
        <button type="button" class="ghost back" onclick={() => (forceWizard = false)}>
          {lang === 'ru' ? '← Назад к флоту' : '← Back to fleet'}
        </button>
      {/if}
    {:else if mode === 'single'}
      <HostShell host={hosts[0]} {lang} {requestConfirm} />
      <p class="hint add-hint">
        <button type="button" class="ghost" onclick={() => (forceWizard = true)}>
          {lang === 'ru' ? '+ Добавить ещё хост' : '+ Add another host'}
        </button>
      </p>
    {:else if mode === 'host' && selected}
      <HostShell
        host={selected}
        {lang}
        {requestConfirm}
        onback={() => (selected = null)}
      />
    {:else}
      <Overview
        {hosts}
        {edges}
        {profiles}
        {groups}
        {dependents}
        {primary}
        {lang}
        {requestConfirm}
        onselect={(h) => (selected = h)}
        onrefresh={refresh}
        onadd={() => (forceWizard = true)}
      />
    {/if}
  </main>
</div>

<ConfirmModal
  open={confirmOpen}
  kind={confirmKind}
  message={confirmMessage()}
  {lang}
  oncancel={() => (confirmOpen = false)}
  onconfirm={acceptConfirm}
/>

<style>
  .app {
    min-height: 100vh;
    background:
      radial-gradient(ellipse 55% 40% at 8% -5%, color-mix(in srgb, var(--accent) 22%, transparent), transparent 70%),
      var(--bg);
  }
  .top {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.85rem 1.5rem;
    border-bottom: 1px solid var(--border);
    background: color-mix(in srgb, var(--panel) 88%, transparent);
  }
  .lang { display: flex; gap: 0.35rem; }
  .lang button {
    padding: 0.3rem 0.55rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--muted);
    cursor: pointer;
  }
  .lang button.active {
    background: var(--accent);
    color: #061018;
    border-color: transparent;
  }
  main {
    padding: 1.25rem 1.5rem 2rem;
    max-width: 1100px;
  }
  .ghost {
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line);
    background: var(--panel);
    cursor: pointer;
    opacity: 0.9;
  }
  .back { margin-top: 1rem; }
  .add-hint { margin-top: 1.25rem; }
</style>
