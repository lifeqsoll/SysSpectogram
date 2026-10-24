<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { ui } from '../lib/state.svelte';

  type Host = {
    id: string;
    label: string;
    ssh: string;
    role: string;
    device_token?: string;
    profile_id?: string | null;
  };
  type Edge = { from: string; to: string; kind: string; note?: string };
  type Profile = { id: string; label: string; settings: Record<string, unknown> };
  type Group = { id: string; label: string; host_ids: string[] };

  let loading = $state(true);
  let err = $state('');
  let primary = $state<string | null>(null);
  let hosts = $state<Host[]>([]);
  let edges = $state<Edge[]>([]);
  let profiles = $state<Profile[]>([]);
  let groups = $state<Group[]>([]);
  let dependents = $state<Record<string, string[]>>({});
  let scope = $state('all');
  let profileId = $state('');
  let attackDeps = $state(false);
  let log = $state('');
  let warmupLocal = $state('');

  async function refresh() {
    loading = true;
    err = '';
    try {
      const r = await invoke<{
        ok: boolean;
        primary_host_id?: string | null;
        hosts?: Host[];
        edges?: Edge[];
        profiles?: Profile[];
        groups?: Group[];
        dependents?: Record<string, string[]>;
        error?: string;
      }>('fleet_graph');
      if (!r.ok) throw new Error(r.error || 'fleet graph failed');
      primary = r.primary_host_id ?? null;
      hosts = r.hosts || [];
      edges = r.edges || [];
      profiles = r.profiles || [];
      groups = r.groups || [];
      dependents = r.dependents || {};
      if (!profileId && profiles.length) profileId = profiles[0].id;
    } catch (e) {
      err = String(e);
      try {
        const r = await invoke<{
          ok: boolean;
          primary_host_id?: string | null;
          hosts?: Host[];
          error?: string;
        }>('fleet_list');
        if (r.ok) {
          primary = r.primary_host_id ?? null;
          hosts = r.hosts || [];
          err = '';
        }
      } catch {
        /* keep err */
      }
    } finally {
      loading = false;
    }
  }

  async function runStatus() {
    log = ui.lang === 'ru' ? 'статус…' : 'status…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_status', { scope });
      log = JSON.stringify(r, null, 2);
    } catch (e) {
      log = String(e);
    }
  }

  async function runUnlock() {
    log = 'unlock locked…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_unlock_locked', { scope });
      log = JSON.stringify(r, null, 2);
    } catch (e) {
      log = String(e);
    }
  }

  async function runAttack(level: string) {
    log = `attack ${level}…`;
    try {
      const r = await invoke<Record<string, unknown>>('fleet_attack', {
        scope,
        level,
        deps: attackDeps,
      });
      log = JSON.stringify(r, null, 2);
    } catch (e) {
      log = String(e);
    }
  }

  async function runRelease() {
    log = 'release…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_release', { scope });
      log = JSON.stringify(r, null, 2);
    } catch (e) {
      log = String(e);
    }
  }

  async function runWarmup() {
    log = 'warmup…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_warmup', { scope: 'local' });
      warmupLocal = JSON.stringify(r, null, 2);
      log = warmupLocal;
    } catch (e) {
      log = String(e);
    }
  }

  async function runApplyProfile() {
    if (!profileId) {
      log = 'no profile selected';
      return;
    }
    log = `apply ${profileId}…`;
    try {
      const r = await invoke<Record<string, unknown>>('fleet_profile_apply', {
        id: profileId,
        scope,
      });
      log = JSON.stringify(r, null, 2);
    } catch (e) {
      log = String(e);
    }
  }

  onMount(refresh);
</script>

<section class="fleet">
  <header>
    <h1>{ui.lang === 'ru' ? 'Флот' : 'Fleet'}</h1>
    <p class="lede">
      {ui.lang === 'ru'
        ? 'Несколько VPS с админского ПК (SSH + device token). Профили, граф зависимостей, warmup, Attack/Release.'
        : 'Many VPS from this PC (SSH + device token). Profiles, dependency graph, warmup, Attack/Release.'}
    </p>
  </header>

  {#if loading}
    <p class="muted">…</p>
  {:else if err}
    <p class="err">{err}</p>
    <p class="hint">
      {ui.lang === 'ru'
        ? 'Добавьте хосты: python -m sysspectogram fleet add --id … --ssh user@host --device-token …'
        : 'Add hosts: python -m sysspectogram fleet add --id … --ssh user@host --device-token …'}
    </p>
  {:else}
    <p class="meta">
      primary: <strong>{primary || '—'}</strong> · hosts: <strong>{hosts.length}</strong> · edges:
      <strong>{edges.length}</strong> · profiles: <strong>{profiles.length}</strong>
    </p>
    <div class="toolbar">
      <label>
        scope
        <select bind:value={scope}>
          <option value="all">all</option>
          {#each groups as g}
            <option value={`group:${g.id}`}>group:{g.label}</option>
          {/each}
          {#each hosts as h}
            <option value={h.id}>{h.role === 'primary' ? '★ ' : ''}{h.label}</option>
          {/each}
        </select>
      </label>
      <label class="check">
        <input type="checkbox" bind:checked={attackDeps} />
        {ui.lang === 'ru' ? 'Attack + deps' : 'Attack + deps'}
      </label>
      <button type="button" onclick={runStatus}>{ui.lang === 'ru' ? 'Статус' : 'Status'}</button>
      <button type="button" onclick={runUnlock}>Unlock locked</button>
      <button type="button" class="warn" onclick={() => runAttack('L2')}>Attack L2</button>
      <button type="button" class="danger" onclick={() => runAttack('L3')}>Attack L3</button>
      <button type="button" onclick={runRelease}>Release</button>
      <button type="button" onclick={runWarmup}>Warmup</button>
      <button type="button" class="ghost" onclick={refresh}>{ui.lang === 'ru' ? 'Обновить' : 'Refresh'}</button>
    </div>

    {#if profiles.length}
      <div class="toolbar">
        <label>
          profile
          <select bind:value={profileId}>
            {#each profiles as p}
              <option value={p.id}>{p.label}</option>
            {/each}
          </select>
        </label>
        <button type="button" onclick={runApplyProfile}>
          {ui.lang === 'ru' ? 'Применить профиль' : 'Apply profile'}
        </button>
      </div>
    {/if}

    <table>
      <thead>
        <tr>
          <th>id</th>
          <th>label</th>
          <th>role</th>
          <th>ssh</th>
          <th>deps</th>
          <th>token</th>
        </tr>
      </thead>
      <tbody>
        {#each hosts as h}
          <tr class:primary={h.id === primary}>
            <td class="mono">{h.id}</td>
            <td>{h.label}</td>
            <td>{h.role}</td>
            <td class="mono">{h.ssh}</td>
            <td class="mono">{(dependents[h.id] || []).join(', ') || '—'}</td>
            <td class="mono">{h.device_token || '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>

    {#if edges.length}
      <h2>{ui.lang === 'ru' ? 'Граф' : 'Graph'}</h2>
      <ul class="edges">
        {#each edges as e}
          <li class="mono">{e.from} —{e.kind}→ {e.to}{e.note ? ` (${e.note})` : ''}</li>
        {/each}
      </ul>
    {/if}
  {/if}

  {#if log}
    <pre class="log">{log}</pre>
  {/if}

  <p class="hint">
    {ui.lang === 'ru'
      ? 'Документация: docs/FLEET.md · CLI: fleet graph / profile-set / edge-add / warmup'
      : 'Docs: docs/FLEET.md · CLI: fleet graph / profile-set / edge-add / warmup'}
  </p>
</section>

<style>
  .fleet {
    padding: 1.25rem 1.5rem 2rem;
    max-width: 960px;
  }
  h1 {
    font-size: 1.6rem;
    margin: 0 0 0.35rem;
  }
  h2 {
    font-size: 1.05rem;
    margin: 1.25rem 0 0.4rem;
  }
  .lede {
    color: var(--ink-soft, #9aa7b2);
    margin: 0 0 1rem;
    max-width: 42rem;
  }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.75rem 0 1rem;
    align-items: end;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    font-size: 0.75rem;
    color: var(--ink-soft, #9aa7b2);
  }
  label.check {
    flex-direction: row;
    align-items: center;
    gap: 0.35rem;
    padding-bottom: 0.35rem;
  }
  select,
  button {
    font: inherit;
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line, #2a333c);
    background: var(--panel, #141a20);
    color: inherit;
    cursor: pointer;
  }
  button.warn {
    border-color: #b45309;
  }
  button.danger {
    border-color: #b91c1c;
  }
  button.ghost {
    opacity: 0.85;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--line, #2a333c);
  }
  tr.primary td {
    color: #f0a060;
  }
  .mono {
    font-family: ui-monospace, monospace;
    font-size: 0.8rem;
  }
  .edges {
    margin: 0;
    padding-left: 1.1rem;
    color: var(--ink-soft, #9aa7b2);
    font-size: 0.85rem;
  }
  .err {
    color: #f87171;
  }
  .hint,
  .muted,
  .meta {
    color: var(--ink-soft, #9aa7b2);
    font-size: 0.85rem;
  }
  .log {
    margin-top: 1rem;
    padding: 0.75rem;
    background: #0b0f14;
    border-radius: 8px;
    overflow: auto;
    max-height: 280px;
    font-size: 0.75rem;
  }
</style>
