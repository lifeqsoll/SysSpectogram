<script lang="ts">
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { ui } from '../lib/state.svelte';
  import FleetPairWizard from './FleetPairWizard.svelte';

  type Host = {
    id: string;
    label: string;
    ssh: string;
    role: string;
    token_set?: boolean;
    device_token?: string;
    profile_id?: string | null;
    host_key_line?: string;
  };
  type Edge = { from: string; to: string; kind: string; note?: string };
  type Profile = { id: string; label: string; settings: Record<string, unknown> };
  type Group = { id: string; label: string; host_ids: string[] };
  type HostResult = {
    host_id: string;
    ok: boolean;
    error?: string;
    latency_ms?: number;
    detail?: Record<string, unknown>;
  };
  type IncidentRow = Record<string, unknown>;

  let loading = $state(true);
  let err = $state('');
  let primary = $state<string | null>(null);
  let hosts = $state<Host[]>([]);
  let edges = $state<Edge[]>([]);
  let profiles = $state<Profile[]>([]);
  let groups = $state<Group[]>([]);
  let dependents = $state<Record<string, string[]>>({});
  let scope = $state('all');
  let groupFilter = $state('all');
  let profileId = $state('');
  let attackDeps = $state(false);
  let banIp = $state('');
  let log = $state('');
  let resultRows = $state<HostResult[]>([]);
  let showRaw = $state(false);
  let showWizard = $state(false);
  let incidentItems = $state<IncidentRow[]>([]);
  let volumetricHint = $state(false);

  let confirmOpen = $state(false);
  let confirmKind = $state<'ATTACK' | 'BAN' | 'UNLOCK' | 'RELEASE' | 'EDGE'>('ATTACK');
  let confirmTyped = $state('');
  let confirmPending: (() => Promise<void>) | null = null;
  let edgeInfo = $state('');
  let edgeBusy = $state(false);

  const filteredHosts = $derived.by(() => {
    if (groupFilter === 'all') return hosts;
    const g = groups.find((x) => x.id === groupFilter || `group:${x.id}` === groupFilter);
    if (!g) return hosts;
    const ids = new Set(g.host_ids);
    return hosts.filter((h) => ids.has(h.id));
  });

  function ru() {
    return ui.lang === 'ru';
  }

  function hostHasToken(h: Host): boolean {
    if (typeof h.token_set === 'boolean') return h.token_set;
    const t = (h.device_token || '').trim();
    return Boolean(t) && t !== '***';
  }

  function openConfirm(kind: typeof confirmKind, run: () => Promise<void>) {
    confirmKind = kind;
    confirmTyped = '';
    confirmPending = run;
    confirmOpen = true;
  }

  async function acceptConfirm() {
    if (confirmTyped.trim().toUpperCase() !== confirmKind) return;
    const fn = confirmPending;
    confirmOpen = false;
    confirmPending = null;
    if (fn) await fn();
  }

  function applyResults(r: Record<string, unknown>) {
    const rows = (r.results as HostResult[]) || [];
    resultRows = rows.map((x) => ({
      host_id: x.host_id,
      ok: Boolean(x.ok),
      error: x.error,
      latency_ms: x.latency_ms,
      detail: x.detail,
    }));
    log = JSON.stringify(r, null, 2);
  }

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
    log = ru() ? 'статус…' : 'status…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_status', { scope });
      applyResults(r);
    } catch (e) {
      log = String(e);
      resultRows = [];
    }
  }

  async function runUnlock() {
    openConfirm('UNLOCK', async () => {
      log = 'unlock locked…';
      try {
        const r = await invoke<Record<string, unknown>>('fleet_unlock_locked', { scope });
        applyResults(r);
      } catch (e) {
        log = String(e);
        resultRows = [];
      }
    });
  }

  async function runAttack(level: string) {
    const go = async () => {
      log = `attack ${level}…`;
      try {
        const r = await invoke<Record<string, unknown>>('fleet_attack', {
          scope,
          level,
          deps: attackDeps,
        });
        applyResults(r);
      } catch (e) {
        log = String(e);
        resultRows = [];
      }
    };
    // L2 and L3 both require typed confirm (security medium fix).
    openConfirm('ATTACK', go);
  }

  async function runRelease() {
    openConfirm('RELEASE', async () => {
      log = 'release…';
      try {
        const r = await invoke<Record<string, unknown>>('fleet_release', { scope });
        applyResults(r);
      } catch (e) {
        log = String(e);
        resultRows = [];
      }
    });
  }

  async function runWarmup() {
    log = 'warmup…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_warmup', { scope });
      applyResults(r);
    } catch (e) {
      log = String(e);
      resultRows = [];
    }
  }

  async function runIncidents() {
    log = 'incidents…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_incidents', { scope, limit: 40 });
      incidentItems = ((r.items as IncidentRow[]) || []).slice(0, 40);
      const text = JSON.stringify(r, null, 2);
      log = text;
      // G5 heuristic badge: many distinct sources / syn-ish rules → suggest Edge
      const blob = text.toLowerCase();
      volumetricHint =
        blob.includes('flow_syn_burst') ||
        blob.includes('volumetric') ||
        incidentItems.length >= 25;
      resultRows = [];
    } catch (e) {
      log = String(e);
      incidentItems = [];
    }
  }

  async function runMarkFp() {
    log = 'mark-fp…';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_mark_fp', {
        scope,
        label: 'host_fp',
      });
      applyResults(r);
    } catch (e) {
      log = String(e);
      resultRows = [];
    }
  }

  async function runApplyProfile() {
    if (!profileId) return;
    openConfirm('ATTACK', async () => {
      log = 'profile-apply…';
      try {
        const r = await invoke<Record<string, unknown>>('fleet_profile_apply', {
          id: profileId,
          scope,
        });
        applyResults(r);
      } catch (e) {
        log = String(e);
        resultRows = [];
      }
    });
  }

  async function runBan() {
    const ip = banIp.trim();
    if (!ip) {
      log = 'enter IP to ban';
      return;
    }
    openConfirm('BAN', async () => {
      log = `ban ${ip}…`;
      try {
        const r = await invoke<Record<string, unknown>>('fleet_ban', {
          scope,
          ip,
          ttl: 3600,
        });
        applyResults(r);
      } catch (e) {
        log = String(e);
        resultRows = [];
      }
    });
  }

  async function edgeStatus() {
    edgeBusy = true;
    try {
      const r = await invoke<Record<string, unknown>>('edge_status', {
        lang: ru() ? 'ru' : 'en',
      });
      edgeInfo = JSON.stringify(r, null, 2);
    } catch (e) {
      edgeInfo = String(e);
    } finally {
      edgeBusy = false;
    }
  }

  async function edgeUnderAttack() {
    openConfirm('EDGE', async () => {
      edgeBusy = true;
      try {
        const r = await invoke<Record<string, unknown>>('edge_under_attack');
        edgeInfo = JSON.stringify(r, null, 2);
      } catch (e) {
        edgeInfo = String(e);
      } finally {
        edgeBusy = false;
      }
    });
  }

  async function edgeClear() {
    openConfirm('EDGE', async () => {
      edgeBusy = true;
      try {
        const r = await invoke<Record<string, unknown>>('edge_clear', { level: 'high' });
        edgeInfo = JSON.stringify(r, null, 2);
      } catch (e) {
        edgeInfo = String(e);
      } finally {
        edgeBusy = false;
      }
    });
  }

  async function edgePlaybook() {
    edgeBusy = true;
    try {
      const r = await invoke<{ playbook?: string; ok?: boolean }>('edge_playbook', {
        lang: ru() ? 'ru' : 'en',
      });
      edgeInfo = r.playbook || JSON.stringify(r, null, 2);
    } catch (e) {
      edgeInfo = String(e);
    } finally {
      edgeBusy = false;
    }
  }

  onMount(() => {
    void refresh();
    void edgeStatus();
  });
</script>

<section class="fleet">
  <header>
    <h1>{ru() ? 'Флот' : 'Fleet'}</h1>
    <p class="lede">
      {ru()
        ? 'Несколько VPS с админского ПК (SSH + device token). Профили, граф, warmup, Attack/Release. Soft-ban ≠ anti-DDoS.'
        : 'Many VPS from this PC (SSH + device token). Profiles, graph, warmup, Attack/Release. Soft-ban ≠ anti-DDoS.'}
    </p>
  </header>

  <div class="edge">
    <h2>Edge / CDN</h2>
    {#if volumetricHint}
      <p class="warn-banner">
        {ru()
          ? 'Похоже на объём / много сигналов — soft-ban не поможет. Используйте Edge / CDN.'
          : 'Likely volumetric / noisy feed — soft ban won’t help. Use Edge / CDN.'}
      </p>
    {/if}
    <p class="hint">
      {ru()
        ? 'Объёмный DDoS — Cloudflare Under Attack или playbook M. Не nft по флоту.'
        : 'Volumetric DDoS — Cloudflare Under Attack or playbook M. Not fleet nft.'}
    </p>
    <div class="toolbar">
      <button type="button" disabled={edgeBusy} onclick={edgeStatus}>Status</button>
      <button type="button" class="danger" disabled={edgeBusy} onclick={edgeUnderAttack}>
        Under Attack
      </button>
      <button type="button" disabled={edgeBusy} onclick={edgeClear}>Clear</button>
      <button type="button" class="ghost" disabled={edgeBusy} onclick={edgePlaybook}>
        Playbook M
      </button>
    </div>
    {#if edgeInfo}
      <pre class="log">{edgeInfo}</pre>
    {/if}
  </div>

  <div class="toolbar">
    <button type="button" class="primary" onclick={() => (showWizard = !showWizard)}>
      {showWizard
        ? ru()
          ? 'Скрыть wizard'
          : 'Hide wizard'
        : ru()
          ? 'Добавить хост (wizard)'
          : 'Add host (wizard)'}
    </button>
  </div>
  {#if showWizard || hosts.length === 0}
    <FleetPairWizard onDone={refresh} />
  {/if}

  {#if loading}
    <p class="muted">…</p>
  {:else if err && hosts.length === 0}
    <p class="err">{err}</p>
  {:else}
    <p class="meta">
      primary: <strong>{primary || '—'}</strong> · hosts: <strong>{hosts.length}</strong> · edges:
      <strong>{edges.length}</strong> · profiles: <strong>{profiles.length}</strong>
    </p>
    <div class="toolbar">
      <label>
        {ru() ? 'фильтр группы' : 'group filter'}
        <select bind:value={groupFilter}>
          <option value="all">all</option>
          {#each groups as g}
            <option value={g.id}>{g.label}</option>
          {/each}
        </select>
      </label>
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
        {ru() ? 'Attack + deps' : 'Attack + deps'}
      </label>
      <button type="button" onclick={runStatus}>{ru() ? 'Статус' : 'Status'}</button>
      <button type="button" onclick={runUnlock}>Unlock locked</button>
      <button type="button" class="warn" onclick={() => runAttack('L2')}>Attack L2</button>
      <button type="button" class="danger" onclick={() => runAttack('L3')}>Attack L3</button>
      <button type="button" onclick={runRelease}>Release</button>
      <button type="button" onclick={runWarmup}>Warmup</button>
      <button type="button" onclick={runIncidents}>
        {ru() ? 'Лента инцидентов' : 'Incidents feed'}
      </button>
      <button type="button" onclick={runMarkFp}>
        {ru() ? 'Ложное (FP)' : 'False positive'}
      </button>
      <label>
        ban IP
        <input bind:value={banIp} placeholder="203.0.113.10" />
      </label>
      <button type="button" class="danger" onclick={runBan}>
        {ru() ? 'Бан IP на scope (флот)' : 'Ban IP on scope (fleet)'}
      </button>
      <button type="button" class="ghost" onclick={refresh}>{ru() ? 'Обновить' : 'Refresh'}</button>
    </div>
    <p class="hint">
      {ru()
        ? 'При brute/scan с одного IP — бан на scope (все eligible). Объёмный DDoS → Edge выше, не этот бан.'
        : 'On brute/scan from one IP — ban on scope (all eligible). Volumetric DDoS → Edge above, not this ban.'}
    </p>

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
          {ru() ? 'Применить профиль' : 'Apply profile'}
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
          <th>pin</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredHosts as h}
          <tr class:primary={h.id === primary}>
            <td class="mono">{h.id}</td>
            <td>{h.label}{#if h.id === primary}<span class="badge">primary</span>{/if}</td>
            <td>{h.role}</td>
            <td class="mono">{h.ssh}</td>
            <td class="mono">{(dependents[h.id] || []).join(', ') || '—'}</td>
            <td>{hostHasToken(h) ? (ru() ? 'да' : 'yes') : (ru() ? 'нет' : 'no')}</td>
            <td>{(h.host_key_line || '').trim() ? (ru() ? 'да' : 'yes') : (ru() ? 'нет' : 'no')}</td>
          </tr>
        {/each}
      </tbody>
    </table>

    {#if incidentItems.length}
      <h2>{ru() ? 'Лента инцидентов' : 'Incidents feed'}</h2>
      <ul class="incidents">
        {#each incidentItems.slice(0, 15) as row}
          <li class="mono">
            {String(row.host_id || '—')} · {String(row.rule_id || row.reason || row.id || JSON.stringify(row).slice(0, 80))}
          </li>
        {/each}
      </ul>
    {/if}

    {#if edges.length}
      <h2>{ru() ? 'Граф' : 'Graph'}</h2>
      <ul class="edges">
        {#each edges as e}
          <li class="mono">{e.from} —{e.kind}→ {e.to}{e.note ? ` (${e.note})` : ''}</li>
        {/each}
      </ul>
    {/if}
  {/if}

  {#if resultRows.length}
    <h2>{ru() ? 'Результат' : 'Results'}</h2>
    <table>
      <thead>
        <tr>
          <th>host</th>
          <th>ok</th>
          <th>error</th>
          <th>ms</th>
        </tr>
      </thead>
      <tbody>
        {#each resultRows as row}
          <tr>
            <td class="mono">{row.host_id}</td>
            <td>{row.ok ? '✓' : '✗'}</td>
            <td class="mono">{row.error || '—'}</td>
            <td class="mono">{row.latency_ms ?? '—'}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}

  {#if log}
    <button type="button" class="ghost" onclick={() => (showRaw = !showRaw)}>
      {showRaw ? (ru() ? 'Скрыть JSON' : 'Hide JSON') : (ru() ? 'Сырой JSON' : 'Raw JSON')}
    </button>
    {#if showRaw}
      <pre class="log">{log}</pre>
    {/if}
  {/if}

  <p class="hint">
    {ru()
      ? 'Документация: docs/FLEET.md · pin: fleet pin-host · mutating ops нужен host_key_line'
      : 'Docs: docs/FLEET.md · pin: fleet pin-host · mutating ops need host_key_line'}
  </p>
</section>

{#if confirmOpen}
  <div class="modal" role="dialog" aria-modal="true">
    <div class="modal-card">
      <h2>{ru() ? 'Подтверждение' : 'Confirm'}</h2>
      <p>
        {confirmKind === 'EDGE'
          ? ru()
            ? 'Включит Cloudflare Under Attack на зоне из .env. Введите EDGE.'
            : 'Enables Cloudflare Under Attack on the .env zone. Type EDGE.'
          : ru()
            ? `Scope: ${scope} · хостов в UI: ${hosts.length}. Введите ${confirmKind} для продолжения.`
            : `Scope: ${scope} · hosts listed: ${hosts.length}. Type ${confirmKind} to continue.`}
      </p>
      <input bind:value={confirmTyped} placeholder={confirmKind} autocomplete="off" />
      <div class="modal-actions">
        <button type="button" class="ghost" onclick={() => (confirmOpen = false)}>
          {ru() ? 'Отмена' : 'Cancel'}
        </button>
        <button
          type="button"
          class="danger"
          disabled={confirmTyped.trim().toUpperCase() !== confirmKind}
          onclick={acceptConfirm}
        >
          {ru() ? 'Выполнить' : 'Run'}
        </button>
      </div>
    </div>
  </div>
{/if}

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
  input,
  button {
    font: inherit;
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line, #2a333c);
    background: var(--panel, #141a20);
    color: inherit;
    cursor: pointer;
  }
  input {
    min-width: 9rem;
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
  button:disabled {
    opacity: 0.4;
    cursor: not-allowed;
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
  .modal {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.55);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 40;
  }
  .modal-card {
    background: var(--panel, #141a20);
    border: 1px solid var(--line, #2a333c);
    border-radius: 10px;
    padding: 1.25rem;
    width: min(420px, 92vw);
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 0.5rem;
  }
  .badge {
    margin-left: 0.35rem;
    font-size: 0.7rem;
    color: #f0a060;
  }
  .warn-banner {
    color: #fbbf24;
    font-size: 0.9rem;
    margin: 0 0 0.5rem;
  }
  .incidents {
    margin: 0;
    padding-left: 1.1rem;
    font-size: 0.8rem;
    color: var(--ink-soft, #9aa7b2);
  }
  button.primary {
    border-color: #3b82f6;
  }
</style>
