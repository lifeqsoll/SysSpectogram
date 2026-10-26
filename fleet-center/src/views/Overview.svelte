<script lang="ts">
  import { applyResults, fleetApi } from '../lib/fleet';
  import {
    hostHasToken,
    type ConfirmKind,
    type Edge,
    type Group,
    type Host,
    type HostResult,
    type Profile,
  } from '../lib/types';

  type Props = {
    hosts: Host[];
    edges: Edge[];
    profiles: Profile[];
    groups: Group[];
    dependents: Record<string, string[]>;
    primary: string | null;
    lang: 'en' | 'ru';
    requestConfirm: (kind: ConfirmKind, run: () => Promise<void>) => void;
    onselect: (host: Host) => void;
    onrefresh: () => void;
    onadd: () => void;
  };

  let {
    hosts,
    edges,
    profiles,
    groups,
    dependents,
    primary,
    lang,
    requestConfirm,
    onselect,
    onrefresh,
    onadd,
  }: Props = $props();

  let scope = $state('all');
  let profileId = $state('');
  let attackDeps = $state(false);
  let banIp = $state('');
  let log = $state('');
  let resultRows = $state<HostResult[]>([]);
  let showRaw = $state(false);

  $effect(() => {
    if (!profileId && profiles.length) profileId = profiles[0].id;
  });

  async function run(label: string, fn: () => Promise<Record<string, unknown>>) {
    log = `${label}…`;
    try {
      const r = await fn();
      const a = applyResults(r);
      resultRows = a.rows;
      log = a.log;
    } catch (e) {
      log = String(e);
      resultRows = [];
    }
  }

  function status() {
    void run('status', () => fleetApi.status(scope));
  }
  function unlock() {
    requestConfirm('UNLOCK', () => run('unlock', () => fleetApi.unlockLocked(scope)));
  }
  function attack(level: 'L2' | 'L3') {
    requestConfirm(level, () =>
      run(`attack ${level}`, () => fleetApi.attack(scope, level, attackDeps)),
    );
  }
  function release() {
    requestConfirm('RELEASE', () => run('release', () => fleetApi.release(scope)));
  }
  function warmup() {
    void run('warmup', () => fleetApi.warmup(scope));
  }
  async function incidents() {
    log = 'incidents…';
    try {
      const r = await fleetApi.incidents(scope, 40);
      log = JSON.stringify(r, null, 2);
      resultRows = [];
    } catch (e) {
      log = String(e);
    }
  }
  function ban() {
    const ip = banIp.trim();
    if (!ip) {
      log = lang === 'ru' ? 'укажите IP' : 'enter IP to ban';
      return;
    }
    requestConfirm('BAN', () => run(`ban ${ip}`, () => fleetApi.ban(scope, ip)));
  }
  function applyProfile() {
    if (!profileId) return;
    requestConfirm('PROFILE', () =>
      run('profile-apply', () => fleetApi.profileApply(profileId, scope)),
    );
  }
</script>

<section>
  <header>
    <h1>{lang === 'ru' ? 'Флот' : 'Fleet'}</h1>
    <p class="lede">
      {lang === 'ru'
        ? 'Несколько VPS с админского ПК (SSH + device token). Soft-ban ≠ anti-DDoS.'
        : 'Many VPS from this PC (SSH + device token). Soft-ban ≠ anti-DDoS.'}
    </p>
  </header>

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
      Attack + deps
    </label>
    <button type="button" onclick={status}>{lang === 'ru' ? 'Статус' : 'Status'}</button>
    <button type="button" onclick={unlock}>Unlock locked</button>
    <button type="button" class="warn" onclick={() => attack('L2')}>Attack L2</button>
    <button type="button" class="danger" onclick={() => attack('L3')}>Attack L3</button>
    <button type="button" onclick={release}>Release</button>
    <button type="button" onclick={warmup}>Warmup</button>
    <button type="button" onclick={incidents}>
      {lang === 'ru' ? 'Лента инцидентов' : 'Incidents feed'}
    </button>
    <label>
      ban IP
      <input bind:value={banIp} placeholder="203.0.113.10" />
    </label>
    <button type="button" class="danger" onclick={ban}>
      {lang === 'ru' ? 'Бан IP на scope' : 'Ban IP on scope'}
    </button>
    <button type="button" class="ghost" onclick={onrefresh}>
      {lang === 'ru' ? 'Обновить' : 'Refresh'}
    </button>
    <button type="button" class="ghost" onclick={onadd}>
      {lang === 'ru' ? '+ Хост' : '+ Host'}
    </button>
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
      <button type="button" onclick={applyProfile}>
        {lang === 'ru' ? 'Применить профиль' : 'Apply profile'}
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
        <th></th>
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
          <td>{hostHasToken(h) ? (lang === 'ru' ? 'да' : 'yes') : lang === 'ru' ? 'нет' : 'no'}</td>
          <td>{(h.host_key_line || '').trim() ? (lang === 'ru' ? 'да' : 'yes') : lang === 'ru' ? 'нет' : 'no'}</td>
          <td>
            <button type="button" class="ghost" onclick={() => onselect(h)}>
              {lang === 'ru' ? 'Открыть' : 'Open'}
            </button>
          </td>
        </tr>
      {/each}
    </tbody>
  </table>

  {#if edges.length}
    <h2>{lang === 'ru' ? 'Граф' : 'Graph'}</h2>
    <ul class="edges">
      {#each edges as e}
        <li class="mono">{e.from} —{e.kind}→ {e.to}{e.note ? ` (${e.note})` : ''}</li>
      {/each}
    </ul>
  {/if}

  {#if resultRows.length}
    <h2>{lang === 'ru' ? 'Результат' : 'Results'}</h2>
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
      {showRaw ? (lang === 'ru' ? 'Скрыть JSON' : 'Hide JSON') : lang === 'ru' ? 'Сырой JSON' : 'Raw JSON'}
    </button>
    {#if showRaw}
      <pre class="log">{log}</pre>
    {/if}
  {/if}
</section>

<style>
  h1 { font-size: 1.6rem; margin: 0 0 0.35rem; }
  h2 { font-size: 1.05rem; margin: 1.25rem 0 0.4rem; }
  .lede { color: var(--ink-soft); margin: 0 0 1rem; max-width: 42rem; }
  .meta { color: var(--ink-soft); font-size: 0.85rem; }
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
    color: var(--ink-soft);
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
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line);
    background: var(--panel);
    cursor: pointer;
  }
  button.warn { border-color: #b45309; }
  button.danger { border-color: #b91c1c; }
  button.ghost { opacity: 0.85; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.9rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--line);
  }
  tr.primary td { color: #f0a060; }
  .edges {
    margin: 0;
    padding-left: 1.1rem;
    color: var(--ink-soft);
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
