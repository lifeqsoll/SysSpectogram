<script lang="ts">
  import { applyResults, fleetApi } from '../lib/fleet';
  import { hostHasToken, type ConfirmKind, type Host, type HostResult } from '../lib/types';

  type Props = {
    host: Host;
    lang: 'en' | 'ru';
    requestConfirm: (kind: ConfirmKind, run: () => Promise<void>) => void;
    onback?: (() => void) | null;
  };

  let { host, lang, requestConfirm, onback = null }: Props = $props();

  let banIp = $state('');
  let log = $state('');
  let resultRows = $state<HostResult[]>([]);
  let showRaw = $state(false);

  const scope = $derived(host.id);

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
    requestConfirm(level, () => run(`attack ${level}`, () => fleetApi.attack(scope, level, false)));
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
</script>

<section class="shell">
  <header class="row">
    {#if onback}
      <button type="button" class="ghost" onclick={onback}>← {lang === 'ru' ? 'Обзор' : 'Overview'}</button>
    {/if}
    <div>
      <h1>{host.label || host.id}</h1>
      <p class="meta mono">
        {host.id} · {host.role} · {host.ssh} · token:
        {hostHasToken(host) ? (lang === 'ru' ? 'да' : 'yes') : lang === 'ru' ? 'нет' : 'no'}
        · pin: {(host.host_key_line || '').trim() ? (lang === 'ru' ? 'да' : 'yes') : lang === 'ru' ? 'нет' : 'no'}
      </p>
    </div>
  </header>

  <div class="toolbar">
    <button type="button" onclick={status}>{lang === 'ru' ? 'Статус' : 'Status'}</button>
    <button type="button" onclick={unlock}>Unlock locked</button>
    <button type="button" class="warn" onclick={() => attack('L2')}>Attack L2</button>
    <button type="button" class="danger" onclick={() => attack('L3')}>Attack L3</button>
    <button type="button" onclick={release}>Release</button>
    <button type="button" onclick={warmup}>Warmup</button>
    <button type="button" onclick={incidents}>
      {lang === 'ru' ? 'Инциденты' : 'Incidents'}
    </button>
    <label>
      ban IP
      <input bind:value={banIp} placeholder="203.0.113.10" />
    </label>
    <button type="button" class="danger" onclick={ban}>Ban</button>
  </div>

  {#if resultRows.length}
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
  .row { display: flex; gap: 0.75rem; align-items: flex-start; }
  h1 { font-size: 1.4rem; margin: 0 0 0.2rem; }
  .meta { color: var(--ink-soft); margin: 0; }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 1rem 0;
    align-items: end;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    font-size: 0.75rem;
    color: var(--ink-soft);
  }
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
    margin-bottom: 0.75rem;
  }
  th,
  td {
    text-align: left;
    padding: 0.4rem 0.5rem;
    border-bottom: 1px solid var(--line);
  }
  .log {
    margin-top: 0.5rem;
    padding: 0.75rem;
    background: #0b0f14;
    border-radius: 8px;
    overflow: auto;
    max-height: 280px;
    font-size: 0.75rem;
  }
</style>
