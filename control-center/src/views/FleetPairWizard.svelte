<script lang="ts">
  import { invoke } from '@tauri-apps/api/core';
  import { ui } from '../lib/state.svelte';

  let { onDone }: { onDone?: () => void } = $props();

  let ssh = $state('');
  let homePath = $state('');
  let label = $state('');
  let hostId = $state('');
  let identity = $state('');
  let hostKeyLine = $state('');
  let pairCode = $state('');
  let finishCode = $state('');
  let step = $state(1);
  let busy = $state(false);
  let err = $state('');
  let info = $state('');
  let tokenOnce = $state('');

  function ru() {
    return ui.lang === 'ru';
  }

  async function startPair() {
    busy = true;
    err = '';
    info = '';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_pair_start', {
        ssh: ssh.trim(),
        home: homePath.trim(),
        label: label.trim() || hostId.trim() || 'device',
        identity: identity.trim() || null,
        hostKeyLine: hostKeyLine.trim() || null,
      });
      if (!r.ok) throw new Error(String(r.error || 'pair-start failed'));
      pairCode = String(r.pair_code || '');
      finishCode = pairCode;
      info = JSON.stringify(r, null, 2);
      step = 2;
    } catch (e) {
      err = String(e);
    } finally {
      busy = false;
    }
  }

  async function keyscan() {
    busy = true;
    err = '';
    try {
      const r = await invoke<Record<string, unknown>>('fleet_keyscan', { ssh: ssh.trim() });
      if (r.ok && r.host_key_line) {
        hostKeyLine = String(r.host_key_line);
      } else {
        err = String(r.error || 'keyscan failed');
      }
    } catch (e) {
      err = String(e);
    } finally {
      busy = false;
    }
  }

  async function finishPair() {
    busy = true;
    err = '';
    try {
      if (!hostId.trim()) throw new Error('host id required');
      const r = await invoke<Record<string, unknown>>('fleet_pair_finish', {
        ssh: ssh.trim(),
        home: homePath.trim(),
        code: finishCode.trim(),
        id: hostId.trim(),
        label: label.trim() || hostId.trim(),
        role: 'worker',
        identity: identity.trim() || null,
        hostKeyLine: hostKeyLine.trim() || null,
      });
      if (!r.ok) throw new Error(String(r.error || 'pair-finish failed'));
      tokenOnce = String(r.device_token || '');
      info = JSON.stringify({ ...r, device_token: tokenOnce ? '(stored)' : null }, null, 2);
      step = 3;
      onDone?.();
    } catch (e) {
      err = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<section class="wiz">
  <h2>{ru() ? 'Добавить хост (pair)' : 'Add host (pair)'}</h2>
  <p class="hint">
    {ru()
      ? 'SSH → pair-remote на VPS → код → pair-complete → fleet.json. Код не в Telegram.'
      : 'SSH → pair-remote on VPS → code → pair-complete → fleet.json. Never send code via Telegram.'}
  </p>

  {#if step === 1}
    <div class="grid">
      <label>ssh<input bind:value={ssh} placeholder="user@vps" /></label>
      <label>home_path<input bind:value={homePath} placeholder="/home/user/SysSpectogram" /></label>
      <label>host id<input bind:value={hostId} placeholder="web1" /></label>
      <label>label<input bind:value={label} placeholder="web1" /></label>
      <label>identity (opt)<input bind:value={identity} placeholder="~/.ssh/id_ed25519" /></label>
      <label>host_key_line<textarea rows="2" bind:value={hostKeyLine} placeholder="ssh-ed25519 AAAA…"></textarea></label>
    </div>
    <div class="row">
      <button type="button" disabled={busy || !ssh.trim()} onclick={keyscan}>
        {ru() ? 'ssh-keyscan' : 'ssh-keyscan'}
      </button>
      <button type="button" class="primary" disabled={busy || !ssh.trim()} onclick={startPair}>
        {ru() ? 'Старт pair' : 'Start pair'}
      </button>
    </div>
  {:else if step === 2}
    <p class="code-label">{ru() ? 'Код (5 мин)' : 'Code (5 min)'}</p>
    <p class="code">{pairCode || '—'}</p>
    <label
      >{ru() ? 'Введите код' : 'Enter code'}<input bind:value={finishCode} autocomplete="off" /></label
    >
    <div class="row">
      <button type="button" class="ghost" onclick={() => (step = 1)}>{ru() ? 'Назад' : 'Back'}</button>
      <button type="button" class="primary" disabled={busy || !finishCode.trim()} onclick={finishPair}>
        {ru() ? 'Завершить + добавить' : 'Finish + add'}
      </button>
    </div>
  {:else}
    <p class="ok">{ru() ? 'Хост в fleet.json' : 'Host saved in fleet.json'}</p>
    {#if tokenOnce}
      <p class="hint mono">{ru() ? 'Токен сохранён локально (не показываем снова в таблице).' : 'Token stored locally (masked in table).'}</p>
    {/if}
    <button type="button" onclick={() => { step = 1; pairCode = ''; tokenOnce = ''; }}
      >{ru() ? 'Ещё хост' : 'Add another'}</button
    >
  {/if}

  {#if err}<p class="err">{err}</p>{/if}
  {#if info}<pre class="log">{info}</pre>{/if}
</section>

<style>
  .wiz {
    margin: 1rem 0 1.5rem;
    padding: 1rem;
    border: 1px solid var(--line, #2a333c);
    border-radius: 10px;
  }
  h2 {
    margin: 0 0 0.35rem;
    font-size: 1.1rem;
  }
  .hint {
    color: var(--ink-soft, #9aa7b2);
    font-size: 0.85rem;
  }
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 0.5rem;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    font-size: 0.75rem;
    color: var(--ink-soft, #9aa7b2);
  }
  input,
  textarea,
  button {
    font: inherit;
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line, #2a333c);
    background: var(--panel, #141a20);
    color: inherit;
  }
  .row {
    display: flex;
    gap: 0.5rem;
    margin-top: 0.75rem;
  }
  button.primary {
    border-color: #3b82f6;
  }
  button.ghost {
    opacity: 0.85;
  }
  .code {
    font-size: 1.6rem;
    letter-spacing: 0.12em;
    font-family: ui-monospace, monospace;
    margin: 0.25rem 0 0.75rem;
  }
  .code-label {
    margin: 0.5rem 0 0;
    font-size: 0.8rem;
    color: var(--ink-soft, #9aa7b2);
  }
  .err {
    color: #f87171;
  }
  .ok {
    color: #4ade80;
  }
  .mono {
    font-family: ui-monospace, monospace;
  }
  .log {
    margin-top: 0.75rem;
    padding: 0.6rem;
    background: #0b0f14;
    border-radius: 8px;
    font-size: 0.72rem;
    max-height: 160px;
    overflow: auto;
  }
  @media (max-width: 700px) {
    .grid {
      grid-template-columns: 1fr;
    }
  }
</style>
