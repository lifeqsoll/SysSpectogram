<script lang="ts">
  import { fleetApi } from '../lib/fleet';

  type Props = {
    lang: 'en' | 'ru';
    ondone: () => void;
  };

  let { lang, ondone }: Props = $props();

  let id = $state('');
  let label = $state('');
  let ssh = $state('');
  let home = $state('');
  let deviceId = $state('');
  let deviceToken = $state('');
  let role = $state('worker');
  let hostKeyLine = $state('');
  let busy = $state(false);
  let err = $state('');
  let note = $state('');

  async function submit() {
    err = '';
    note = '';
    if (!id.trim() || !ssh.trim()) {
      err = lang === 'ru' ? 'Нужны id и ssh' : 'id and ssh are required';
      return;
    }
    if (!deviceToken.trim()) {
      err =
        lang === 'ru'
          ? 'Нужен device_token (один раз с pair-complete на VPS)'
          : 'device_token required (once from pair-complete on the VPS)';
      return;
    }
    busy = true;
    try {
      await fleetApi.add({
        id: id.trim(),
        label: label.trim() || id.trim(),
        ssh: ssh.trim(),
        home: home.trim(),
        deviceId: deviceId.trim(),
        deviceToken: deviceToken.trim(),
        role: role.trim() || 'worker',
      });
      // Clear token from memory/UI immediately — never display it again.
      deviceToken = '';
      if (hostKeyLine.trim()) {
        await fleetApi.pinHost(id.trim(), hostKeyLine.trim());
      }
      note = lang === 'ru' ? 'Хост добавлен. Токен сохранён в fleet.json (0600).' : 'Host added. Token stored in fleet.json (0600).';
      ondone();
    } catch (e) {
      err = String(e);
    } finally {
      busy = false;
    }
  }
</script>

<section class="wizard">
  <h1>{lang === 'ru' ? 'Добавить хост' : 'Add host'}</h1>
  <p class="lede">
    {lang === 'ru'
      ? 'На VPS: home pair-remote → на админ-ПК (SSH): home pair-complete CODE → вставьте device_token сюда один раз. Не шлите токен в Telegram.'
      : 'On VPS: home pair-remote → on admin PC (SSH): home pair-complete CODE → paste device_token here once. Never send the token via Telegram.'}
  </p>

  <ol class="steps">
    <li>
      <code class="mono">python -m sysspectogram home pair-remote --label laptop</code>
    </li>
    <li>
      <code class="mono"
        >ssh user@vps '… home pair-complete PAIRCODE --label laptop'</code
      >
    </li>
    <li>{lang === 'ru' ? 'Заполните форму ниже' : 'Fill the form below'}</li>
  </ol>

  <div class="form">
    <label>id <input bind:value={id} placeholder="web1" autocomplete="off" /></label>
    <label>label <input bind:value={label} placeholder="Web 1" /></label>
    <label>ssh <input bind:value={ssh} placeholder="user@vps" class="wide" /></label>
    <label>home <input bind:value={home} placeholder="/opt/SysSpectogram" class="wide" /></label>
    <label>device-id <input bind:value={deviceId} autocomplete="off" /></label>
    <label>
      device-token
      <input
        type="password"
        bind:value={deviceToken}
        autocomplete="off"
        placeholder={lang === 'ru' ? 'показывается один раз' : 'shown once from pair-complete'}
      />
    </label>
    <label>
      role
      <select bind:value={role}>
        <option value="primary">primary</option>
        <option value="worker">worker</option>
        <option value="canary">canary</option>
        <option value="bastion">bastion</option>
        <option value="dns">dns</option>
      </select>
    </label>
    <label>
      host_key_line (pin)
      <textarea
        bind:value={hostKeyLine}
        rows="2"
        placeholder="known_hosts line or 'ssh-ed25519 AAAA…'"
      ></textarea>
    </label>
  </div>

  {#if err}<p class="err">{err}</p>{/if}
  {#if note}<p class="ok">{note}</p>{/if}

  <div class="toolbar">
    <button type="button" disabled={busy} onclick={submit}>
      {lang === 'ru' ? 'Добавить в флот' : 'Add to fleet'}
    </button>
  </div>
  <p class="hint">
    {lang === 'ru'
      ? 'CLI: docs/FLEET_CLI.md · mutating ops нужен host_key_line'
      : 'CLI: docs/FLEET_CLI.md · mutating ops need host_key_line'}
  </p>
</section>

<style>
  .wizard { max-width: 640px; }
  h1 { font-size: 1.6rem; margin: 0 0 0.35rem; }
  .lede { color: var(--ink-soft); margin: 0 0 1rem; }
  .steps { color: var(--ink-soft); font-size: 0.85rem; padding-left: 1.2rem; }
  .form {
    display: grid;
    gap: 0.65rem;
    margin: 1rem 0;
  }
  label {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
    font-size: 0.75rem;
    color: var(--ink-soft);
  }
  input,
  select,
  textarea,
  button {
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line);
    background: var(--panel);
  }
  input.wide,
  textarea { width: 100%; }
  .toolbar { margin: 0.75rem 0; }
  button { cursor: pointer; }
  button:disabled { opacity: 0.4; }
  .ok { color: var(--ok); }
</style>
