<script lang="ts">
  import { edgeApi } from '../lib/fleet';
  import type { ConfirmKind } from '../lib/types';

  type Props = {
    lang: 'en' | 'ru';
    requestConfirm: (kind: ConfirmKind, run: () => Promise<void>) => void;
  };

  let { lang, requestConfirm }: Props = $props();
  let edgeInfo = $state('');
  let busy = $state(false);

  async function status() {
    busy = true;
    try {
      const r = await edgeApi.status(lang);
      edgeInfo = JSON.stringify(r, null, 2);
    } catch (e) {
      edgeInfo = String(e);
    } finally {
      busy = false;
    }
  }

  function underAttack() {
    requestConfirm('EDGE', async () => {
      busy = true;
      try {
        const r = await edgeApi.underAttack();
        edgeInfo = JSON.stringify(r, null, 2);
      } catch (e) {
        edgeInfo = String(e);
      } finally {
        busy = false;
      }
    });
  }

  async function clear() {
    busy = true;
    try {
      const r = await edgeApi.clear('high');
      edgeInfo = JSON.stringify(r, null, 2);
    } catch (e) {
      edgeInfo = String(e);
    } finally {
      busy = false;
    }
  }

  async function playbook() {
    busy = true;
    try {
      const r = await edgeApi.playbook(lang);
      edgeInfo = r.playbook || JSON.stringify(r, null, 2);
    } catch (e) {
      edgeInfo = String(e);
    } finally {
      busy = false;
    }
  }

  $effect(() => {
    void status();
  });
</script>

<section class="edge">
  <h2>Edge / CDN</h2>
  <p class="hint">
    {lang === 'ru'
      ? 'Объёмный DDoS — Cloudflare Under Attack или playbook M. Не nft по флоту.'
      : 'Volumetric DDoS — Cloudflare Under Attack or playbook M. Not fleet nft.'}
  </p>
  <div class="toolbar">
    <button type="button" disabled={busy} onclick={status}>Status</button>
    <button type="button" class="danger" disabled={busy} onclick={underAttack}>Under Attack</button>
    <button type="button" disabled={busy} onclick={clear}>Clear</button>
    <button type="button" class="ghost" disabled={busy} onclick={playbook}>Playbook M</button>
  </div>
  {#if edgeInfo}
    <pre class="log">{edgeInfo}</pre>
  {/if}
</section>

<style>
  .edge {
    margin-bottom: 1.25rem;
    padding: 1rem;
    border: 1px solid var(--line);
    border-radius: var(--radius);
    background: color-mix(in srgb, var(--panel) 94%, transparent);
  }
  h2 { font-size: 1.05rem; margin: 0 0 0.35rem; }
  .toolbar {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    margin: 0.5rem 0;
  }
  button {
    padding: 0.4rem 0.65rem;
    border-radius: 6px;
    border: 1px solid var(--line);
    background: var(--panel);
    cursor: pointer;
  }
  button.danger { border-color: #b91c1c; }
  button.ghost { opacity: 0.85; }
  button:disabled { opacity: 0.4; cursor: not-allowed; }
  .log {
    margin: 0.5rem 0 0;
    padding: 0.75rem;
    background: #0b0f14;
    border-radius: 8px;
    overflow: auto;
    max-height: 200px;
    font-size: 0.75rem;
  }
</style>
