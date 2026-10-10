<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtTime } from '../lib/format';

  const FILES = ['alerts.jsonl', 'agent.jsonl', 'perimeter.jsonl', 'incidents.jsonl'];

  let file = $state(FILES[0]);
  let rows = $state<Record<string, unknown>[]>([]);
  let error = $state<string | null>(null);

  async function load(name: string): Promise<void> {
    error = null;
    try {
      rows = (await api.logTail(name, 200)).reverse();
    } catch (e) {
      error = errorText(e);
      rows = [];
    }
  }

  onMount(() => load(file));

  function when(row: Record<string, unknown>): string {
    const v = row.ts ?? row.first_ts;
    if (typeof v === 'number') return fmtTime(v);
    if (typeof v === 'string') return v;
    return '-';
  }

  function brief(row: Record<string, unknown>): string {
    const s = JSON.stringify(row);
    return s.length > 360 ? `${s.slice(0, 360)}…` : s;
  }
</script>

<h1>{t('logs.title')}</h1>
<div class="row" style="margin-bottom: 14px">
  <label class="field">
    <span class="muted">{t('logs.file')}</span>
    <select
      bind:value={file}
      onchange={(e) => load(e.currentTarget.value)}
    >
      {#each FILES as f (f)}<option value={f}>{f}</option>{/each}
    </select>
  </label>
  <span class="spacer"></span>
  <button class="btn" onclick={() => load(file)}>{t('common.refresh')}</button>
</div>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}

<div class="panel" style="padding: 6px 4px">
  {#if rows.length === 0}
    <p class="muted" style="padding: 12px">{t('logs.empty')}</p>
  {:else}
    <table>
      <tbody>
        {#each rows as row, i (i)}
          <tr>
            <td class="muted mono" style="white-space: nowrap">{when(row)}</td>
            <td class="mono" style="word-break: break-all">{brief(row)}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
