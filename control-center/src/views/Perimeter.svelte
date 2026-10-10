<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtTime } from '../lib/format';

  let rows = $state<Record<string, unknown>[]>([]);
  let error = $state<string | null>(null);

  async function load(): Promise<void> {
    error = null;
    try {
      rows = (await api.logTail('perimeter.jsonl', 300)).reverse();
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(load);

  function str(v: unknown): string {
    return v === undefined || v === null ? '' : String(v);
  }

  function ts(row: Record<string, unknown>): number {
    const v = row.ts;
    return typeof v === 'number' ? v : Date.parse(String(v)) / 1000 || 0;
  }
</script>

<h1>{t('perim.title')}</h1>
<div class="row" style="margin-bottom: 14px">
  <span class="muted">perimeter.jsonl</span>
  <span class="spacer"></span>
  <button class="btn" onclick={load}>{t('common.refresh')}</button>
</div>

{#if error}<div class="notice error">{error}</div>{/if}

<div class="panel" style="padding: 6px 4px">
  {#if rows.length === 0}
    <p class="muted" style="padding: 12px">{t('perim.empty')}</p>
  {:else}
    <table>
      <thead>
        <tr><th>time</th><th>rule</th><th>remote</th><th>message</th></tr>
      </thead>
      <tbody>
        {#each rows as row, i (i)}
          <tr>
            <td class="muted mono">{fmtTime(ts(row))}</td>
            <td>{str(row.rule_id ?? row.type ?? row.pattern)}</td>
            <td class="mono">{str(row.remote_ip ?? row.ip ?? row.src ?? '')}</td>
            <td>{str(row.message ?? row.summary ?? '')}</td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
