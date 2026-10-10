<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api, errorText, type Incident } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtDuration, fmtNum, fmtTime } from '../lib/format';

  let incidents = $state<Incident[]>([]);
  let selected = $state<Incident | null>(null);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let busy = $state(false);

  // Re-correlates alert/agent/perimeter logs into incidents, then reloads the list.
  async function load(): Promise<void> {
    error = null;
    busy = true;
    try {
      incidents = (await api.incidentsRefresh(500)).sort((a, b) => b.last_ts - a.last_ts);
      if (selected) selected = incidents.find((i) => i.id === selected?.id) ?? null;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function report(format: 'html' | 'md'): Promise<void> {
    if (!selected) return;
    notice = null;
    error = null;
    try {
      const path = await api.incidentReport(selected.id, format);
      notice = `${t('inc.reportDone')} ${path}`;
    } catch (e) {
      error = errorText(e);
    }
  }

  let spectroUrl = $state<string | null>(null);
  let spectroBusy = $state(false);

  function clearSpectro(): void {
    if (spectroUrl) URL.revokeObjectURL(spectroUrl);
    spectroUrl = null;
  }

  // Renders the metrics spectrogram around the incident on demand (not stored, not sent anywhere).
  async function showSpectro(): Promise<void> {
    if (!selected) return;
    error = null;
    spectroBusy = true;
    clearSpectro();
    try {
      const buf = await api.incidentSpectrogram(selected.id);
      spectroUrl = URL.createObjectURL(new Blob([buf], { type: 'image/png' }));
    } catch (e) {
      error = `${t('inc.spectroFail')}: ${errorText(e)}`;
    } finally {
      spectroBusy = false;
    }
  }

  onDestroy(clearSpectro);

  onMount(load);

  const severityClass = (s: string) => (s === 'critical' || s === 'high' ? 'danger' : s === 'medium' ? 'warn' : '');
</script>

<h1>{t('inc.title')}</h1>
<p class="lead">
  {t('nav.incidents')}: {incidents.length}
  <button class="btn" style="margin-left: 12px" disabled={busy} onclick={load}>{t('common.refresh')}</button>
</p>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}
{#if notice}<div class="notice ok">{notice}</div><div style="height: 12px"></div>{/if}

{#if incidents.length === 0}
  <div class="panel"><p class="muted">{t('inc.empty')}</p></div>
{:else}
  <div class="grid-2" style="grid-template-columns: 1.2fr 1fr">
    <div class="panel" style="padding: 6px 4px">
      <table>
        <thead>
          <tr>
            <th>{t('inc.id')}</th>
            <th>{t('inc.severity')}</th>
            <th>{t('inc.events')}</th>
            <th>{t('inc.attack')}</th>
          </tr>
        </thead>
        <tbody>
          {#each incidents as inc (inc.id)}
            <tr class="clickable" onclick={() => { if (selected?.id !== inc.id) clearSpectro(); selected = inc; }}>
              <td class="mono">{inc.id.slice(0, 10)}</td>
              <td><span class="pill {severityClass(inc.severity)}">{inc.severity}</span></td>
              <td>{inc.event_count}</td>
              <td class="muted">{inc.attack.slice(0, 3).join(', ') || '-'}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    <div class="panel">
      {#if selected}
        <div class="row">
          <h2 style="margin: 0">{selected.id}</h2>
          <span class="spacer"></span>
          <button class="btn" onclick={() => report('html')}>{t('inc.report')} HTML</button>
          <button class="btn" onclick={() => report('md')}>MD</button>
          <button class="btn" onclick={showSpectro} disabled={spectroBusy}>{t('inc.spectro')}</button>
        </div>
        <p class="muted" style="margin: 6px 0 12px">
          {fmtTime(selected.first_ts)} · {fmtDuration(selected.duration_sec)} · risk {fmtNum(selected.risk_max, 2)}
        </p>
        <p><span class="muted">{t('inc.reason')}:</span> {selected.reason}</p>
        {#if spectroUrl}
          <img alt="Spectrogram" src={spectroUrl} style="max-width: 100%; border-radius: 6px; margin-bottom: 12px" />
        {/if}
        <p><span class="muted">{t('inc.attack')}:</span> {selected.attack.join(', ') || t('common.none')}</p>
        <h2>{t('inc.entities')}</h2>
        <ul class="mono" style="margin: 0 0 14px; padding-left: 18px">
          {#each Object.entries(selected.entities) as [kind, values] (kind)}
            <li>{kind}: {values.join(', ')}</li>
          {/each}
        </ul>
        <h2>{t('inc.timeline')}</h2>
        <table>
          <tbody>
            {#each selected.timeline as item, i (i)}
              <tr>
                <td class="muted mono">{fmtTime(item.ts)}</td>
                <td><span class="pill {severityClass(item.severity)}">{item.rule_id}</span></td>
                <td>{item.message}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      {:else}
        <p class="muted">{t('common.none')}</p>
      {/if}
    </div>
  </div>
{/if}
