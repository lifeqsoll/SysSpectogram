<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { ui } from '../lib/state.svelte';
  import {
    explainChanges,
    formatValue,
    scenarioDraft,
    type Scenario,
    type SettingEntry,
    type SettingsExport,
  } from '../lib/settings';

  let data = $state<SettingsExport | null>(null);
  let selected = $state<Scenario | null>(null);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let busy = $state(false);
  let modeOverride = $state('');

  onMount(async () => {
    try {
      data = await api.settingsExport();
    } catch (e) {
      error = errorText(e);
    }
  });

  const entries = $derived((data?.settings ?? []) as SettingEntry[]);
  const modeChoices = $derived(entries.find((e) => e.key === 'agent.mode')?.choices ?? ['userspace', 'ebpf']);
  const preview = $derived.by(() => {
    if (!selected) return null;
    const overrides: Record<string, unknown> = { ...selected.overrides };
    // The user may pick userspace or eBPF for any scenario; the scenario's value is only the default.
    if (modeOverride) overrides['agent.mode'] = modeOverride;
    const { draft, errors } = scenarioDraft(entries, overrides);
    return { draft, errors, changes: explainChanges(entries, draft, ui.lang) };
  });

  function pick(sc: Scenario): void {
    selected = sc;
    modeOverride = String(sc.overrides['agent.mode'] ?? '');
    notice = null;
  }

  async function applyScenario(): Promise<void> {
    if (!selected || !preview || preview.errors.length > 0 || preview.changes.length === 0) return;
    busy = true;
    error = null;
    notice = null;
    try {
      await api.settingsApply(preview.draft);
      notice = `${t('scen.applied')} ${selected.title[ui.lang] || selected.title.en}`;
      data = await api.settingsExport();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<h1>{t('scen.title')}</h1>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}
{#if notice}<div class="notice ok">{notice}</div><div style="height: 12px"></div>{/if}

<div class="cards" style="grid-template-columns: repeat(auto-fit, minmax(240px, 1fr))">
  {#each data?.scenarios ?? [] as sc (sc.id)}
    <button
      class="panel"
      style="text-align: left; cursor: pointer; border-color: {selected?.id === sc.id ? 'var(--accent)' : 'var(--border)'}"
      onclick={() => pick(sc)}
    >
      <div style="font-weight: 600">{sc.title[ui.lang] || sc.title.en}</div>
      <div class="muted" style="font-size: 12.5px; margin-top: 6px">{sc.description[ui.lang] || sc.description.en}</div>
      <div class="mono muted" style="font-size: 11.5px; margin-top: 8px">agent: {sc.overrides['agent.mode'] ?? '-'} · {Object.keys(sc.overrides).length} keys</div>
    </button>
  {/each}
</div>

{#if selected && preview}
  <div style="height: 18px"></div>
  <div class="panel">
    <h2>{selected.title[ui.lang] || selected.title.en}</h2>
    <p class="muted">{selected.description[ui.lang] || selected.description.en}</p>

    <div class="row" style="margin: 10px 0">
      <label class="muted" for="scen-mode">{t('scen.mode')}</label>
      <select id="scen-mode" bind:value={modeOverride}>
        {#each modeChoices as m (m)}
          <option value={m}>{m}</option>
        {/each}
      </select>
    </div>

    {#each preview.errors as err (err)}
      <div class="notice error" style="margin: 8px 0">{err}</div>
    {/each}

    {#if preview.changes.length === 0 && preview.errors.length === 0}
      <p class="muted">{t('scen.noChanges')}</p>
    {/if}

    {#each preview.changes as c (c.key)}
      <div style="padding: 8px 0; border-top: 1px solid var(--border)">
        <div>{c.title}</div>
        <div class="mono" style="font-size: 12px">
          <span class="muted">{formatValue(c.oldValue)}</span> → {formatValue(c.newValue)}
          {#if c.restart}<span class="pill warn" style="margin-left: 6px">restart</span>{/if}
        </div>
        <div class="muted" style="font-size: 12px">{c.description}</div>
      </div>
    {/each}

    <div class="row" style="margin-top: 12px">
      <span class="spacer"></span>
      <button
        class="btn primary"
        onclick={applyScenario}
        disabled={busy || preview.changes.length === 0 || preview.errors.length > 0}
      >
        {t('scen.apply')}
      </button>
    </div>
  </div>
{/if}
