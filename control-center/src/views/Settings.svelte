<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText } from '../lib/api';
  import { t } from '../lib/i18n';
  import { ui } from '../lib/state.svelte';
  import {
    explainChanges,
    formatValue,
    sameValue,
    validateValue,
    type SettingEntry,
    type SettingsExport,
  } from '../lib/settings';
  import Icon from '../lib/Icon.svelte';

  let data = $state<SettingsExport | null>(null);
  let draft = $state<Record<string, unknown>>({});
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let busy = $state(false);
  let needsRestart = $state(false);

  async function reload(): Promise<void> {
    error = null;
    try {
      data = await api.settingsExport();
    } catch (e) {
      error = errorText(e);
    }
  }

  onMount(reload);

  const entries = $derived((data?.settings ?? []) as SettingEntry[]);
  const changes = $derived(explainChanges(entries, draft, ui.lang));
  const errors = $derived(
    Object.entries(draft)
      .map(([key, value]) => {
        const entry = entries.find((e) => e.key === key);
        return entry ? validateValue(entry, value) : `${key}: unknown setting`;
      })
      .filter((e): e is string => Boolean(e)),
  );
  const groups = $derived(
    Object.entries(data?.groups ?? {}).map(([id, g]) => ({
      id,
      title: g.title[ui.lang] || g.title.en,
    })),
  );

  function valueOf(entry: SettingEntry): unknown {
    return entry.key in draft ? draft[entry.key] : entry.current;
  }

  function setDraft(entry: SettingEntry, value: unknown): void {
    const next = { ...draft };
    if (sameValue(entry.current, value)) delete next[entry.key];
    else next[entry.key] = value;
    draft = next;
  }

  function onNumber(entry: SettingEntry, raw: string): void {
    const v = raw.trim() === '' ? Number.NaN : Number(raw);
    setDraft(entry, entry.type === 'int' ? Math.trunc(v) : v);
  }

  async function apply(): Promise<void> {
    if (errors.length > 0 || changes.length === 0) return;
    busy = true;
    error = null;
    notice = null;
    try {
      await api.settingsApply(draft);
      needsRestart = changes.some((c) => c.restart);
      notice = t('set.applied');
      draft = {};
      await reload();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function rollback(): Promise<void> {
    busy = true;
    error = null;
    notice = null;
    try {
      await api.settingsRollback();
      notice = t('set.rollbackDone');
      needsRestart = true;
      await reload();
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function restartGuard(): Promise<void> {
    busy = true;
    error = null;
    try {
      await api.guardService('restart');
      needsRestart = false;
      notice = t('inst.done');
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<h1>{t('set.title')}</h1>
<p class="lead">{t('set.help')}</p>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}
{#if notice}<div class="notice ok">{notice}</div><div style="height: 12px"></div>{/if}
{#if needsRestart}
  <div class="notice warn row">
    <span>{t('common.restartNote')}</span>
    <span class="spacer"></span>
    <button class="btn" onclick={restartGuard} disabled={busy}>{t('common.restartNow')}</button>
  </div>
  <div style="height: 12px"></div>
{/if}

{#if data}
  <div class="grid-2" style="grid-template-columns: minmax(0, 1.6fr) minmax(280px, 1fr); align-items: start">
    <div class="stack">
      {#each groups as g (g.id)}
        <section class="panel">
          <h2>{g.title}</h2>
          {#each entries.filter((e) => e.group === g.id) as entry (entry.key)}
            <div class="setting" style="display: grid; grid-template-columns: 1fr auto; gap: 14px; padding: 10px 0; border-top: 1px solid var(--border)">
              <div>
                <div>
                  {entry.title[ui.lang] || entry.title.en}
                  {#if entry.restart}<span class="pill" style="margin-left: 6px">restart</span>{/if}
                  {#if entry.key in draft}<span class="pill warn" style="margin-left: 6px">draft</span>{/if}
                </div>
                <div class="muted" style="font-size: 12.5px">{entry.description[ui.lang] || entry.description.en}</div>
                <div class="mono muted" style="font-size: 11.5px">
                  {entry.key} · {t('common.default')}: {formatValue(entry.default)} · {t('common.current')}: {formatValue(entry.current)}
                </div>
              </div>
              <div style="align-self: center">
                {#if entry.type === 'bool'}
                  <input
                    type="checkbox"
                    checked={Boolean(valueOf(entry))}
                    onchange={(e) => setDraft(entry, e.currentTarget.checked)}
                    aria-label={entry.key}
                  />
                {:else if entry.type === 'enum'}
                  <select value={String(valueOf(entry))} onchange={(e) => setDraft(entry, e.currentTarget.value)}>
                    {#each entry.choices ?? [] as choice (choice)}
                      <option value={choice}>{choice}</option>
                    {/each}
                  </select>
                {:else if entry.type === 'string'}
                  <input
                    type="text"
                    value={String(valueOf(entry) ?? '')}
                    oninput={(e) => setDraft(entry, e.currentTarget.value)}
                    placeholder="203.0.113.10/32"
                    style="width: min(280px, 40vw); padding: 6px 8px; border: 1px solid var(--border); border-radius: 7px; background: var(--bg)"
                    aria-label={entry.key}
                  />
                {:else}
                  <input
                    type="number"
                    value={String(valueOf(entry))}
                    min={entry.min}
                    max={entry.max}
                    step={entry.type === 'int' ? 1 : 0.01}
                    oninput={(e) => onNumber(entry, e.currentTarget.value)}
                    style="width: 110px; padding: 6px 8px; border: 1px solid var(--border); border-radius: 7px; background: var(--bg)"
                    aria-label={entry.key}
                  />
                {/if}
              </div>
            </div>
          {/each}
        </section>
      {/each}
    </div>

    <aside class="panel" style="position: sticky; top: 0">
      <h2>{t('set.pending')}</h2>
      {#if changes.length === 0 && errors.length === 0}
        <p class="muted">{t('set.noChanges')}</p>
      {/if}
      {#each errors as err (err)}
        <div class="notice error" style="margin-bottom: 8px">{err}</div>
      {/each}
      {#if errors.length > 0}<p class="muted">{t('set.invalid')}</p>{/if}
      {#each changes as c (c.key)}
        <div style="padding: 8px 0; border-top: 1px solid var(--border)">
          <div>{c.title}</div>
          <div class="mono" style="font-size: 12px">
            <span class="muted">{formatValue(c.oldValue)}</span> → <span>{formatValue(c.newValue)}</span>
            {#if c.restart}<span class="pill warn" style="margin-left: 6px">restart</span>{/if}
          </div>
          <div class="muted" style="font-size: 12px">{c.description}</div>
        </div>
      {/each}
      <div class="row" style="margin-top: 10px">
        <button class="btn" onclick={() => (draft = {})} disabled={busy || Object.keys(draft).length === 0}>
          {t('set.discard')}
        </button>
        <span class="spacer"></span>
        <button class="btn primary" onclick={apply} disabled={busy || changes.length === 0 || errors.length > 0}>
          {t('common.apply')}
        </button>
      </div>
      <div style="height: 16px"></div>
      <button class="btn danger" onclick={rollback} disabled={busy} style="width: 100%">
        <Icon name="refresh" size={16} /> {t('set.rollback')}
      </button>
      <p class="muted mono" style="font-size: 11.5px; margin-top: 12px">{t('set.overlay')}: {data.overlay_path}</p>
    </aside>
  </div>
{:else if !error}
  <p class="muted">{t('common.loading')}</p>
{/if}
