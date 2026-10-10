<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { api, errorText, type LabLine, type LabRun } from '../lib/api';
  import { t } from '../lib/i18n';
  import { ui } from '../lib/state.svelte';
  import { fmtDuration, fmtTime } from '../lib/format';

  type Line = { text: string; stderr: boolean };
  type Verdict = { seen: boolean; checkedAt: number; text: string };

  let runs = $state<LabRun[]>([]);
  let error = $state<string | null>(null);
  let running = $state<string | null>(null);
  let startedAt = $state(0);
  let lines = $state<Line[]>([]);
  let consent = $state<Record<string, boolean>>({});
  let verdict = $state<Verdict | null>(null);
  let outputOwner = $state<string | null>(null);
  const unlisten: Array<() => void> = [];

  onMount(async () => {
    try {
      runs = await api.labList();
    } catch (e) {
      error = errorText(e);
    }
    unlisten.push(
      await api.onLabOutput((e: LabLine) => {
        if (e.id !== outputOwner) return;
        lines = [...lines, { text: e.line, stderr: e.stderr }];
      }),
    );
    unlisten.push(
      await api.onLabDone(async (e) => {
        if (e.id !== outputOwner) return;
        lines = [...lines, { text: `${t('lab.done')} ${e.code}`, stderr: e.code !== 0 }];
        running = null;
        verdict = await checkExpected(e.id);
      }),
    );
  });

  onDestroy(() => unlisten.forEach((u) => u()));

  async function checkExpected(id: string): Promise<Verdict> {
    const run = runs.find((r) => r.id === id);
    const expect = run?.expect_rule ?? '';
    const now = Date.now() / 1000;
    let seen = false;
    for (const name of ['alerts.jsonl', 'agent.jsonl', 'perimeter.jsonl']) {
      try {
        const rows = await api.logTail(name, 300);
        seen ||= rows.some((row) => {
          const label = String(row.rule_id ?? row.pattern ?? row.type ?? '');
          const ts = typeof row.ts === 'number' ? row.ts : Date.parse(String(row.ts)) / 1000;
          return label.includes(expect) && ts >= startedAt - 5;
        });
      } catch {
        // missing report file: treated as not seen
      }
    }
    const text = seen
      ? `${t('lab.expect')}: ${expect} ✓`
      : `${t('lab.expect')}: ${expect} - ${ui.lang === 'ru' ? 'пока не найдено в отчётах' : 'not seen in reports yet'}`;
    return { seen, checkedAt: now, text };
  }

  async function run(r: LabRun): Promise<void> {
    if (running) return;
    error = null;
    verdict = null;
    outputOwner = r.id;
    lines = [];
    running = r.id;
    startedAt = Date.now() / 1000;
    try {
      await api.labRun(r.id);
    } catch (e) {
      error = errorText(e);
      running = null;
    }
  }
</script>

<h1>{t('lab.title')}</h1>
<p class="lead">{t('lab.note')}</p>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}

<div class="cards" style="grid-template-columns: repeat(auto-fit, minmax(280px, 1fr))">
  {#each runs as r (r.id)}
    <div class="panel">
      <div class="row" style="justify-content: space-between">
        <div style="font-weight: 600">{r.title[ui.lang] || r.title.en}</div>
        {#if r.lab_flag}<span class="pill warn">lab</span>{/if}
      </div>
      <div class="muted" style="font-size: 12.5px; margin: 6px 0 10px">{r.description[ui.lang] || r.description.en}</div>
      <div class="mono muted" style="font-size: 11.5px">
        {t('lab.expect')}: {r.expect_rule} · {t('lab.duration')}: {fmtDuration(r.duration_sec)}
      </div>
      {#if r.lab_flag}
        <label class="row" style="margin-top: 10px; font-size: 12.5px">
          <input type="checkbox" bind:checked={consent[r.id]} />
          <span>{t('lab.labOnly')}</span>
        </label>
      {/if}
      <div class="row" style="margin-top: 12px">
        <span class="spacer"></span>
        <button
          class="btn primary"
          onclick={() => run(r)}
          disabled={running !== null || (r.lab_flag && !consent[r.id])}
        >
          {running === r.id ? '…' : t('lab.run')}
        </button>
      </div>
    </div>
  {/each}
</div>

{#if outputOwner}
  <div style="height: 18px"></div>
  <div class="panel">
    <div class="row">
      <h2 style="margin: 0">{t('lab.output')}: {outputOwner}</h2>
      <span class="spacer"></span>
      {#if running}<span class="pill">running since {fmtTime(startedAt)}</span>{/if}
    </div>
    <div class="console" style="margin-top: 10px">
      {#each lines as l, i (i)}
        <div class:err={l.stderr}>{l.text}</div>
      {:else}
        <div class="muted">…</div>
      {/each}
    </div>
    {#if verdict}
      <div class="notice {verdict.seen ? 'ok' : 'warn'}" style="margin-top: 10px">{verdict.text}</div>
    {/if}
  </div>
{/if}
