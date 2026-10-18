<script lang="ts">
  import { onMount } from 'svelte';
  import { api, errorText, type Incident } from '../lib/api';
  import { t } from '../lib/i18n';
  import { fmtTime } from '../lib/format';

  let incidents = $state<Incident[]>([]);
  let perimeter = $state<Record<string, unknown>[]>([]);
  let error = $state<string | null>(null);
  let notice = $state<string | null>(null);
  let unlocked = $state(true);
  let busy = $state(false);

  async function load(): Promise<void> {
    error = null;
    busy = true;
    try {
      incidents = (await api.incidentsRefresh(300)).sort((a, b) => b.last_ts - a.last_ts);
      perimeter = await api.logTail('perimeter.jsonl', 40);
      try {
        const st = await api.controlStatus();
        const status = (st.status ?? st) as Record<string, unknown>;
        unlocked = status.control_unlocked !== false;
      } catch {
        unlocked = true;
      }
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  async function act(name: string, payload: Record<string, unknown>): Promise<void> {
    notice = null;
    error = null;
    if (!unlocked) {
      error = t('alerts.controlLocked');
      return;
    }
    try {
      const res = await api.controlAction(name, payload);
      if (res.ok === false) {
        error = String(res.error || 'action failed');
      } else {
        notice = `${name}: ${JSON.stringify(res.result ?? 'ok')}`;
      }
    } catch (e) {
      error = errorText(e);
    }
  }

  async function muteRule(ruleId: string): Promise<void> {
    notice = null;
    error = null;
    try {
      await api.homeMuteRule(ruleId, 24);
      notice = `${t('alerts.muted')}: ${ruleId}`;
    } catch (e) {
      error = errorText(e);
    }
  }

  function entityIp(inc: Incident): string | null {
    const ips = inc.entities?.ip || inc.entities?.ips || [];
    return ips[0] || null;
  }

  function entityPid(inc: Incident): number | null {
    const pids = inc.entities?.pid || inc.entities?.pids || [];
    const n = Number(pids[0]);
    return Number.isFinite(n) && n > 1 ? n : null;
  }

  onMount(load);
</script>

<h1>{t('alerts.title')}</h1>
<p class="lead">{t('alerts.lead')}</p>

<div class="row" style="margin-bottom: 12px">
  <button class="btn" disabled={busy} onclick={load}>{t('common.refresh')}</button>
  <span class="pill" class:ok={unlocked} class:warn={!unlocked}>{unlocked ? 'unlocked' : 'LOCKED'}</span>
</div>

{#if error}<div class="notice error">{error}</div><div style="height: 12px"></div>{/if}
{#if notice}<div class="notice ok">{notice}</div><div style="height: 12px"></div>{/if}

<div class="panel" style="margin-bottom: 16px">
  <h2>{t('inc.title')}</h2>
  {#if incidents.length === 0}
    <p class="muted">{t('inc.empty')}</p>
  {:else}
    {#each incidents as inc (inc.id)}
      <div class="alert-row">
        <div class="row">
          <span class="pill" class:danger={inc.severity === 'high' || inc.severity === 'critical'} class:warn={inc.severity === 'medium'}>{inc.severity}</span>
          <span class="title">{(inc.rules || []).join(', ') || inc.id}</span>
          <span class="spacer"></span>
          <span class="muted mono">{fmtTime(inc.last_ts)}</span>
        </div>
        <div class="muted">{inc.reason}</div>
        <div class="alert-actions">
          {#if entityIp(inc)}
            <button class="btn danger" onclick={() => act('ban', { ip: entityIp(inc), ttl: 3600 })}>{t('alerts.ban')}</button>
            <button class="btn" onclick={() => act('allow', { ip: entityIp(inc) })}>{t('alerts.allow')}</button>
            <button class="btn" onclick={() => act('mute', { ip: entityIp(inc), ttl: 3600 })}>{t('alerts.mute')}</button>
          {/if}
          {#if entityPid(inc)}
            <button class="btn danger" onclick={() => act('kill', { pid: entityPid(inc) })}>{t('alerts.kill')}</button>
          {/if}
          {#if inc.rules?.[0]}
            <button class="btn" onclick={() => muteRule(inc.rules[0])}>{t('alerts.muteRule')}</button>
          {/if}
        </div>
      </div>
    {/each}
  {/if}
</div>

<div class="panel">
  <h2>{t('alerts.perimeter')}</h2>
  {#if perimeter.length === 0}
    <p class="muted">{t('perim.empty')}</p>
  {:else}
    {#each perimeter.slice().reverse() as row, i (i)}
      {@const rid = String(row.rule_id || row.rule || 'alert')}
      {@const ip = row.ip ? String(row.ip) : null}
      <div class="alert-row">
        <div class="row">
          <span class="title">{rid}</span>
          <span class="spacer"></span>
          <span class="muted mono">{row.ts ? fmtTime(Number(row.ts)) : ''}</span>
        </div>
        <div class="muted">{String(row.message || '')}</div>
        {#if ip}
          <div class="alert-actions">
            <button class="btn danger" onclick={() => act('ban', { ip, ttl: 3600 })}>{t('alerts.ban')}</button>
            <button class="btn" onclick={() => act('allow', { ip })}>{t('alerts.allow')}</button>
          </div>
        {/if}
      </div>
    {/each}
  {/if}
</div>
