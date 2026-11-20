<script lang="ts">
  import { onMount } from 'svelte';
  import { fleet } from './api';
  import { setActiveHost, ui } from './state.svelte';
  import { clearLiveHistory } from './live.svelte';
  import { t } from './i18n';

  type HostRow = { id: string; label: string; role?: string };

  let hosts = $state<HostRow[]>([]);

  async function refresh(): Promise<void> {
    try {
      const r = await fleet.list();
      const list = (r.hosts as HostRow[] | undefined) ?? [];
      hosts = list.map((h) => ({ id: h.id, label: h.label || h.id, role: h.role }));
      if (ui.activeHostId !== 'local' && !hosts.some((h) => h.id === ui.activeHostId)) {
        setActiveHost('local');
        clearLiveHistory();
      }
    } catch {
      hosts = [];
    }
  }

  function onChange(ev: Event): void {
    const v = (ev.currentTarget as HTMLSelectElement).value || 'local';
    setActiveHost(v);
    clearLiveHistory();
  }

  let lastSection = '';

  onMount(() => {
    void refresh();
  });

  $effect(() => {
    const s = ui.section;
    // Refresh host list once when entering Fleet (after pair wizard), not on every tick.
    if (s === 'fleet' && lastSection !== 'fleet') void refresh();
    lastSection = s;
  });
</script>

<label class="host-picker">
  <span class="muted">{t('host.picker')}</span>
  <select value={ui.activeHostId} onchange={onChange}>
    <option value="local">{t('host.local')}</option>
    {#each hosts as h (h.id)}
      <option value={h.id}>{h.role === 'primary' ? '★ ' : ''}{h.label}</option>
    {/each}
  </select>
</label>

<style>
  .host-picker {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 8px 12px 12px;
    font-size: 12px;
  }
  .host-picker select {
    width: 100%;
    font-size: 12px;
  }
</style>
