// One subscription to the backend "live" event, shared by every view.
// Remote hosts poll fleet timeseries latest (gated by section + visibility).
import { api, type LiveEvent, type Latest } from './api';
import { isRemoteHost, ui } from './state.svelte';

export interface LiveHistoryRow {
  ts: number;
  host_risk: number | null;
  host_score: number | null;
  agent_score: number | null;
}

export interface LiveState {
  at: number;
  values: Record<string, { value: number; ts: number }>;
  history: LiveHistoryRow[];
  connected: boolean;
}

export const live: LiveState = $state({
  at: 0,
  values: {},
  history: [],
  connected: false,
});

const HISTORY_SECONDS = 300;
const LIVE_SECTIONS = new Set(['home', 'charts', 'live', 'overview', 'alerts', 'incidents', 'fleet']);
const REMOTE_METRICS = [
  'host_risk',
  'host_score',
  'agent_score',
  'cpu_percent',
  'mem_percent',
  'net_bytes_recv_per_s',
  'net_bytes_sent_per_s',
];

let started = false;
let remoteTimer: ReturnType<typeof setInterval> | undefined;
let applyLocal = true;

function sectionWantsLive(): boolean {
  if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return false;
  return LIVE_SECTIONS.has(ui.section);
}

function applyLatest(at: number, latest: Latest[]): void {
  if (!sectionWantsLive()) return;
  const values: Record<string, { value: number; ts: number }> = {};
  for (const item of latest) values[item.metric] = { value: item.value, ts: item.ts };
  live.at = at;
  live.values = values;
  live.history.push({
    ts: at,
    host_risk: values.host_risk?.value ?? null,
    host_score: values.host_score?.value ?? null,
    agent_score: values.agent_score?.value ?? null,
  });
  const cutoff = at - HISTORY_SECONDS;
  while (live.history.length > 0 && live.history[0].ts < cutoff) live.history.shift();
  live.connected = true;
}

function apply(e: LiveEvent): void {
  if (!applyLocal || isRemoteHost()) return;
  applyLatest(e.at, e.latest);
}

export function clearLiveHistory(): void {
  live.history = [];
  live.values = {};
  live.at = 0;
  live.connected = false;
}

async function pollRemote(): Promise<void> {
  if (!isRemoteHost() || !sectionWantsLive()) return;
  try {
    const latest = await api.timeseriesLatest(REMOTE_METRICS);
    const at =
      latest.reduce((m, row) => Math.max(m, row.ts), 0) || Date.now() / 1000;
    applyLatest(at, latest);
  } catch {
    /* ignore SSH blips */
  }
}

function syncRemotePoller(): void {
  const want = isRemoteHost();
  applyLocal = !want;
  if (want && !remoteTimer) {
    void pollRemote();
    remoteTimer = setInterval(() => void pollRemote(), 8000);
  } else if (!want && remoteTimer) {
    clearInterval(remoteTimer);
    remoteTimer = undefined;
  }
}

export async function startLive(): Promise<void> {
  if (started) return;
  started = true;
  await api.onLive(apply);
  syncRemotePoller();
  if (typeof document !== 'undefined') {
    document.addEventListener('visibilitychange', () => {
      if (document.visibilityState === 'visible') void pollRemote();
    });
  }
  // React to host / section changes via cheap interval (avoids $effect in non-component).
  setInterval(() => syncRemotePoller(), 1000);
}
