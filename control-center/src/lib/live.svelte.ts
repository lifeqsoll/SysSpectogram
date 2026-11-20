// values → всегда (алерты / «now» на карточках).
// history → только вкладка Live (там один график). Charts/Dashboards не трогаем history.
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
const REMOTE_METRICS = ['host_risk', 'host_score', 'agent_score', 'cpu_percent', 'mem_percent'];
const REMOTE_POLL_MS = 5000;

let started = false;
let remoteTimer: ReturnType<typeof setInterval> | undefined;
let applyLocal = true;
let remoteInFlight = false;
let lastRemoteHost = '';

function pageVisible(): boolean {
  return typeof document === 'undefined' || document.visibilityState !== 'hidden';
}

function applyLatest(at: number, latest: Latest[]): void {
  if (!pageVisible()) return;
  const values: Record<string, { value: number; ts: number }> = {};
  for (const item of latest) values[item.metric] = { value: item.value, ts: item.ts };
  live.at = at;
  live.values = values;
  live.connected = true;

  // Only the Live page draws a streaming chart from history.
  if (ui.section !== 'live') return;

  const prev = live.history[live.history.length - 1];
  if (
    prev &&
    prev.host_risk === (values.host_risk?.value ?? null) &&
    Math.abs(at - prev.ts) < 2.5
  ) {
    return;
  }
  live.history.push({
    ts: at,
    host_risk: values.host_risk?.value ?? null,
    host_score: values.host_score?.value ?? null,
    agent_score: values.agent_score?.value ?? null,
  });
  const cutoff = at - HISTORY_SECONDS;
  while (live.history.length > 0 && live.history[0].ts < cutoff) live.history.shift();
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
  if (!isRemoteHost() || !pageVisible() || remoteInFlight) return;
  remoteInFlight = true;
  try {
    const latest = await api.timeseriesLatest(REMOTE_METRICS);
    const at =
      latest.reduce((m, row) => Math.max(m, row.ts), 0) || Date.now() / 1000;
    applyLatest(at, latest);
  } catch {
    /* ignore */
  } finally {
    remoteInFlight = false;
  }
}

function syncRemotePoller(): void {
  const want = isRemoteHost() && pageVisible();
  applyLocal = !isRemoteHost();
  if (ui.activeHostId !== lastRemoteHost) {
    lastRemoteHost = ui.activeHostId;
    if (isRemoteHost()) void pollRemote();
  }
  if (want && !remoteTimer) {
    void pollRemote();
    remoteTimer = setInterval(() => void pollRemote(), REMOTE_POLL_MS);
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
      if (document.visibilityState === 'visible' && isRemoteHost()) void pollRemote();
    });
  }
  setInterval(() => syncRemotePoller(), 2500);
}
