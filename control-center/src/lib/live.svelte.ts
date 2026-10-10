// One subscription to the backend "live" event, shared by every view.
import { api, type LiveEvent } from './api';

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
let started = false;

function apply(e: LiveEvent): void {
  const values: Record<string, { value: number; ts: number }> = {};
  for (const item of e.latest) values[item.metric] = { value: item.value, ts: item.ts };
  live.at = e.at;
  live.values = values;
  live.history.push({
    ts: e.at,
    host_risk: values.host_risk?.value ?? null,
    host_score: values.host_score?.value ?? null,
    agent_score: values.agent_score?.value ?? null,
  });
  const cutoff = e.at - HISTORY_SECONDS;
  while (live.history.length > 0 && live.history[0].ts < cutoff) live.history.shift();
  live.connected = true;
}

export async function startLive(): Promise<void> {
  if (started) return;
  started = true;
  await api.onLive(apply);
}
