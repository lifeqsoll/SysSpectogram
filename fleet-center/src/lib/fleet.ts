import { invoke } from '@tauri-apps/api/core';
import type { Edge, Group, Host, HostResult, Profile } from './types';

export type GraphPayload = {
  ok: boolean;
  primary_host_id?: string | null;
  hosts?: Host[];
  edges?: Edge[];
  profiles?: Profile[];
  groups?: Group[];
  dependents?: Record<string, string[]>;
  error?: string;
};

export function applyResults(r: Record<string, unknown>): {
  rows: HostResult[];
  log: string;
} {
  const rows = ((r.results as HostResult[]) || []).map((x) => ({
    host_id: x.host_id,
    ok: Boolean(x.ok),
    error: x.error,
    latency_ms: x.latency_ms,
    detail: x.detail,
  }));
  return { rows, log: JSON.stringify(r, null, 2) };
}

export async function loadGraph(): Promise<GraphPayload> {
  try {
    return await invoke<GraphPayload>('fleet_graph');
  } catch {
    return await invoke<GraphPayload>('fleet_list');
  }
}

export const fleetApi = {
  status: (scope: string) => invoke<Record<string, unknown>>('fleet_status', { scope }),
  unlockLocked: (scope: string) =>
    invoke<Record<string, unknown>>('fleet_unlock_locked', { scope }),
  attack: (scope: string, level: string, deps: boolean) =>
    invoke<Record<string, unknown>>('fleet_attack', { scope, level, deps }),
  release: (scope: string) => invoke<Record<string, unknown>>('fleet_release', { scope }),
  warmup: (scope: string) => invoke<Record<string, unknown>>('fleet_warmup', { scope }),
  incidents: (scope: string, limit = 40) =>
    invoke<Record<string, unknown>>('fleet_incidents', { scope, limit }),
  ban: (scope: string, ip: string, ttl = 3600) =>
    invoke<Record<string, unknown>>('fleet_ban', { scope, ip, ttl }),
  markFp: (scope: string, label = 'host_fp') =>
    invoke<Record<string, unknown>>('fleet_mark_fp', { scope, label }),
  profileApply: (id: string, scope: string) =>
    invoke<Record<string, unknown>>('fleet_profile_apply', { id, scope }),
  add: (payload: Record<string, string>) =>
    invoke<Record<string, unknown>>('fleet_add', payload),
  pinHost: (id: string, hostKeyLine: string) =>
    invoke<Record<string, unknown>>('fleet_pin_host', { id, hostKeyLine }),
  pairStart: (payload: Record<string, string | null>) =>
    invoke<Record<string, unknown>>('fleet_pair_start', payload),
  pairFinish: (payload: Record<string, string | null>) =>
    invoke<Record<string, unknown>>('fleet_pair_finish', payload),
  keyscan: (ssh: string) => invoke<Record<string, unknown>>('fleet_keyscan', { ssh }),
};

export const edgeApi = {
  status: (lang: string) => invoke<Record<string, unknown>>('edge_status', { lang }),
  underAttack: () => invoke<Record<string, unknown>>('edge_under_attack'),
  clear: (level = 'high') => invoke<Record<string, unknown>>('edge_clear', { level }),
  playbook: (lang: string) =>
    invoke<{ playbook?: string; ok?: boolean }>('edge_playbook', { lang }),
};
