export type Host = {
  id: string;
  label: string;
  ssh: string;
  role: string;
  token_set?: boolean;
  device_token?: string;
  profile_id?: string | null;
  host_key_line?: string;
  home?: string;
  device_id?: string;
};

export type Edge = { from: string; to: string; kind: string; note?: string };
export type Profile = { id: string; label: string; settings: Record<string, unknown> };
export type Group = { id: string; label: string; host_ids: string[] };

export type HostResult = {
  host_id: string;
  ok: boolean;
  error?: string;
  latency_ms?: number;
  detail?: Record<string, unknown>;
};

export type ConfirmKind = 'L2' | 'L3' | 'BAN' | 'UNLOCK' | 'RELEASE' | 'EDGE';

/** Never expose raw device_token in the UI. */
export function hostHasToken(h: Host): boolean {
  if (typeof h.token_set === 'boolean') return h.token_set;
  const t = (h.device_token || '').trim();
  return Boolean(t) && t !== '***';
}
