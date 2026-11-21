// Typed wrappers around the Tauri commands in src-tauri/src/lib.rs.
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { SettingsExport } from './settings';
import { ui } from './state.svelte';

export type Range = '1h' | '6h' | '12h' | '24h' | '7d' | '30d';
export const RANGES: Range[] = ['1h', '6h', '12h', '24h', '7d', '30d'];

export const fleet = {
  list: () => invoke<Record<string, unknown>>('fleet_list'),
  graph: () => invoke<Record<string, unknown>>('fleet_graph'),
  warmup: (scope?: string) => invoke<Record<string, unknown>>('fleet_warmup', { scope }),
  profileApply: (id: string, scope?: string) =>
    invoke<Record<string, unknown>>('fleet_profile_apply', { id, scope }),
  status: (scope?: string) => invoke<Record<string, unknown>>('fleet_status', { scope }),
  unlockLocked: (scope?: string) =>
    invoke<Record<string, unknown>>('fleet_unlock_locked', { scope }),
  attack: (scope: string, level?: string, deps?: boolean) =>
    invoke<Record<string, unknown>>('fleet_attack', { scope, level, deps }),
  release: (scope?: string) => invoke<Record<string, unknown>>('fleet_release', { scope }),
  incidents: (scope?: string, limit?: number) =>
    invoke<Record<string, unknown>>('fleet_incidents', { scope, limit }),
  markFp: (scope?: string, label?: string) =>
    invoke<Record<string, unknown>>('fleet_mark_fp', { scope, label }),
  ban: (scope: string, ip: string, ttl?: number) =>
    invoke<Record<string, unknown>>('fleet_ban', { scope, ip, ttl }),
  timeseriesMetrics: (scope: string) =>
    invoke<{ ok: boolean; metrics?: string[]; error?: string }>('fleet_timeseries_metrics', {
      scope,
    }),
  timeseriesLatest: (scope: string, metrics?: string) =>
    invoke<{ ok: boolean; latest?: Latest[]; error?: string }>('fleet_timeseries_latest', {
      scope,
      metrics: metrics ?? null,
    }),
  timeseriesQuery: (scope: string, metrics: string, range?: Range, maxPoints?: number) =>
    invoke<{ ok: boolean; series?: Record<string, Point[]>; error?: string }>(
      'fleet_timeseries_query',
      { scope, metrics, range: range ?? null, maxPoints: maxPoints ?? null },
    ),
};

function activeHostScope(): string | null {
  const id = ui.activeHostId;
  return id && id !== 'local' ? id : null;
}

/** Metric-list cache (changes rarely; avoid DISTINCT scan on every mount). */
const METRICS_CACHE_TTL_MS = 5 * 60 * 1000;
const metricsCache = new Map<string, { at: number; metrics: string[] }>();

export function invalidateMetricsCache(scope?: string): void {
  if (scope) metricsCache.delete(scope);
  else metricsCache.clear();
}

export interface AppInfo {
  version: string;
  root: string;
  helper_socket: string;
  dev_checkout?: boolean;
  stack_ready?: boolean;
}

export interface BootstrapStatus {
  ok: boolean;
  dev_checkout: boolean;
  home: string;
  python: string;
  stack_ready: boolean;
  helper_ok: boolean;
  github_repo: string;
  app_version: string;
}

export interface Point {
  ts: number;
  avg: number;
  min: number;
  max: number;
  n: number;
}

export interface Latest {
  metric: string;
  ts: number;
  value: number;
}

export interface LiveEvent {
  at: number;
  latest: Latest[];
}

export interface TimelineItem {
  ts: number;
  rule_id: string;
  kind: string;
  severity: string;
  message: string;
}

export interface Incident {
  id: string;
  host_id: string;
  first_ts: number;
  last_ts: number;
  duration_sec: number;
  event_count: number;
  severity: string;
  risk_max: number | null;
  rules: string[];
  entities: Record<string, string[]>;
  attack: string[];
  reason: string;
  timeline: TimelineItem[];
}

export interface LabRun {
  id: string;
  title: { en: string; ru: string };
  description: { en: string; ru: string };
  expect_rule: string;
  duration_sec: number;
  lab_flag: boolean;
  tags: string[];
}

export interface LabLine {
  id: string;
  line: string;
  stderr: boolean;
}

export interface StepResult {
  ok: boolean;
  message: string;
}

export interface StartAllResult {
  helper: StepResult;
  guard: StepResult;
}

export interface StackStatus {
  guard_running: boolean;
  guard_pid: number | null;
}

export interface HealthCheck {
  id: string;
  ok: boolean;
  detail: string;
  severity: string;
}

export interface HomeHealth {
  ok: boolean;
  checks: HealthCheck[];
}

export interface HomeDigest {
  ok: boolean;
  hours: number;
  text: string;
  incidents: number;
  perimeter: number;
  alerts: number;
  risk_max: number | null;
  cpu_avg: number | null;
}

export interface ChecklistItem {
  id: string;
  title: { en: string; ru: string };
  ok: boolean;
  hint: { en: string; ru: string };
}

export interface HomeChecklist {
  ok: boolean;
  ready: number;
  total: number;
  items: ChecklistItem[];
}

export const api = {
  appInfo: () => invoke<AppInfo>('app_info'),
  helperStatus: () => invoke<{ guard: string }>('helper_status'),
  guardService: (action: 'start' | 'stop' | 'restart') => invoke<unknown>('guard_service', { action }),
  settingsExport: () => invoke<SettingsExport>('settings_export'),
  settingsApply: (changes: Record<string, unknown>) => invoke<unknown>('settings_apply', { changes }),
  settingsRollback: () => invoke<unknown>('settings_rollback'),
  installBundle: (version: string, source: string) => invoke<unknown>('install_bundle', { version, source }),
  timeseriesQuery: async (
    metric: string,
    range: Range,
    opts?: { maxPoints?: number; afterTs?: number },
  ): Promise<Point[]> => {
    const scope = activeHostScope();
    const maxPoints = opts?.maxPoints;
    const afterTs = opts?.afterTs;
    if (!scope) {
      return invoke<Point[]>('timeseries_query', {
        metric,
        range,
        maxPoints: maxPoints ?? null,
        afterTs: afterTs ?? null,
      });
    }
    // Fleet path: full window + client filter for afterTs (remote downsample still applies).
    const res = await fleet.timeseriesQuery(scope, metric, range, maxPoints);
    if (!res.ok) throw new Error(res.error || 'fleet timeseries query failed');
    let pts = res.series?.[metric] ?? [];
    if (afterTs != null) pts = pts.filter((p) => p.ts > afterTs);
    return pts;
  },
  timeseriesQueryMany: async (
    metrics: string[],
    range: Range,
    opts?: { maxPoints?: number; afterTs?: number },
  ): Promise<Record<string, Point[]>> => {
    const scope = activeHostScope();
    const maxPoints = opts?.maxPoints;
    const afterTs = opts?.afterTs;
    if (!scope) {
      return invoke<Record<string, Point[]>>('timeseries_query_many', {
        metrics,
        range,
        maxPoints: maxPoints ?? null,
        afterTs: afterTs ?? null,
      });
    }
    const res = await fleet.timeseriesQuery(scope, metrics.join(','), range, maxPoints);
    if (!res.ok) throw new Error(res.error || 'fleet timeseries query failed');
    const series = res.series ?? {};
    if (afterTs == null) return series;
    const out: Record<string, Point[]> = {};
    for (const [k, pts] of Object.entries(series)) {
      out[k] = pts.filter((p) => p.ts > afterTs);
    }
    return out;
  },
  timeseriesMetrics: async (opts?: { force?: boolean }): Promise<string[]> => {
    const scope = activeHostScope() ?? 'local';
    const now = Date.now();
    const hit = metricsCache.get(scope);
    if (!opts?.force && hit && now - hit.at < METRICS_CACHE_TTL_MS) {
      return hit.metrics;
    }
    let metrics: string[];
    if (scope === 'local' || !activeHostScope()) {
      metrics = await invoke<string[]>('timeseries_metrics');
    } else {
      const res = await fleet.timeseriesMetrics(scope);
      if (!res.ok) throw new Error(res.error || 'fleet timeseries metrics failed');
      metrics = res.metrics ?? [];
    }
    metricsCache.set(scope, { at: now, metrics });
    return metrics;
  },
  timeseriesLatest: async (metrics?: string[]): Promise<Latest[]> => {
    const scope = activeHostScope();
    if (!scope) {
      return invoke<Latest[]>('timeseries_latest', { metrics: metrics ?? null });
    }
    const res = await fleet.timeseriesLatest(
      scope,
      metrics && metrics.length ? metrics.join(',') : undefined,
    );
    if (!res.ok) throw new Error(res.error || 'fleet timeseries latest failed');
    return res.latest ?? [];
  },
  incidentsList: async (limit = 500): Promise<Incident[]> => {
    const scope = activeHostScope();
    if (!scope) return invoke<Incident[]>('incidents_list', { limit });
    const res = await fleet.incidents(scope, limit);
    const items = (res.items as Incident[] | undefined) ?? [];
    return items;
  },
  incidentsRefresh: async (limit = 500): Promise<Incident[]> => {
    const scope = activeHostScope();
    if (!scope) return invoke<Incident[]>('incidents_refresh', { limit });
    return api.incidentsList(limit);
  },
  incidentSpectrogram: (id: string) => invoke<ArrayBuffer>('incident_spectrogram', { id }),
  unlockCode: () => invoke<string | null>('unlock_code'),
  incidentReport: (id: string, format: 'html' | 'md') => invoke<string>('incident_report', { id, format }),
  logTail: (name: string, limit = 200) => invoke<Record<string, unknown>[]>('log_tail', { name, limit }),
  labList: () => invoke<LabRun[]>('lab_list'),
  labRun: (id: string) => invoke<void>('lab_run', { id }),
  startAll: () => invoke<StartAllResult>('start_all'),
  stopGuard: () => invoke<void>('stop_guard'),
  stackStatus: () => invoke<StackStatus>('stack_status'),
  controlStatus: () => invoke<Record<string, unknown>>('control_status'),
  controlAction: (name: string, payload: Record<string, unknown> = {}) =>
    invoke<Record<string, unknown>>('control_action', { name, payload }),
  homeImportModel: (source: string) => invoke<Record<string, unknown>>('home_import_model', { source }),
  homeWriteEnv: (botToken?: string, chatId?: string) =>
    invoke<Record<string, unknown>>('home_write_env', { botToken, chatId }),
  onboardingStatus: () => invoke<{ done: boolean; path: string }>('onboarding_status'),
  onboardingDone: () => invoke<Record<string, unknown>>('onboarding_done'),
  homeHealth: (ping = false) => invoke<HomeHealth>('home_health', { ping }),
  homeDigest: (hours = 24, lang?: string) =>
    invoke<HomeDigest>('home_digest', { hours, lang }),
  homeChecklist: () => invoke<HomeChecklist>('home_checklist'),
  homeMuteRule: (ruleId: string, hours = 24) =>
    invoke<Record<string, unknown>>('home_mute_rule', { ruleId, hours }),
  bootstrapStatus: () => invoke<BootstrapStatus>('bootstrap_status'),
  bootstrapInstall: (tag?: string) =>
    invoke<Record<string, unknown>>('bootstrap_install', { tag: tag ?? null }),
  bootstrapPreflight: () =>
    invoke<{
      ok: boolean;
      ready: boolean;
      checks: { id: string; ok: boolean; detail: string }[];
      hints: Record<string, string>;
    }>('bootstrap_preflight'),
  protectStatus: () =>
    invoke<{
      ok: boolean;
      installed?: boolean;
      enabled?: boolean;
      active?: boolean;
      detail?: string;
      home?: string;
      hint?: string;
      linger?: boolean;
    }>('protect_status'),
  protectEnable: () => invoke<Record<string, unknown>>('protect_enable'),
  protectDisable: () => invoke<Record<string, unknown>>('protect_disable'),
  homeUpdate: (tag?: string) =>
    invoke<Record<string, unknown>>('home_update', { tag: tag ?? null }),
  homeSeedRole: (role: string) =>
    invoke<{ ok: boolean; role?: string; rules_added?: number; error?: string }>(
      'home_seed_role',
      { role },
    ),
  detectPublicIp: () =>
    invoke<{ ok: boolean; ip: string; source?: string }>('detect_public_ip'),
  installHelperRelease: (tag?: string) =>
    invoke<Record<string, unknown>>('install_helper_release', { tag: tag ?? null }),
  onLive: (cb: (e: LiveEvent) => void): Promise<UnlistenFn> =>
    listen<LiveEvent>('live', (e) => cb(e.payload)),
  onLabOutput: (cb: (e: LabLine) => void): Promise<UnlistenFn> =>
    listen<LabLine>('lab-output', (e) => cb(e.payload)),
  onLabDone: (cb: (e: { id: string; code: number }) => void): Promise<UnlistenFn> =>
    listen<{ id: string; code: number }>('lab-done', (e) => cb(e.payload)),
};

export function errorText(err: unknown): string {
  if (typeof err === 'string') return err;
  if (err instanceof Error) return err.message;
  return JSON.stringify(err);
}

/** True only inside the Tauri webview (not a plain browser / Vite tab). */
export function isTauri(): boolean {
  return typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;
}
