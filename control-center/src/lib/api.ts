// Typed wrappers around the Tauri commands in src-tauri/src/lib.rs.
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import type { SettingsExport } from './settings';

export type Range = '1h' | '6h' | '12h' | '24h' | '7d' | '30d';
export const RANGES: Range[] = ['1h', '6h', '12h', '24h', '7d', '30d'];

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
  timeseriesQuery: (metric: string, range: Range) => invoke<Point[]>('timeseries_query', { metric, range }),
  timeseriesMetrics: () => invoke<string[]>('timeseries_metrics'),
  incidentsList: (limit = 500) => invoke<Incident[]>('incidents_list', { limit }),
  incidentsRefresh: (limit = 500) => invoke<Incident[]>('incidents_refresh', { limit }),
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
