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
