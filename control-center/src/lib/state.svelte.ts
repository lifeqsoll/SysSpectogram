// Shared UI state (Svelte 5 runes). Language defaults to English.
import type { Lang } from './settings';
import type { Range } from './api';

/** Simple-home sections (default). */
export const SIMPLE_SECTIONS = ['home', 'fleet', 'charts', 'alerts', 'settings'] as const;

/** Geek / Advanced sections. */
export const ADVANCED_SECTIONS = [
  'overview',
  'live',
  'dashboards',
  'incidents',
  'agent',
  'perimeter',
  'settingsAdvanced',
  'scenarios',
  'lab',
  'install',
  'logs',
  'about',
] as const;

export const SECTIONS = [...SIMPLE_SECTIONS, ...ADVANCED_SECTIONS] as const;

export type SectionId = (typeof SECTIONS)[number];
export type ThemeId = 'dark' | 'light';

function storedLang(): Lang {
  const v = typeof localStorage !== 'undefined' ? localStorage.getItem('sys-lang') : null;
  return v === 'ru' ? 'ru' : 'en';
}

function storedTheme(): ThemeId {
  const v = typeof localStorage !== 'undefined' ? localStorage.getItem('sys-theme') : null;
  return v === 'light' ? 'light' : 'dark';
}

function storedAdvanced(): boolean {
  try {
    return localStorage.getItem('sys-advanced') === '1';
  } catch {
    return false;
  }
}

function storedFleetHubOnly(): boolean {
  try {
    return localStorage.getItem('sys-fleet-hub') === '1';
  } catch {
    return false;
  }
}

/** Nav when Fleet hub-only mode is on (observability + fleet ops). */
export const HUB_SECTIONS = [
  'fleet',
  'charts',
  'alerts',
  'overview',
  'live',
  'incidents',
  'settings',
] as const;

/** `local` = this machine; otherwise a fleet host id. */
export type ActiveHostId = 'local' | string;

export const DEFAULT_CHART_GRID: string[] = [
  'host_risk',
  'cpu_percent',
  'mem_percent',
  'net_bytes_recv_per_s',
  'net_bytes_sent_per_s',
  'disk_write_bytes_per_s',
];

function storedActiveHost(): ActiveHostId {
  try {
    const v = localStorage.getItem('sys-active-host');
    return v && v.trim() ? v.trim() : 'local';
  } catch {
    return 'local';
  }
}

function storedChartGridMetrics(): string[] {
  try {
    const raw = localStorage.getItem('sys-chart-grid');
    if (!raw) return [...DEFAULT_CHART_GRID];
    const parsed = JSON.parse(raw) as unknown;
    if (Array.isArray(parsed) && parsed.every((x) => typeof x === 'string') && parsed.length) {
      return parsed as string[];
    }
  } catch {
    /* ignore */
  }
  return [...DEFAULT_CHART_GRID];
}

export const ui = $state({
  lang: storedLang() as Lang,
  theme: storedTheme() as ThemeId,
  advanced: storedAdvanced(),
  fleetHubOnly: storedFleetHubOnly(),
  section: (storedFleetHubOnly() ? 'fleet' : 'home') as SectionId,
  range: '1h' as Range,
  /** Which host Charts/Live/Overview read from. */
  activeHostId: storedActiveHost() as ActiveHostId,
  /** Bumped when active host changes so views clear series caches. */
  hostEpoch: 0,
  /** Metrics shown in the Charts grid (persisted). */
  chartGridMetrics: storedChartGridMetrics() as string[],
  onboardingDone: true as boolean,
  /** False until stack is ready (dev checkout always ready). */
  bootstrapDone: true as boolean,
});

export function setChartGridMetrics(ids: string[]): void {
  const next = ids.map((s) => s.trim()).filter(Boolean);
  ui.chartGridMetrics = next.length ? next : [...DEFAULT_CHART_GRID];
  try {
    localStorage.setItem('sys-chart-grid', JSON.stringify(ui.chartGridMetrics));
  } catch {
    /* ignore */
  }
}

export function isRemoteHost(): boolean {
  return ui.activeHostId !== 'local';
}

export function setActiveHost(id: ActiveHostId): void {
  const next = (id || 'local').trim() || 'local';
  if (next === ui.activeHostId) return;
  ui.activeHostId = next;
  ui.hostEpoch += 1;
  try {
    localStorage.setItem('sys-active-host', next);
  } catch {
    /* ignore */
  }
  // Lazy import avoids a circular dependency with live.svelte.ts.
  void import('./live.svelte').then((m) => m.notifyLiveHostChanged());
}

export function setFleetHubOnly(on: boolean): void {
  ui.fleetHubOnly = on;
  try {
    localStorage.setItem('sys-fleet-hub', on ? '1' : '0');
  } catch {
    /* ignore */
  }
  if (on) {
    ui.section = 'fleet';
  }
}

export function setLang(lang: Lang): void {
  ui.lang = lang;
  try {
    localStorage.setItem('sys-lang', lang);
  } catch {
    /* ignore */
  }
}

export function setTheme(theme: ThemeId): void {
  ui.theme = theme;
  try {
    localStorage.setItem('sys-theme', theme);
    document.documentElement.dataset.theme = theme;
  } catch {
    /* ignore */
  }
}

export function setAdvanced(on: boolean): void {
  ui.advanced = on;
  try {
    localStorage.setItem('sys-advanced', on ? '1' : '0');
  } catch {
    /* ignore */
  }
  if (!on && ADVANCED_SECTIONS.includes(ui.section as (typeof ADVANCED_SECTIONS)[number])) {
    ui.section = 'home';
  }
}

export function applyThemeToDom(): void {
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = ui.theme;
  }
}

export function navSections(): readonly SectionId[] {
  if (ui.fleetHubOnly) {
    return HUB_SECTIONS as unknown as SectionId[];
  }
  if (ui.advanced) {
    return [...SIMPLE_SECTIONS, ...ADVANCED_SECTIONS.filter((s) => s !== 'settingsAdvanced')] as SectionId[];
  }
  return SIMPLE_SECTIONS;
}
