// Shared UI state (Svelte 5 runes). Language defaults to English.
import type { Lang } from './settings';
import type { Range } from './api';

/** Simple-home sections (default). */
export const SIMPLE_SECTIONS = ['home', 'charts', 'alerts', 'settings'] as const;

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

export const ui = $state({
  lang: storedLang() as Lang,
  theme: storedTheme() as ThemeId,
  advanced: storedAdvanced(),
  section: 'home' as SectionId,
  range: '1h' as Range,
  onboardingDone: true as boolean,
  /** False until stack is ready (dev checkout always ready). */
  bootstrapDone: true as boolean,
});

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
  if (ui.advanced) {
    return [...SIMPLE_SECTIONS, ...ADVANCED_SECTIONS.filter((s) => s !== 'settingsAdvanced')] as SectionId[];
  }
  return SIMPLE_SECTIONS;
}
