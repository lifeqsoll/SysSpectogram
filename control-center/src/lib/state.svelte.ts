// Shared UI state (Svelte 5 runes). Language defaults to English.
import type { Lang } from './settings';
import type { Range } from './api';

export const SECTIONS = [
  'overview',
  'live',
  'dashboards',
  'incidents',
  'agent',
  'perimeter',
  'settings',
  'scenarios',
  'lab',
  'install',
  'logs',
  'about',
] as const;

export type SectionId = (typeof SECTIONS)[number];

function storedLang(): Lang {
  const v = typeof localStorage !== 'undefined' ? localStorage.getItem('sys-lang') : null;
  return v === 'ru' ? 'ru' : 'en';
}

export const ui = $state({
  lang: storedLang() as Lang,
  section: 'overview' as SectionId,
  range: '1h' as Range,
});

export function setLang(lang: Lang): void {
  ui.lang = lang;
  try {
    localStorage.setItem('sys-lang', lang);
  } catch {
    // storage may be unavailable; the choice then lasts for this session only
  }
}
