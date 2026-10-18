// Pure settings logic: schema types, client-side validation (mirrors helper rules),
// and change explanations. Kept free of UI code so it can be unit-tested.

export type Lang = 'en' | 'ru';

export interface Localized {
  en: string;
  ru: string;
}

export interface SettingEntry {
  key: string;
  group: string;
  type: 'bool' | 'int' | 'float' | 'enum' | 'string';
  default: unknown;
  current?: unknown;
  min?: number;
  max?: number;
  choices?: string[];
  restart?: boolean;
  title: Localized;
  description: Localized;
}

export interface Scenario {
  id: string;
  title: Localized;
  description: Localized;
  overrides: Record<string, unknown>;
}

export interface SettingsExport {
  schema: string;
  groups: Record<string, { title: Localized }>;
  settings: SettingEntry[];
  scenarios: Scenario[];
  overlay: Record<string, unknown>;
  overlay_path: string;
}

export interface SettingChange {
  key: string;
  title: string;
  description: string;
  oldValue: unknown;
  newValue: unknown;
  restart: boolean;
}

export function validateValue(entry: SettingEntry, value: unknown): string | null {
  switch (entry.type) {
    case 'bool':
      return typeof value === 'boolean' ? null : `${entry.key}: expected true or false`;
    case 'int':
    case 'float': {
      if (typeof value !== 'number' || Number.isNaN(value)) return `${entry.key}: expected a number`;
      if (entry.type === 'int' && !Number.isInteger(value)) return `${entry.key}: expected an integer`;
      if (entry.min !== undefined && value < entry.min) return `${entry.key}: below minimum ${entry.min}`;
      if (entry.max !== undefined && value > entry.max) return `${entry.key}: above maximum ${entry.max}`;
      return null;
    }
    case 'enum':
      return entry.choices?.includes(String(value)) ? null : `${entry.key}: must be one of ${entry.choices?.join(', ')}`;
    case 'string':
      if (typeof value !== 'string') return `${entry.key}: expected a string`;
      if (value.length > 2048) return `${entry.key}: string too long`;
      return null;
    default:
      return `${entry.key}: unknown type`;
  }
}

export function sameValue(a: unknown, b: unknown): boolean {
  return a === b || (typeof a === 'number' && typeof b === 'number' && Math.abs(a - b) < 1e-12);
}

/** Changes between the current values and a draft, explained in the requested language. */
export function explainChanges(
  entries: SettingEntry[],
  draft: Record<string, unknown>,
  lang: Lang,
): SettingChange[] {
  const byKey = new Map(entries.map((e) => [e.key, e]));
  const out: SettingChange[] = [];
  for (const [key, newValue] of Object.entries(draft)) {
    const entry = byKey.get(key);
    if (!entry || sameValue(entry.current, newValue)) continue;
    out.push({
      key,
      title: entry.title[lang] || entry.title.en,
      description: entry.description[lang] || entry.description.en,
      oldValue: entry.current,
      newValue,
      restart: Boolean(entry.restart),
    });
  }
  return out;
}

/** Keep only overrides that actually change something, validated against the schema. */
export function scenarioDraft(entries: SettingEntry[], overrides: Record<string, unknown>): {
  draft: Record<string, unknown>;
  errors: string[];
} {
  const byKey = new Map(entries.map((e) => [e.key, e]));
  const draft: Record<string, unknown> = {};
  const errors: string[] = [];
  for (const [key, value] of Object.entries(overrides)) {
    const entry = byKey.get(key);
    if (!entry) {
      errors.push(`${key}: not in the settings schema`);
      continue;
    }
    const err = validateValue(entry, value);
    if (err) errors.push(err);
    else draft[key] = value;
  }
  return { draft, errors };
}

export function formatValue(value: unknown): string {
  if (value === null || value === undefined) return '-';
  if (typeof value === 'boolean') return value ? 'on' : 'off';
  return String(value);
}
