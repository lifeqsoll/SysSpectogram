import { describe, expect, it } from 'vitest';
import { STRINGS } from './i18n';

describe('UI strings', () => {
  it('every key has a non-empty English and Russian text', () => {
    const missing = Object.entries(STRINGS)
      .filter(([, v]) => !v.en.trim() || !v.ru.trim())
      .map(([k]) => k);
    expect(missing).toEqual([]);
  });
});
