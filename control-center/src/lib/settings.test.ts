import { describe, expect, it } from 'vitest';
import { explainChanges, scenarioDraft, validateValue, type SettingEntry } from './settings';

const entries: SettingEntry[] = [
  {
    key: 'kirk.vmi',
    group: 'kirk',
    type: 'bool',
    default: false,
    current: false,
    restart: true,
    title: { en: 'Hypervisor cross-check', ru: 'Проверка с гипервизора' },
    description: { en: 'Read-only comparison.', ru: 'Read-only сверка.' },
  },
  {
    key: 'ensemble.risk_threshold',
    group: 'ensemble',
    type: 'float',
    default: 0.7,
    current: 0.7,
    min: 0,
    max: 1,
    title: { en: 'Risk threshold', ru: 'Порог риска' },
    description: { en: 'Fires at this value.', ru: 'Срабатывает при этом значении.' },
  },
  {
    key: 'response.mode',
    group: 'response',
    type: 'enum',
    default: 'observe',
    current: 'observe',
    choices: ['observe', 'enforce'],
    title: { en: 'Response mode', ru: 'Режим реагирования' },
    description: { en: 'Records only.', ru: 'Только запись.' },
  },
];

describe('validateValue', () => {
  it('checks type and range', () => {
    expect(validateValue(entries[0], true)).toBeNull();
    expect(validateValue(entries[0], 'yes')).not.toBeNull();
    expect(validateValue(entries[1], 1.5)).toMatch(/above maximum/);
    expect(validateValue(entries[1], 0.5)).toBeNull();
  });

  it('checks enum choices', () => {
    expect(validateValue(entries[2], 'enforce')).toBeNull();
    expect(validateValue(entries[2], 'nuke')).not.toBeNull();
  });
});

describe('explainChanges', () => {
  it('reports only real changes and carries restart flag and localized text', () => {
    const draft = { 'kirk.vmi': true, 'ensemble.risk_threshold': 0.7, 'response.mode': 'enforce' };
    const changes = explainChanges(entries, draft, 'ru');
    expect(changes.map((c) => c.key)).toEqual(['kirk.vmi', 'response.mode']);
    expect(changes[0].restart).toBe(true);
    expect(changes[0].title).toBe('Проверка с гипервизора');
    expect(changes[1].restart).toBe(false);
  });

  it('falls back to English when a translation is empty', () => {
    const copy = structuredClone(entries);
    copy[2].title.ru = '';
    const [change] = explainChanges(copy, { 'response.mode': 'enforce' }, 'ru');
    expect(change.title).toBe('Response mode');
  });
});

describe('scenarioDraft', () => {
  it('rejects unknown keys and invalid values', () => {
    const { draft, errors } = scenarioDraft(entries, {
      'response.mode': 'enforce',
      'ssh.PermitRootLogin': 'yes',
      'ensemble.risk_threshold': 2,
    });
    expect(draft).toEqual({ 'response.mode': 'enforce' });
    expect(errors).toHaveLength(2);
  });
});
