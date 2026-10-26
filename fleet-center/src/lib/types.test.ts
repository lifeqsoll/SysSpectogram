import { describe, expect, it } from 'vitest';
import { hostHasToken, type Host } from './types';

describe('hostHasToken', () => {
  it('prefers token_set boolean', () => {
    expect(hostHasToken({ id: 'a', label: 'A', ssh: 'a@h', role: 'worker', token_set: true })).toBe(
      true,
    );
    expect(hostHasToken({ id: 'b', label: 'B', ssh: 'b@h', role: 'worker', token_set: false })).toBe(
      false,
    );
  });

  it('ignores masked legacy device_token', () => {
    const h: Host = {
      id: 'c',
      label: 'C',
      ssh: 'c@h',
      role: 'worker',
      device_token: '***',
    };
    expect(hostHasToken(h)).toBe(false);
  });
});
