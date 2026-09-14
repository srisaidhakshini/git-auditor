import { describe, it, expect } from 'vitest';
import { maskSecret, redactFromString } from '../../src/utils/mask.js';

describe('mask.ts', () => {
  it('masks secret values correctly', () => {
    expect(maskSecret('AKIAIOSFODNN7EXAMPLE')).toBe('AKIA****');
    expect(maskSecret('ghp_abcdef123456')).toBe('ghp_****');
  });

  it('masks short or empty strings safely', () => {
    expect(maskSecret('')).toBe('****');
    expect(maskSecret('abc')).toBe('****');
    expect(maskSecret('1234')).toBe('****');
  });

  it('redacts occurrences of a secret from a multiline string', () => {
    const rawText = 'Error occurred with token ghp_secret12345 in line 10';
    const redacted = redactFromString(rawText, 'ghp_secret12345');
    expect(redacted).toBe('Error occurred with token ghp_**** in line 10');
    expect(redacted).not.toContain('ghp_secret12345');
  });
});
