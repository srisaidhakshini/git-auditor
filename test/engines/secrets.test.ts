/**
 * secrets.test.ts — Integration test for the secrets engine.
 *
 * Validates scan_secrets behavior against dirty-repo fixture.
 * If gitleaks is installed: asserts findings, correct masking, required fields, and deduplication.
 * If gitleaks is not installed: asserts graceful failure response with install instructions.
 */

import { describe, it, expect, beforeAll } from 'vitest';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { existsSync } from 'node:fs';
import { runCommand } from '../../src/utils/shell.js';
import { scanSecrets } from '../../src/engines/secrets/scanner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURE_PATH = resolve(__dirname, '../fixtures/dirty-repo');

const KNOWN_RAW_SECRETS = [
  'AKIAIOSFODNN7EXAMPLE',
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  'ghp_EXAMPLE1234567890abcdefghijklmnopqrs',
];

describe('scan_secrets — dirty-repo fixture', () => {
  let hasGitleaks = false;

  beforeAll(async () => {
    // Ensure test fixture git repository is initialized
    const gitDir = resolve(FIXTURE_PATH, '.git');
    if (!existsSync(gitDir)) {
      await runCommand('git', ['init', FIXTURE_PATH]);
      await runCommand('git', ['-C', FIXTURE_PATH, 'config', 'user.email', 'test@repo-guardian.local']);
      await runCommand('git', ['-C', FIXTURE_PATH, 'config', 'user.name', 'Test User']);
      await runCommand('git', ['-C', FIXTURE_PATH, 'add', '.']);
      await runCommand('git', ['-C', FIXTURE_PATH, 'commit', '-m', 'fixture initial commit']);
    }

    try {
      const checkCmd = process.platform === 'win32' ? 'where' : 'which';
      const check = await runCommand(checkCmd, ['gitleaks']);
      hasGitleaks = check.exitCode === 0 && check.stdout.trim().length > 0;
      if (!hasGitleaks) {
        console.warn('\n⚠️  gitleaks not found in PATH — running graceful fallback tests.');
      }
    } catch {
      hasGitleaks = false;
    }
  });

  it('fixture repo exists and has been committed', () => {
    expect(existsSync(FIXTURE_PATH)).toBe(true);
    expect(existsSync(resolve(FIXTURE_PATH, '.git'))).toBe(true);
    expect(existsSync(resolve(FIXTURE_PATH, '.env'))).toBe(true);
  });

  it('handles missing binary or completes scan', async () => {
    const result = await scanSecrets(FIXTURE_PATH, 'test/dirty-repo', 'full-history');

    if (!hasGitleaks) {
      expect(result.success).toBe(false);
      expect(result.error).toContain('gitleaks');
      expect(result.error).toContain('not found');
      expect(result.findings).toEqual([]);
    } else {
      expect(result.success).toBe(true);
      expect(result.repoFullName).toBe('test/dirty-repo');
      expect(result.mode).toBe('full-history');
      expect(result.durationMs).toBeGreaterThan(0);
    }
  }, 30_000);

  it('detects and masks secrets when gitleaks is available', async () => {
    const result = await scanSecrets(FIXTURE_PATH, 'test/dirty-repo', 'full-history');

    if (!hasGitleaks || !result.success) {
      expect(result.findings).toEqual([]);
      return;
    }

    expect(result.findings.length).toBeGreaterThan(0);

    for (const finding of result.findings) {
      // Must never expose raw secrets
      for (const rawSecret of KNOWN_RAW_SECRETS) {
        expect(finding.maskedValue).not.toContain(rawSecret);
      }
      expect(finding.maskedValue).toMatch(/\*{4}$/);
      expect(finding.maskedValue.length).toBeLessThanOrEqual(8);

      // Verify shape
      expect(finding.secretType).toBeDefined();
      expect(finding.ruleId).toBeDefined();
      expect(finding.filePath).toBeDefined();
      expect(finding.fingerprint).toBeDefined();
      expect(finding.commitSha).not.toBeNull();
    }

    // Deduplication check
    const fingerprints = result.findings.map((f) => f.fingerprint);
    const unique = new Set(fingerprints);
    expect(fingerprints.length).toBe(unique.size);
  }, 30_000);

  it('handles non-existent repository path gracefully', async () => {
    const invalidPath = resolve(__dirname, '../fixtures/does-not-exist');
    const result = await scanSecrets(invalidPath, 'test/invalid-repo', 'full-history');

    expect(result.success).toBe(false);
    expect(result.error).toBeDefined();
  });
});
