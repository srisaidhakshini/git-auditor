import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, readFileSync, existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { patchGitignore } from '../../src/engines/prevention/gitignore.js';
import { installPreCommitHook } from '../../src/engines/prevention/hooks.js';

describe('Prevention Layer', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'repo-guardian-prevention-test-'));
  });

  afterEach(() => {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });

  it('creates .gitignore with security rules if it does not exist', () => {
    const result = patchGitignore(tempDir);
    expect(result.created).toBe(true);
    expect(result.modified).toBe(true);
    expect(result.addedPatterns.length).toBeGreaterThan(0);

    const content = readFileSync(join(tempDir, '.gitignore'), 'utf8');
    expect(content).toContain('.env');
    expect(content).toContain('*.pem');
    expect(content).toContain('node_modules/');
  });

  it('patches existing .gitignore without clobbering existing custom entries', () => {
    const customContent = '# My custom ignore rules\n*.log\ncustom_build/\n';
    writeFileSync(join(tempDir, '.gitignore'), customContent, 'utf8');

    const result = patchGitignore(tempDir);
    expect(result.created).toBe(false);
    expect(result.modified).toBe(true);

    const updatedContent = readFileSync(join(tempDir, '.gitignore'), 'utf8');
    expect(updatedContent).toContain('*.log');
    expect(updatedContent).toContain('custom_build/');
    expect(updatedContent).toContain('.env');
  });

  it('does not modify .gitignore if all security patterns are already present', () => {
    patchGitignore(tempDir);
    const secondResult = patchGitignore(tempDir);
    expect(secondResult.modified).toBe(false);
    expect(secondResult.addedPatterns).toHaveLength(0);
  });

  it('installs pre-commit hook script into .git/hooks directory', () => {
    mkdirSync(join(tempDir, '.git', 'hooks'), { recursive: true });
    const hookResult = installPreCommitHook(tempDir);

    expect(hookResult.installed).toBe(true);
    expect(existsSync(hookResult.hookPath)).toBe(true);

    const hookContent = readFileSync(hookResult.hookPath, 'utf8');
    expect(hookContent).toContain('Repo Guardian Pre-Commit Hook');
    expect(hookContent).toContain('gitleaks');
  });
});
