import { describe, it, expect } from 'vitest';
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { extractRepo } from '../src/agent/orchestrator.js';
import { executeAgentTool } from '../src/agent/tools.js';
import { installPreCommitHook } from '../src/engines/prevention/hooks.js';

describe('extractRepo (offline chat planner)', () => {
  it('ignores command words and repo names containing keywords', () => {
    expect(extractRepo('scan git-auditor for secrets')).toBe('git-auditor');
    expect(extractRepo('dry run clean git-auditor')).toBe('git-auditor');
    expect(extractRepo('check dependencies in owner/my-repo')).toBe('owner/my-repo');
  });
  it('returns null when no repo is named', () => {
    expect(extractRepo('scan for secrets')).toBeNull();
    expect(extractRepo('clean history')).toBeNull();
  });
});

describe('init_prevention agent tool', () => {
  it('refuses a directory that is not a git repo and creates nothing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'rg-nogit-'));
    const res = await executeAgentTool(
      { id: '1', name: 'init_prevention', input: { target_path: dir } },
      { workingDir: dir, autoConfirmNonDestructive: true },
    );
    expect(res['error']).toBeDefined();
    expect(existsSync(join(dir, '.git'))).toBe(false);
    expect(existsSync(join(dir, '.gitignore'))).toBe(false);
  });
});

describe('installPreCommitHook', () => {
  it('preserves and chains an existing user hook, idempotently', () => {
    const repo = mkdtempSync(join(tmpdir(), 'rg-hook-'));
    mkdirSync(join(repo, '.git', 'hooks'), { recursive: true });
    const hook = join(repo, '.git', 'hooks', 'pre-commit');
    writeFileSync(hook, '#!/bin/sh\necho custom\n');
    installPreCommitHook(repo);
    installPreCommitHook(repo);
    expect(readFileSync(join(repo, '.git', 'hooks', 'pre-commit.pre-guardian'), 'utf8')).toContain('custom');
    expect(readFileSync(hook, 'utf8')).toContain('pre-commit.pre-guardian');
  });
});
