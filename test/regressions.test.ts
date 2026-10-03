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

import { groupSecrets, groupFixes } from '../src/report/compact.js';
import { scanSecrets } from '../src/engines/secrets/scanner.js';
import { runCommand } from '../src/utils/shell.js';
import type { SecretFinding } from '../src/engines/secrets/types.js';
import type { DependencyFinding } from '../src/engines/deps/types.js';

const sf = (over: Partial<SecretFinding>): SecretFinding => ({
  secretType: 'aws-access-key', maskedValue: 'AKIA****', ruleId: 'aws-access-key-id', filePath: '.env',
  commitSha: null, author: null, commitDate: null, lineNumber: 1, fingerprint: Math.random().toString(), ...over,
});

describe('compact report grouping', () => {
  it('collapses history + working-tree duplicates into one group, keeping the oldest commit', () => {
    const g = groupSecrets([
      sf({ commitSha: 'bbb', commitDate: '2026-02-01', author: 'B' }),
      sf({ commitSha: 'aaa', commitDate: '2026-01-01', author: 'A' }),
      sf({ commitSha: null }),
      sf({ filePath: 'other.txt' }),
    ]);
    expect(g).toHaveLength(2);
    const env = g.find((x) => x.filePath === '.env')!;
    expect(env.occurrences).toBe(3);
    expect(env.commitSha).toBe('aaa');
    expect(env.inCurrentFiles).toBe(true);
  });

  it('groups CVEs by the action that fixes them', () => {
    const dep = (name: string, remediation: string): DependencyFinding => ({
      id: name, packageName: name, severity: 'high', findingType: 'cve', title: name, description: name, remediation,
    });
    const r = groupFixes([
      dep('a', 'Run npm audit fix or update package version in package.json'),
      dep('b', 'Update to next@16.3.8 (patch)'),
      dep('c', 'Update to next@16.3.8 (patch)'),
      dep('d', 'Update to x@2.0.0 (major upgrade)'),
      dep('e', 'Contact the maintainer'),
    ]);
    expect(r.auto).toHaveLength(1);
    expect(r.updates.find((u) => u.label === 'next@16.3.8')!.findings).toHaveLength(2);
    expect(r.updates.find((u) => u.label === 'x@2.0.0')!.breaking).toBe(true);
    expect(r.manual).toHaveLength(1);
  });
});

describe('secret scanner false positives', () => {
  it('ignores placeholders and .env.example but still flags real secrets', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'rg-fp-'));
    await runCommand('git', ['init', '-q', dir]);
    await runCommand('git', ['-C', dir, 'config', 'user.email', 'a@b.c']);
    await runCommand('git', ['-C', dir, 'config', 'user.name', 't']);
    writeFileSync(join(dir, '.env.example'), 'API_KEY=your_api_key_here\nSECRET=replace_me_please\n');
    writeFileSync(join(dir, 'README.md'), 'Set SECRET=your_secret_value in .env\n');
    writeFileSync(join(dir, 'real.js'), "const k = 'AKIAIOSFODNN7EXAMPLE';\n");
    await runCommand('git', ['-C', dir, 'add', '.']);
    await runCommand('git', ['-C', dir, 'commit', '-qm', 'x']);
    const res = await scanSecrets(dir, 'me/fp', 'full-history');
    const files = new Set(res.findings.map((f) => f.filePath));
    expect(files.has('real.js')).toBe(true);
    expect(files.has('.env.example')).toBe(false);
    expect(files.has('README.md')).toBe(false);
  }, 30_000);
});

import { trapExit, ExitTrapped, isExitTrapped } from '../src/utils/exit.js';

describe('trapExit', () => {
  it('turns an exit inside the trap into a result, and un-traps afterwards', async () => {
    const r = await trapExit(async () => {
      throw new ExitTrapped(3);
    });
    expect(r.exitCode).toBe(3);
    expect(isExitTrapped()).toBe(false);
  });
  it('returns the value when nothing exits', async () => {
    expect((await trapExit(async () => 42)).value).toBe(42);
  });
  it('rethrows unrelated errors', async () => {
    await expect(trapExit(async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    expect(isExitTrapped()).toBe(false);
  });
});
