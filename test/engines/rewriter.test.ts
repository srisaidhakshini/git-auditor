import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCommand } from '../../src/utils/shell.js';
import {
  createVerifiedBackup,
  dryRunRewrite,
  executeRewrite,
} from '../../src/engines/secrets/rewriter.js';

describe('History Rewriter Engine', () => {
  let testRepoDir: string;

  beforeEach(async () => {
    testRepoDir = mkdtempSync(join(tmpdir(), 'repo-guardian-test-repo-'));

    // Initialize git repo
    await runCommand('git', ['init', '-b', 'main'], { cwd: testRepoDir });
    await runCommand('git', ['config', 'user.name', 'Test User'], { cwd: testRepoDir });
    await runCommand('git', ['config', 'user.email', 'test@example.com'], { cwd: testRepoDir });

    // Commit 1: Initial readme
    writeFileSync(join(testRepoDir, 'README.md'), '# Test Repository\n');
    await runCommand('git', ['add', 'README.md'], { cwd: testRepoDir });
    await runCommand('git', ['commit', '-m', 'Initial commit'], { cwd: testRepoDir });

    // Commit 2: Leaked secret .env
    writeFileSync(join(testRepoDir, '.env'), 'AWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n');
    await runCommand('git', ['add', '.env'], { cwd: testRepoDir });
    await runCommand('git', ['commit', '-m', 'Add config and env'], { cwd: testRepoDir });

    // Commit 3: App code
    writeFileSync(join(testRepoDir, 'index.js'), 'console.log("hello world");\n');
    await runCommand('git', ['add', 'index.js'], { cwd: testRepoDir });
    await runCommand('git', ['commit', '-m', 'Add app code'], { cwd: testRepoDir });
  });

  afterEach(() => {
    try {
      rmSync(testRepoDir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  it('creates and verifies a restorable git bundle backup', async () => {
    const backup = await createVerifiedBackup(testRepoDir);
    expect(backup.verified).toBe(true);
    expect(existsSync(backup.backupPath)).toBe(true);

    // Cleanup backup file
    try {
      rmSync(backup.backupPath, { force: true });
    } catch {}
  });

  it('dry-run identifies commits containing sensitive files', async () => {
    const dryRun = await dryRunRewrite(testRepoDir, ['.env']);
    expect(dryRun.totalCommitsToRewrite).toBe(1);
    expect(dryRun.affectedCommits[0]?.matchedFiles).toContain('.env');
    expect(dryRun.affectedCommits[0]?.message).toBe('Add config and env');
  });

  it('rewrites history and purges the target file from all commits', async () => {
    const backup = await createVerifiedBackup(testRepoDir);
    const result = await executeRewrite(testRepoDir, ['.env'], 'test/repo', backup.backupPath);

    expect(result.success).toBe(true);

    // Verify .env is completely missing from working directory and git log
    expect(existsSync(join(testRepoDir, '.env'))).toBe(false);

    const logCheck = await runCommand('git', ['log', '--all', '--', '.env'], { cwd: testRepoDir });
    expect(logCheck.stdout.trim()).toBe('');

    // Verify clean files are preserved
    expect(existsSync(join(testRepoDir, 'README.md'))).toBe(true);
    expect(existsSync(join(testRepoDir, 'index.js'))).toBe(true);
  });
});
