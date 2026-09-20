/**
 * rewriter.ts — Safe Git history rewrite engine.
 *
 * Implements:
 * 1. Verifiable full git bundle backup creation
 * 2. Dry-run inspection predicting affected commits/files
 * 3. Destructive history rewrite (git filter-repo or git filter-branch fallback)
 * 4. Aggressive garbage collection & reflog expiration
 */

import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runCommand } from '../../utils/shell.js';
import { logger } from '../../utils/logger.js';
import { recordAuditEvent } from '../../utils/audit.js';

export interface AffectedCommit {
  commitSha: string;
  author: string;
  date: string;
  message: string;
  matchedFiles: string[];
}

export interface DryRunResult {
  repoPath: string;
  targetPatterns: string[];
  affectedCommits: AffectedCommit[];
  totalCommitsToRewrite: number;
}

export interface BackupResult {
  backupPath: string;
  verified: boolean;
  timestamp: string;
}

export interface RewriteResult {
  success: boolean;
  repoPath: string;
  targetPatterns: string[];
  backupPath: string;
  headShaBefore: string;
  headShaAfter: string;
  commitsModified: number;
  durationMs: number;
  error?: string;
}

/**
 * Creates a restorable git bundle backup of the entire repository history.
 * Verifies that the bundle can be restored before proceeding.
 */
export async function createVerifiedBackup(
  repoPath: string,
  customBackupDir?: string,
): Promise<BackupResult> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const backupDir = customBackupDir || join(tmpdir(), 'repo-guardian-backups');

  if (!existsSync(backupDir)) {
    mkdirSync(backupDir, { recursive: true });
  }

  const backupPath = join(backupDir, `backup-${timestamp}.bundle`);

  // 1. Create bundle containing all refs and tags
  const createRes = await runCommand('git', ['bundle', 'create', backupPath, '--all'], {
    cwd: repoPath,
  });

  if (createRes.exitCode !== 0) {
    throw new Error(`Failed to create git bundle backup: ${createRes.stderr}`);
  }

  // 2. Verify bundle integrity
  const verifyRes = await runCommand('git', ['bundle', 'verify', backupPath], {
    cwd: repoPath,
  });

  if (verifyRes.exitCode !== 0) {
    throw new Error(`Git bundle verification failed: ${verifyRes.stderr}`);
  }

  logger.info(`Verified backup created at: ${backupPath}`);
  return {
    backupPath,
    verified: true,
    timestamp,
  };
}

/**
 * Performs a dry run predicting which commits and files will be rewritten.
 */
export async function dryRunRewrite(
  repoPath: string,
  targetPatterns: string[],
): Promise<DryRunResult> {
  const affectedCommits: AffectedCommit[] = [];

  // Get log of commits touching any matching files
  for (const pattern of targetPatterns) {
    const res = await runCommand(
      'git',
      ['log', '--all', '--name-only', '--format=COMMIT:%H|%an|%ad|%s', '--', pattern],
      { cwd: repoPath },
    );

    if (res.exitCode !== 0 || !res.stdout.trim()) {
      continue;
    }

    const blocks = res.stdout.split('COMMIT:').filter(Boolean);
    for (const block of blocks) {
      const lines = block.split('\n').map((l) => l.trim()).filter(Boolean);
      const header = lines[0];
      if (!header) continue;

      const [sha = '', author = '', date = '', message = ''] = header.split('|');
      const files = lines.slice(1).filter((f) => !f.startsWith('COMMIT:'));

      const existing = affectedCommits.find((c) => c.commitSha === sha);
      if (existing) {
        for (const f of files) {
          if (!existing.matchedFiles.includes(f)) {
            existing.matchedFiles.push(f);
          }
        }
      } else {
        affectedCommits.push({
          commitSha: sha,
          author,
          date,
          message,
          matchedFiles: files.length > 0 ? files : [pattern],
        });
      }
    }
  }

  recordAuditEvent(
    'REWRITE_DRY_RUN',
    repoPath,
    { targetPatterns, affectedCount: affectedCommits.length },
    false,
  );

  return {
    repoPath,
    targetPatterns,
    affectedCommits,
    totalCommitsToRewrite: affectedCommits.length,
  };
}

/**
 * Executes destructive history rewrite to excise sensitive files across all commits.
 */
export async function executeRewrite(
  repoPath: string,
  targetPatterns: string[],
  repoFullName: string,
  backupPath: string,
): Promise<RewriteResult> {
  const startTime = Date.now();

  // 1. Get HEAD SHA before rewrite
  const headBeforeRes = await runCommand('git', ['rev-parse', 'HEAD'], { cwd: repoPath });
  const headShaBefore = headBeforeRes.stdout.trim();

  // 2. Check if git-filter-repo is installed
  const filterRepoCheck = await runCommand('git', ['filter-repo', '--version'], { cwd: repoPath });
  const hasFilterRepo = filterRepoCheck.exitCode === 0;

  let rewriteError: string | undefined;

  if (hasFilterRepo) {
    // Use git-filter-repo
    const args = ['filter-repo', '--force'];
    for (const p of targetPatterns) {
      args.push('--path-glob', p, '--invert-paths');
    }

    const rewriteRes = await runCommand('git', args, { cwd: repoPath });
    if (rewriteRes.exitCode !== 0) {
      rewriteError = rewriteRes.stderr;
    }
  } else {
    // Fallback to git filter-branch
    // Build rm command for patterns
    const rmArgs = targetPatterns.map((p) => `"${p}"`).join(' ');
    const indexFilter = `git rm --cached --ignore-unmatch -r ${rmArgs}`;

    const filterBranchRes = await runCommand(
      'git',
      [
        'filter-branch',
        '--force',
        '--index-filter',
        indexFilter,
        '--prune-empty',
        '--tag-name-filter',
        'cat',
        '--',
        '--all',
      ],
      { cwd: repoPath },
    );

    if (filterBranchRes.exitCode !== 0) {
      rewriteError = filterBranchRes.stderr;
    }
  }

  if (rewriteError) {
    return {
      success: false,
      repoPath,
      targetPatterns,
      backupPath,
      headShaBefore,
      headShaAfter: headShaBefore,
      commitsModified: 0,
      durationMs: Date.now() - startTime,
      error: `History rewrite command failed: ${rewriteError}`,
    };
  }

  // 3. Remove backup refs created by filter-branch and expire reflogs
  try {
    const { rmSync } = await import('node:fs');
    rmSync(join(repoPath, '.git', 'refs', 'original'), { recursive: true, force: true });
    rmSync(join(repoPath, '.git', 'logs'), { recursive: true, force: true });
  } catch {}

  await runCommand('git', ['reflog', 'expire', '--expire=now', '--all'], { cwd: repoPath });
  await runCommand('git', ['gc', '--prune=now', '--aggressive'], { cwd: repoPath });

  // 4. Get HEAD SHA after rewrite
  const headAfterRes = await runCommand('git', ['rev-parse', 'HEAD'], { cwd: repoPath });
  const headShaAfter = headAfterRes.stdout.trim();

  // Audit record
  recordAuditEvent(
    'REWRITE_EXECUTED',
    repoFullName,
    {
      targetPatterns,
      backupPath,
      headShaBefore,
      headShaAfter,
      durationMs: Date.now() - startTime,
    },
    true,
  );

  return {
    success: true,
    repoPath,
    targetPatterns,
    backupPath,
    headShaBefore,
    headShaAfter,
    commitsModified: headShaBefore !== headShaAfter ? 1 : 0,
    durationMs: Date.now() - startTime,
  };
}
