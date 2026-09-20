/**
 * pusher.ts — Confirmation-gated force push flow with branch protection checks.
 *
 * Implements PRD §4.3, §4.4, §5:
 * 1. Checks branch protection & open PRs
 * 2. Requires explicit human confirmation before git push --force
 * 3. Logs audit trail
 */

import { runCommand } from '../../utils/shell.js';
import { logger } from '../../utils/logger.js';
import { recordAuditEvent } from '../../utils/audit.js';
import { checkBranchProtection, checkOpenPullRequests } from '../../github/protection.js';
import type { GitHubAuth } from '../../github/auth.js';

export interface PushResult {
  success: boolean;
  repoFullName: string;
  branch: string;
  pushedSha?: string;
  blockedByProtection?: boolean;
  protectionWarning?: string;
  error?: string;
}

/**
 * Pushes rewritten history to remote repository after verifying protection and confirmation.
 */
export async function pushRewrittenHistory(
  repoPath: string,
  repoFullName: string,
  branch: string,
  auth: GitHubAuth,
  forcePushConfirmed: boolean = false,
): Promise<PushResult> {
  if (!forcePushConfirmed) {
    return {
      success: false,
      repoFullName,
      branch,
      error: 'Force push was cancelled: missing explicit human confirmation.',
    };
  }

  const [owner, repo] = repoFullName.split('/', 2);
  if (owner && repo) {
    // 1. Check branch protection
    const protection = await checkBranchProtection(auth, owner, repo, branch);
    if (protection.isProtected && !protection.allowForcePushes) {
      const warning = `Branch "${branch}" is protected on GitHub and disallows force pushes.`;
      logger.warn(warning);
      return {
        success: false,
        repoFullName,
        branch,
        blockedByProtection: true,
        protectionWarning: warning,
        error: warning,
      };
    }

    // 2. Check open PRs
    const prStatus = await checkOpenPullRequests(auth, owner, repo, branch);
    if (prStatus.hasOpenPRs) {
      logger.warn(
        `Branch "${branch}" has ${prStatus.openPRCount} open PR(s) which will become conflicted after force push.`,
      );
    }
  }

  // 3. Perform force push
  const pushRes = await runCommand('git', ['push', '--force', 'origin', branch], {
    cwd: repoPath,
  });

  if (pushRes.exitCode !== 0) {
    return {
      success: false,
      repoFullName,
      branch,
      error: `git push --force failed:\n${pushRes.stderr}`,
    };
  }

  const headRes = await runCommand('git', ['rev-parse', 'HEAD'], { cwd: repoPath });
  const pushedSha = headRes.stdout.trim();

  // 4. Audit trail
  recordAuditEvent(
    'FORCE_PUSH_EXECUTED',
    repoFullName,
    {
      branch,
      pushedSha,
    },
    true,
  );

  return {
    success: true,
    repoFullName,
    branch,
    pushedSha,
  };
}
