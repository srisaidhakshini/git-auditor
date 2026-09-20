/**
 * protection.ts — GitHub branch protection & Pull Request conflict checks.
 */

import { Octokit } from '@octokit/rest';
import type { GitHubAuth } from './auth.js';
import { logger } from '../utils/logger.js';

export interface BranchProtectionStatus {
  isProtected: boolean;
  allowForcePushes: boolean;
  requiresApprovingReviews: boolean;
  requiredStatusChecks: string[];
}

export interface PRConflictStatus {
  hasOpenPRs: boolean;
  openPRCount: number;
  prUrls: string[];
}

/**
 * Checks branch protection rules for a given repository branch.
 */
export async function checkBranchProtection(
  auth: GitHubAuth,
  owner: string,
  repo: string,
  branch: string,
): Promise<BranchProtectionStatus> {
  const octokit = new Octokit({ auth: auth.token });

  try {
    const res = await octokit.repos.getBranchProtection({
      owner,
      repo,
      branch,
    });

    const data = res.data;
    return {
      isProtected: true,
      allowForcePushes: data.allow_force_pushes?.enabled ?? false,
      requiresApprovingReviews: Boolean(data.required_pull_request_reviews),
      requiredStatusChecks: data.required_status_checks?.contexts ?? [],
    };
  } catch (err: any) {
    // If 404, branch protection is not enabled or branch does not exist
    if (err.status === 404) {
      return {
        isProtected: false,
        allowForcePushes: true,
        requiresApprovingReviews: false,
        requiredStatusChecks: [],
      };
    }

    logger.debug(`Branch protection check error: ${err.message}`);
    return {
      isProtected: false,
      allowForcePushes: true,
      requiresApprovingReviews: false,
      requiredStatusChecks: [],
    };
  }
}

/**
 * Checks if there are open Pull Requests targeting the affected branch.
 */
export async function checkOpenPullRequests(
  auth: GitHubAuth,
  owner: string,
  repo: string,
  branch: string,
): Promise<PRConflictStatus> {
  const octokit = new Octokit({ auth: auth.token });

  try {
    const res = await octokit.pulls.list({
      owner,
      repo,
      base: branch,
      state: 'open',
      per_page: 30,
    });

    return {
      hasOpenPRs: res.data.length > 0,
      openPRCount: res.data.length,
      prUrls: res.data.map((pr) => pr.html_url),
    };
  } catch (err) {
    logger.debug(`PR conflict check error: ${err instanceof Error ? err.message : String(err)}`);
    return {
      hasOpenPRs: false,
      openPRCount: 0,
      prUrls: [],
    };
  }
}
