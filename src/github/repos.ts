/**
 * repos.ts — GitHub repository listing via Octokit.
 *
 * Phase 1: lists repos owned by the authenticated user only.
 * --include-collaborator flag is deferred to Phase 2.
 */

import { Octokit } from '@octokit/rest';
import type { GitHubAuth } from './auth.js';
import { logger } from '../utils/logger.js';

export interface GitHubRepo {
  name: string;
  fullName: string;
  cloneUrl: string;
  sshUrl: string;
  defaultBranch: string;
  private: boolean;
  htmlUrl: string;
}

/**
 * Lists all repos owned by the authenticated user.
 * Paginates automatically until all repos are fetched.
 */
export async function listOwnedRepos(auth: GitHubAuth): Promise<GitHubRepo[]> {
  const octokit = new Octokit({ auth: auth.token });

  const repos: GitHubRepo[] = [];
  let page = 1;

  logger.info('Fetching repository list from GitHub...');

  while (true) {
    const response = await octokit.repos.listForAuthenticatedUser({
      affiliation: 'owner', // Phase 1: owned only
      sort: 'updated',
      per_page: 100,
      page,
    });

    const batch = response.data;
    if (batch.length === 0) break;

    for (const r of batch) {
      repos.push({
        name: r.name,
        fullName: r.full_name,
        cloneUrl: r.clone_url,
        sshUrl: r.ssh_url,
        defaultBranch: r.default_branch,
        private: r.private,
        htmlUrl: r.html_url,
      });
    }

    if (batch.length < 100) break;
    page++;
  }

  logger.info(`Found ${repos.length} owned repositories`);
  return repos;
}

/**
 * Finds a single repo by name (owner/name or just name for the authed user).
 */
export async function findRepo(
  auth: GitHubAuth,
  repoName: string,
): Promise<GitHubRepo> {
  const octokit = new Octokit({ auth: auth.token });

  // Support "owner/repo" or bare "repo" (assume authed user as owner)
  let owner: string;
  let repo: string;

  if (repoName.includes('/')) {
    [owner, repo] = repoName.split('/', 2) as [string, string];
  } else {
    const user = await octokit.users.getAuthenticated();
    owner = user.data.login;
    repo = repoName;
  }

  const response = await octokit.repos.get({ owner, repo });
  const r = response.data;

  return {
    name: r.name,
    fullName: r.full_name,
    cloneUrl: r.clone_url,
    sshUrl: r.ssh_url,
    defaultBranch: r.default_branch,
    private: r.private,
    htmlUrl: r.html_url,
  };
}
