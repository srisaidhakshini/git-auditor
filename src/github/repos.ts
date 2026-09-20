/**
 * repos.ts — GitHub repository listing via Octokit.
 *
 * Lists repos owned by the authenticated user and looks up individual repositories.
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

function handleOctokitError(err: any): never {
  const errMsg = err?.message || String(err);
  const isDnsOrNetwork =
    err?.code === 'ENOTFOUND' ||
    err?.cause?.code === 'ENOTFOUND' ||
    errMsg.includes('ENOTFOUND') ||
    errMsg.includes('fetch failed') ||
    errMsg.includes('ETIMEDOUT') ||
    errMsg.includes('ECONNREFUSED');

  if (isDnsOrNetwork) {
    throw new Error(
      'Network connection failed: Unable to reach api.github.com.\n' +
        'Please check your internet connection or proxy settings.',
    );
  }

  if (err?.status === 401 || errMsg.includes('Bad credentials')) {
    throw new Error(
      'GitHub authentication failed (401 Unauthorized).\n' +
        'Your GitHub token is invalid or expired. Please run:\n' +
        '  repo-guardian auth login\n' +
        'or update your GITHUB_TOKEN environment variable.',
    );
  }

  if (err?.status === 404) {
    throw new Error('Repository not found or access denied (404).');
  }

  if (err?.status === 403) {
    throw new Error('GitHub API rate limit exceeded or access forbidden (403).');
  }

  throw new Error(errMsg);
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

  try {
    while (true) {
      const response = await octokit.repos.listForAuthenticatedUser({
        affiliation: 'owner',
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
  } catch (err) {
    handleOctokitError(err);
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

  let owner: string;
  let repo: string;

  try {
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
  } catch (err) {
    handleOctokitError(err);
  }
}
