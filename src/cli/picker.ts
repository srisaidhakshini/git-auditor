/**
 * picker.ts — Interactive helpers so commands work without memorising flags.
 */

import inquirer from 'inquirer';
import chalk from 'chalk';
import { resolveGitHubToken } from '../github/auth.js';
import { listOwnedRepos } from '../github/repos.js';
import { loadCachedRepos, saveReposToCache } from '../github/cache.js';
import type { GitHubRepo } from '../github/repos.js';

/** True when we can safely ask the user questions. */
export function isInteractive(): boolean {
  return Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

async function loadRepos(): Promise<GitHubRepo[]> {
  const cached = loadCachedRepos(false);
  if (cached) return cached;
  const auth = await resolveGitHubToken();
  console.log(chalk.dim('Fetching your repositories from GitHub...'));
  const repos = await listOwnedRepos(auth);
  saveReposToCache(repos);
  return repos;
}

/** Lets the user pick one of their repositories; returns its full name. */
export async function pickRepo(message = 'Which repository?'): Promise<string> {
  const repos = await loadRepos();
  if (repos.length === 0) {
    throw new Error('No repositories found for this GitHub account.');
  }
  const { repo } = await inquirer.prompt<{ repo: string }>([
    {
      type: 'select',
      name: 'repo',
      message,
      pageSize: 15,
      choices: repos.map((r) => ({
        name: `${r.fullName}${r.private ? chalk.dim('  (private)') : ''}`,
        value: r.fullName,
      })),
    },
  ]);
  return repo;
}

/** Asks whether to scan one repo or all of them. */
export async function pickScanTarget(): Promise<{ repo?: string; all?: boolean }> {
  const { target } = await inquirer.prompt<{ target: 'one' | 'all' }>([
    {
      type: 'select',
      name: 'target',
      message: 'What do you want to scan?',
      choices: [
        { name: 'One repository', value: 'one' },
        { name: 'All my repositories', value: 'all' },
      ],
    },
  ]);
  return target === 'all' ? { all: true } : { repo: await pickRepo('Which repository to scan?') };
}
