/**
 * auth.ts — GitHub authentication resolution.
 *
 * Phase 1: reads GITHUB_TOKEN from environment.
 * Falls back to `gh auth token` if the env var is not set.
 */

import { runCommand } from '../utils/shell.js';
import { logger } from '../utils/logger.js';

export interface GitHubAuth {
  token: string;
  source: 'env' | 'gh-cli';
}

/**
 * Resolves a GitHub PAT. Precedence:
 * 1. GITHUB_TOKEN environment variable
 * 2. `gh auth token` (requires gh CLI to be installed and logged in)
 *
 * Throws if no token can be found.
 */
export async function resolveGitHubToken(): Promise<GitHubAuth> {
  const envToken = process.env['GITHUB_TOKEN'];
  if (envToken && envToken.trim().length > 0) {
    logger.debug('Using GITHUB_TOKEN from environment');
    return { token: envToken.trim(), source: 'env' };
  }

  logger.debug('GITHUB_TOKEN not set, trying `gh auth token`');
  try {
    const result = await runCommand('gh', ['auth', 'token']);
    const token = result.stdout.trim();
    if (result.exitCode === 0 && token.length > 0) {
      logger.debug('Resolved token via gh CLI');
      return { token, source: 'gh-cli' };
    }
  } catch {
    // gh not installed — fall through to the error below
  }

  throw new Error(
    'No GitHub token found.\n' +
      'Set the GITHUB_TOKEN environment variable, or install the GitHub CLI (gh) and run:\n' +
      '  gh auth login',
  );
}
