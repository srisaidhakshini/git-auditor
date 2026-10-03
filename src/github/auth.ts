/**
 * auth.ts — GitHub authentication resolution.
 *
 * Precedence:
 * 1. GITHUB_TOKEN environment variable (CI / manual overrides)
 * 2. Stored config at ~/.repo-guardian/config.json (set via `repo-guardian auth login`)
 * 3. `gh auth token` (if GitHub CLI is installed and logged in)
 */

import { runCommand } from '../utils/shell.js';
import { loadStoredConfig } from './config.js';
import { logger } from '../utils/logger.js';

export interface GitHubAuth {
  token: string;
  source: 'env' | 'config' | 'gh-cli';
  user?: string;
}

export async function resolveGitHubToken(): Promise<GitHubAuth> {
  // 1. GITHUB_TOKEN env var (ignoring literal documentation placeholders)
  const envToken = process.env['GITHUB_TOKEN'];
  if (
    envToken &&
    envToken.trim().length > 0 &&
    !/your(Personal)?(Access)?Token/i.test(envToken)
  ) {
    logger.debug('Using GITHUB_TOKEN from environment');
    return { token: envToken.trim(), source: 'env' };
  }

  // 2. Stored credentials from ~/.repo-guardian/config.json
  const stored = loadStoredConfig();
  if (stored?.githubToken && stored.githubToken.trim().length > 0) {
    logger.debug('Using GitHub token from local config file');
    return {
      token: stored.githubToken.trim(),
      source: 'config',
      user: stored.githubUser,
    };
  }

  // 3. gh CLI fallback
  logger.debug('No env or config token found, trying `gh auth token`');
  try {
    const result = await runCommand('gh', ['auth', 'token']);
    const token = result.stdout.trim();
    if (result.exitCode === 0 && token.length > 0) {
      logger.debug('Resolved token via gh CLI');
      return { token, source: 'gh-cli' };
    }
  } catch {
    // gh not installed
  }

  throw new Error(
    'No GitHub authentication found.\n\n' +
      'To log in directly from your terminal, run:\n' +
      '  repo-guardian auth login\n\n' +
      'Or set the GITHUB_TOKEN environment variable:\n' +
      '  $env:GITHUB_TOKEN = "ghp_yourToken"',
  );
}
