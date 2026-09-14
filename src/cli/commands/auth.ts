/**
 * auth.ts — The `repo-guardian auth` subcommands.
 *
 * Provides:
 * - repo-guardian auth login [--pat] [--client-id <id>]
 * - repo-guardian auth status
 * - repo-guardian auth logout
 */

import type { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { Octokit } from '@octokit/rest';
import { loginWithDeviceFlow, openBrowser } from '../../github/device-flow.js';
import { loadStoredConfig, saveStoredToken, clearStoredToken } from '../../github/config.js';
import { resolveGitHubToken } from '../../github/auth.js';
import { maskSecret } from '../../utils/mask.js';

interface LoginOptions {
  pat?: boolean;
  clientId?: string;
}

/**
 * Interactive PAT token prompt fallback.
 */
async function loginWithPat(): Promise<void> {
  console.log(chalk.cyan('\nAuthenticate via GitHub Personal Access Token\n'));
  console.log(chalk.dim('Generating a token requires the `repo` scope to scan private repositories.\n'));

  const tokenUrl = 'https://github.com/settings/tokens/new?description=repo-guardian&scopes=repo,read:user';
  console.log(chalk.dim(`Opening token creation page: ${tokenUrl}`));
  await openBrowser(tokenUrl);

  const { token } = await inquirer.prompt<{ token: string }>([
    {
      type: 'password',
      name: 'token',
      message: 'Paste your GitHub Personal Access Token:',
      mask: '*',
      validate: (input: string) => {
        if (!input || input.trim().length === 0) return 'Token cannot be empty';
        return true;
      },
    },
  ]);

  const cleanToken = token.trim();

  // Validate token with GitHub
  console.log(chalk.dim('\nValidating token with GitHub...'));
  try {
    const octokit = new Octokit({ auth: cleanToken });
    const user = await octokit.users.getAuthenticated();
    const login = user.data.login;

    saveStoredToken(cleanToken, login, 'pat');

    console.log(chalk.bold.green(`\n✓ Successfully authenticated as @${login}`));
    console.log(chalk.dim('  Credentials saved to ~/.repo-guardian/config.json\n'));
  } catch (err) {
    console.error(
      chalk.red('\nFailed to authenticate token: ') +
        (err instanceof Error ? err.message : String(err)),
    );
    process.exit(1);
  }
}

async function handleLogin(options: LoginOptions): Promise<void> {
  if (options.pat) {
    await loginWithPat();
    return;
  }

  try {
    // Default to Device Flow
    await loginWithDeviceFlow(options.clientId);
  } catch (err) {
    console.error(chalk.yellow('\nDevice Flow error: ') + (err instanceof Error ? err.message : String(err)));
    console.log(chalk.dim('\nFalling back to token prompt...\n'));
    await loginWithPat();
  }
}

async function handleStatus(): Promise<void> {
  console.log(chalk.cyan('\nRepo Guardian — Authentication Status\n'));

  try {
    const auth = await resolveGitHubToken();
    const octokit = new Octokit({ auth: auth.token });
    const userRes = await octokit.users.getAuthenticated();

    console.log(`  Status:      ${chalk.bold.green('Logged in')}`);
    console.log(`  Account:     ${chalk.bold(userRes.data.login)} (${userRes.data.name || 'No display name'})`);
    console.log(`  Auth Source: ${chalk.cyan(auth.source)}`);
    console.log(`  Token:       ${chalk.dim(maskSecret(auth.token))}\n`);
  } catch (err) {
    console.log(`  Status:      ${chalk.bold.yellow('Not logged in')}`);
    console.log(chalk.dim(`  Details:     ${err instanceof Error ? err.message : String(err)}\n`));
    console.log(chalk.dim('  Run `repo-guardian auth login` to authenticate.\n'));
  }
}

async function handleLogout(): Promise<void> {
  const config = loadStoredConfig();
  if (!config?.githubToken) {
    console.log(chalk.dim('\nNo local credentials currently stored.\n'));
    return;
  }

  clearStoredToken();
  console.log(chalk.green('\n✓ Logged out. Stored credentials removed from ~/.repo-guardian/config.json\n'));
}

export function registerAuthCommand(program: Command): void {
  const auth = program
    .command('auth')
    .description('Manage GitHub authentication (login via browser, token, status, logout)');

  auth
    .command('login')
    .description('Authenticate with GitHub via browser device code or Personal Access Token')
    .option('--pat', 'Use Personal Access Token prompt instead of Device Code flow')
    .option('--client-id <id>', 'Custom GitHub OAuth App Client ID for Device Flow')
    .action(handleLogin);

  auth
    .command('status')
    .description('View current GitHub authentication status and account details')
    .action(handleStatus);

  auth
    .command('logout')
    .description('Log out and remove stored credentials from local disk')
    .action(handleLogout);
}
