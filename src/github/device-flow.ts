/**
 * device-flow.ts — GitHub OAuth Device Authorization Flow.
 *
 * Implements RFC 8628 Device Authorization Grant:
 * 1. Requests a device verification code from GitHub.
 * 2. Displays the user code in the terminal and opens the browser.
 * 3. Polls GitHub until the user authorizes the request.
 * 4. Stores the access token in ~/.repo-guardian/config.json.
 */

import { Octokit } from '@octokit/rest';
import chalk from 'chalk';
import { runCommand } from '../utils/shell.js';
import { saveStoredToken } from './config.js';
import { logger } from '../utils/logger.js';

// Default public OAuth App Client ID for Repo Guardian (can be overridden via flag/env)
export const DEFAULT_CLIENT_ID = process.env['GITHUB_CLIENT_ID'] || 'Ov23liP6w7K6Uq9e7r1X';

interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

interface AccessTokenResponse {
  access_token?: string;
  token_type?: string;
  scope?: string;
  error?: string;
  error_description?: string;
}

/**
 * Opens a URL in the user's default web browser across OS platforms.
 */
export async function openBrowser(url: string): Promise<boolean> {
  try {
    if (process.platform === 'win32') {
      await runCommand('cmd', ['/c', 'start', '', url]);
    } else if (process.platform === 'darwin') {
      await runCommand('open', [url]);
    } else {
      await runCommand('xdg-open', [url]);
    }
    return true;
  } catch (err) {
    logger.debug('Failed to auto-open browser:', { error: String(err) });
    return false;
  }
}

/**
 * Initiates the GitHub Device Flow.
 */
export async function loginWithDeviceFlow(clientId: string = DEFAULT_CLIENT_ID): Promise<{
  token: string;
  user: string;
}> {
  console.log(chalk.cyan('\nInitiating GitHub Device Authorization Flow...\n'));

  // 1. Request device code from GitHub
  const codeResponse = await fetch('https://github.com/login/device/code', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client_id: clientId,
      scope: 'repo,read:user',
    }),
  });

  if (!codeResponse.ok) {
    const errorText = await codeResponse.text();
    throw new Error(
      `Failed to request device authorization code from GitHub (${codeResponse.status}):\n${errorText}\n` +
        `Tip: You can also login with a Personal Access Token via 'repo-guardian auth login --pat'`,
    );
  }

  const data = (await codeResponse.json()) as DeviceCodeResponse;
  const { device_code, user_code, verification_uri, expires_in, interval = 5 } = data;

  // 2. Display code to user
  console.log(chalk.bold('! First copy your one-time code: ') + chalk.bold.green.bgBlack(` ${user_code} `));
  console.log(chalk.dim(`  Verification URL: ${verification_uri}`));
  console.log(chalk.dim('  Opening your browser to authorize...\n'));

  await openBrowser(verification_uri);

  // 3. Poll GitHub for authorization
  let pollInterval = interval;
  const deadline = Date.now() + expires_in * 1000;

  process.stdout.write(chalk.yellow('Waiting for GitHub authorization in your browser'));

  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, pollInterval * 1000));
    process.stdout.write(chalk.yellow('.'));

    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: clientId,
        device_code,
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
      }),
    });

    if (!tokenResponse.ok) {
      continue;
    }

    const tokenData = (await tokenResponse.json()) as AccessTokenResponse;

    if (tokenData.access_token) {
      process.stdout.write('\n\n');
      const token = tokenData.access_token;

      // Fetch user profile
      const octokit = new Octokit({ auth: token });
      const userRes = await octokit.users.getAuthenticated();
      const login = userRes.data.login;

      // Save to local config
      saveStoredToken(token, login, 'device-flow');

      console.log(chalk.bold.green(`✓ Successfully authenticated as @${login}`));
      console.log(chalk.dim('  Credentials saved to ~/.repo-guardian/config.json\n'));

      return { token, user: login };
    }

    if (tokenData.error) {
      if (tokenData.error === 'authorization_pending') {
        continue;
      }
      if (tokenData.error === 'slow_down') {
        pollInterval += 5;
        continue;
      }
      if (tokenData.error === 'expired_token') {
        process.stdout.write('\n');
        throw new Error('Device code expired. Please run `repo-guardian auth login` again.');
      }
      if (tokenData.error === 'access_denied') {
        process.stdout.write('\n');
        throw new Error('Authorization was cancelled by the user.');
      }

      process.stdout.write('\n');
      throw new Error(`Authentication error: ${tokenData.error_description || tokenData.error}`);
    }
  }

  process.stdout.write('\n');
  throw new Error('Timed out waiting for GitHub authorization.');
}
