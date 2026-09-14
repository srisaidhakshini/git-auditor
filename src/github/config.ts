/**
 * config.ts — Persistent CLI configuration storage.
 * Stores auth credentials and user preferences at ~/.repo-guardian/config.json.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { logger } from '../utils/logger.js';

const CONFIG_DIR = join(homedir(), '.repo-guardian');
const CONFIG_FILE = join(CONFIG_DIR, 'config.json');

export interface StoredConfig {
  githubToken?: string;
  githubUser?: string;
  authenticatedAt?: string;
  authMethod?: 'device-flow' | 'pat';
}

function ensureConfigDir(): void {
  if (!existsSync(CONFIG_DIR)) {
    mkdirSync(CONFIG_DIR, { recursive: true });
  }
}

/**
 * Loads stored configuration from ~/.repo-guardian/config.json.
 */
export function loadStoredConfig(): StoredConfig | null {
  if (!existsSync(CONFIG_FILE)) {
    return null;
  }

  try {
    const raw = readFileSync(CONFIG_FILE, 'utf8');
    return JSON.parse(raw) as StoredConfig;
  } catch (err) {
    logger.warn('Failed to parse config.json:', { error: String(err) });
    return null;
  }
}

/**
 * Saves auth token and user metadata to ~/.repo-guardian/config.json.
 */
export function saveStoredToken(
  token: string,
  user?: string,
  method: 'device-flow' | 'pat' = 'device-flow',
): void {
  ensureConfigDir();
  const current = loadStoredConfig() ?? {};
  const updated: StoredConfig = {
    ...current,
    githubToken: token,
    githubUser: user,
    authenticatedAt: new Date().toISOString(),
    authMethod: method,
  };
  writeFileSync(CONFIG_FILE, JSON.stringify(updated, null, 2), {
    encoding: 'utf8',
    mode: 0o600, // Read/write by owner only for security
  });
  logger.debug('Saved auth token to local config');
}

/**
 * Clears stored auth credentials.
 */
export function clearStoredToken(): void {
  if (!existsSync(CONFIG_FILE)) return;
  try {
    const current = loadStoredConfig();
    if (current) {
      delete current.githubToken;
      delete current.githubUser;
      delete current.authenticatedAt;
      writeFileSync(CONFIG_FILE, JSON.stringify(current, null, 2), 'utf8');
    }
  } catch {
    rmSync(CONFIG_FILE, { force: true });
  }
}
