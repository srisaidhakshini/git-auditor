/**
 * cache.ts — Local repo list cache.
 * Stores the repo list in a JSON file to avoid repeated API calls.
 * Invalidated by --refresh flag or if cache is older than CACHE_TTL_MS.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { GitHubRepo } from './repos.js';
import { logger } from '../utils/logger.js';

const CACHE_DIR = join(homedir(), '.repo-guardian');
const CACHE_FILE = join(CACHE_DIR, 'repo-cache.json');
const CACHE_TTL_MS = 1000 * 60 * 60 * 24; // 24 hours

interface CacheFile {
  cachedAt: string;
  repos: GitHubRepo[];
}

function ensureCacheDir(): void {
  if (!existsSync(CACHE_DIR)) {
    mkdirSync(CACHE_DIR, { recursive: true });
  }
}

/**
 * Returns cached repo list if it exists and is not stale.
 * Returns null if cache is missing, expired, or force-refreshed.
 */
export function loadCachedRepos(forceRefresh: boolean): GitHubRepo[] | null {
  if (forceRefresh) {
    logger.debug('--refresh flag set, bypassing cache');
    return null;
  }

  if (!existsSync(CACHE_FILE)) {
    logger.debug('No repo cache found');
    return null;
  }

  const stat = statSync(CACHE_FILE);
  const ageMs = Date.now() - stat.mtimeMs;
  if (ageMs > CACHE_TTL_MS) {
    logger.debug(`Repo cache is stale (${Math.round(ageMs / 60000)} min old), refreshing`);
    return null;
  }

  try {
    const raw = readFileSync(CACHE_FILE, 'utf8');
    const data = JSON.parse(raw) as CacheFile;
    logger.info(`Using cached repo list from ${data.cachedAt} (${data.repos.length} repos)`);
    return data.repos;
  } catch {
    logger.warn('Failed to parse repo cache, refreshing');
    return null;
  }
}

/**
 * Writes the repo list to the local cache file.
 */
export function saveReposToCache(repos: GitHubRepo[]): void {
  ensureCacheDir();
  const data: CacheFile = {
    cachedAt: new Date().toISOString(),
    repos,
  };
  writeFileSync(CACHE_FILE, JSON.stringify(data, null, 2), 'utf8');
  logger.debug(`Cached ${repos.length} repos to ${CACHE_FILE}`);
}
