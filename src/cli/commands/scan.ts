/**
 * scan.ts — The `repo-guardian scan` command.
 *
 * Orchestrates: repo discovery → clone → scan_secrets → report.
 * Phase 1: secrets-only. Dependency scanning added in Phase 2.
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Command } from 'commander';
import chalk from 'chalk';

import { resolveGitHubToken } from '../../github/auth.js';
import { listOwnedRepos, findRepo } from '../../github/repos.js';
import { loadCachedRepos, saveReposToCache } from '../../github/cache.js';
import { scanSecrets } from '../../engines/secrets/scanner.js';
import { renderTerminalReport, renderJsonReport } from '../../report/formatter.js';
import { runCommand } from '../../utils/shell.js';
import { logger } from '../../utils/logger.js';
import type { ScanReport, RepoReport } from '../../report/types.js';
import type { GitHubRepo } from '../../github/repos.js';

// ─── Options ──────────────────────────────────────────────────────────────────

interface ScanOptions {
  repo?: string;
  all?: boolean;
  secretsOnly?: boolean;
  depsOnly?: boolean;
  json?: boolean;
  refresh?: boolean;
  timeoutSeconds?: string;
}

// ─── Clone helpers ────────────────────────────────────────────────────────────

/**
 * Clones a repo into a temp directory.
 * Returns the cloned path, or throws on failure.
 */
async function cloneRepo(cloneUrl: string, token: string): Promise<string> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'repo-guardian-clone-'));

  // Inject token into the HTTPS URL for private repo access
  const authedUrl = cloneUrl.replace('https://', `https://x-access-token:${token}@`);

  logger.debug(`Cloning ${cloneUrl} → ${tmpDir}`);

  const result = await runCommand('git', [
    'clone',
    '--depth=0', // full history for secret scanning
    '--no-single-branch',
    authedUrl,
    tmpDir,
  ]);

  if (result.exitCode !== 0) {
    rmSync(tmpDir, { recursive: true, force: true });
    throw new Error(`git clone failed for ${cloneUrl}:\n${result.stderr}`);
  }

  return tmpDir;
}

// ─── Command action ───────────────────────────────────────────────────────────

async function runScan(options: ScanOptions): Promise<void> {
  // Validate mutually exclusive options
  if (options.secretsOnly && options.depsOnly) {
    console.error(chalk.red('Error: --secrets-only and --deps-only cannot be used together.'));
    process.exit(1);
  }

  if (!options.repo && !options.all) {
    console.error(
      chalk.red('Error: specify a target with --repo <name> or --all.\n') +
        chalk.dim('Example: repo-guardian scan --repo myrepo --secrets-only'),
    );
    process.exit(1);
  }

  // 1. Authenticate
  const authResult = await resolveGitHubToken().catch((err: unknown) => {
    console.error(chalk.red('\n' + (err instanceof Error ? err.message : String(err))));
    process.exit(1);
  });
  const token = authResult.token;
  console.log(chalk.dim(`✓ Authenticated via ${authResult.source}`));

  // 2. Discover repos
  let repos: GitHubRepo[];

  if (options.repo) {
    // Single repo mode
    const found = await findRepo({ token, source: 'env' }, options.repo).catch((err: unknown) => {
      console.error(
        chalk.red(`\nCould not find repository "${options.repo}":\n`) +
          (err instanceof Error ? err.message : String(err)),
      );
      process.exit(1);
    });
    repos = [found];
  } else {
    // --all mode: use cache or fetch from GitHub
    const cached = loadCachedRepos(options.refresh ?? false);
    if (cached) {
      repos = cached;
    } else {
      repos = await listOwnedRepos({ token, source: 'env' });
      saveReposToCache(repos);
    }
  }

  console.log(chalk.cyan(`\n🔍 Scanning ${repos.length} repo(s)...\n`));

  const timeoutMs = options.timeoutSeconds ? parseInt(options.timeoutSeconds, 10) * 1000 : 0;
  const repoReports: RepoReport[] = [];
  let totalFindings = 0;
  const clonedDirs: string[] = [];

  try {
    for (const repo of repos) {
      console.log(chalk.bold(`  → ${repo.fullName}`));

      let clonedPath: string;
      try {
        clonedPath = await cloneRepo(repo.cloneUrl, token);
        clonedDirs.push(clonedPath);
      } catch (err) {
        console.error(
          chalk.yellow(`  ⚠ Skipping ${repo.fullName}: clone failed — `) +
            chalk.dim(err instanceof Error ? err.message : String(err)),
        );
        repoReports.push({
          repoFullName: repo.fullName,
          htmlUrl: repo.htmlUrl,
        });
        continue;
      }

      const repoReport: RepoReport = {
        repoFullName: repo.fullName,
        htmlUrl: repo.htmlUrl,
      };

      // Secret scan (skipped if --deps-only)
      if (!options.depsOnly) {
        const secretResult = await scanSecrets(
          clonedPath,
          repo.fullName,
          'full-history',
          timeoutMs,
        );
        repoReport.secrets = secretResult;
        totalFindings += secretResult.findings.length;
      }

      // Phase 2: dep scan would go here

      repoReports.push(repoReport);
    }
  } finally {
    // Always clean up clones, even on error
    for (const dir of clonedDirs) {
      try {
        rmSync(dir, { recursive: true, force: true });
      } catch {
        // best-effort
      }
    }
  }

  // 3. Build and render the report
  const report: ScanReport = {
    generatedAt: new Date().toISOString(),
    totalRepos: repos.length,
    totalFindings,
    repos: repoReports,
  };

  if (options.json) {
    process.stdout.write(renderJsonReport(report) + '\n');
  } else {
    process.stdout.write(renderTerminalReport(report) + '\n');
  }

  // Exit 1 if findings (useful for CI)
  process.exit(totalFindings > 0 ? 1 : 0);
}

// ─── Command registration ─────────────────────────────────────────────────────

export function registerScanCommand(program: Command): void {
  program
    .command('scan')
    .description('Scan repositories for leaked secrets and malicious dependencies')
    .option('--repo <name>', 'Scan a specific repository (owner/name or bare name)')
    .option('--all', 'Scan all owned repositories')
    .option('--secrets-only', 'Run only the secrets engine (skip dependency scan)')
    .option('--deps-only', 'Run only the dependency engine (Phase 2) — skip secrets')
    .option('--json', 'Output results as JSON (for CI pipelines)')
    .option('--refresh', 'Force-refresh the cached repository list')
    .option('--timeout-seconds <n>', 'Per-repo scan timeout in seconds (0 = unlimited)')
    .action(runScan);
}
