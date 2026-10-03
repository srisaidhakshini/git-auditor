/**
 * scan.ts — The `repo-guardian scan` command.
 *
 * Orchestrates: repo discovery → clone → scan_secrets + scan_dependencies → report.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Command } from 'commander';
import chalk from 'chalk';

import { resolveGitHubToken } from '../../github/auth.js';
import { listOwnedRepos, findRepo } from '../../github/repos.js';
import { loadCachedRepos, saveReposToCache } from '../../github/cache.js';
import { scanSecrets } from '../../engines/secrets/scanner.js';
import { scanDependencies } from '../../engines/deps/scanner.js';
import {
  renderTerminalReport,
  renderJsonReport,
  renderHtmlReport,
} from '../../report/formatter.js';
import { runCommand } from '../../utils/shell.js';
import { isInteractive, pickScanTarget } from '../picker.js';
import { logger } from '../../utils/logger.js';
import type { ScanReport, RepoReport } from '../../report/types.js';
import type { GitHubRepo } from '../../github/repos.js';

// ─── Options ──────────────────────────────────────────────────────────────────

export interface ScanOptions {
  repo?: string;
  all?: boolean;
  secretsOnly?: boolean;
  depsOnly?: boolean;
  json?: boolean;
  report?: 'terminal' | 'json' | 'html';
  output?: string;
  refresh?: boolean;
  timeoutSeconds?: string;
}

// ─── Clone helpers ────────────────────────────────────────────────────────────

/**
 * Clones a repo into a temp directory.
 * Returns the cloned path, or throws on failure.
 */
export async function cloneRepo(cloneUrl: string, token: string): Promise<string> {
  const tmpDir = mkdtempSync(join(tmpdir(), 'repo-guardian-clone-'));

  // Inject token into the HTTPS URL for private repo access
  const authedUrl = cloneUrl.replace('https://', `https://x-access-token:${token}@`);

  logger.debug(`Cloning ${cloneUrl} → ${tmpDir}`);

  const result = await runCommand('git', [
    'clone',
    // full clone (no --depth) so secret scanning sees all history
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

export async function runScan(options: ScanOptions): Promise<void> {
  // Validate mutually exclusive options
  if (options.secretsOnly && options.depsOnly) {
    console.error(chalk.red('Error: --secrets-only and --deps-only cannot be used together.'));
    process.exit(1);
  }

  if (!options.repo && !options.all) {
    if (isInteractive()) {
      Object.assign(options, await pickScanTarget());
    } else {
      console.error(
        chalk.red('Error: specify a target with --repo <name> or --all.\n') +
          chalk.dim('Example: repo-guardian scan --repo myrepo --secrets-only'),
      );
      process.exit(1);
    }
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
      repos = await listOwnedRepos({ token, source: 'env' }).catch((err: unknown) => {
        console.error(
          chalk.red('\nFailed to fetch repositories from GitHub:\n') +
            (err instanceof Error ? err.message : String(err)),
        );
        process.exit(1);
      });
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

      // 1. Secret scan (skipped if --deps-only)
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

      // 2. Dependency scan (skipped if --secrets-only)
      if (!options.secretsOnly) {
        const depResult = await scanDependencies(clonedPath, repo.fullName, timeoutMs);
        repoReport.deps = depResult;
        totalFindings += depResult.findings.length;
      }

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

  const reportFormat = options.json ? 'json' : options.report || 'terminal';
  let formattedOutput = '';

  if (reportFormat === 'json') {
    formattedOutput = renderJsonReport(report);
  } else if (reportFormat === 'html') {
    formattedOutput = renderHtmlReport(report);
  } else {
    formattedOutput = renderTerminalReport(report);
  }

  if (options.output) {
    writeFileSync(options.output, formattedOutput, 'utf8');
    console.log(chalk.green(`\n✓ Report saved to ${options.output}`));
  } else {
    process.stdout.write(formattedOutput + '\n');
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
    .option('--deps-only', 'Run only the dependency engine — skip secrets')
    .option('--json', 'Output results as JSON (shorthand for --report json)')
    .option('--report <format>', 'Report format: terminal, json, or html', 'terminal')
    .option('--output <file>', 'Write report to a file instead of stdout')
    .option('--refresh', 'Force-refresh the cached repository list')
    .option('--timeout-seconds <n>', 'Per-repo scan timeout in seconds (0 = unlimited)')
    .action(runScan);
}
