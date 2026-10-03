/**
 * fix.ts — `repo-guardian fix`: guided, one-repo-at-a-time remediation.
 *
 * Scans (like `scan`), then walks through every repo with problems. Each step offers a
 * suggested fix as the default choice, so pressing Enter accepts it; the user can always
 * skip or quit. Destructive steps keep their own confirmations (see `clean`).
 *
 *  - Secrets      → `clean` flow (rotation check, dry-run, backup, rewrite, gated force-push)
 *  - Dependencies → `npm audit fix` in a fresh clone, committed to a NEW BRANCH and pushed
 *                   (never touches the default branch or history)
 */

import { rmSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';

import { buildScanReport, cloneRepo } from './scan.js';
import type { ScanOptions } from './scan.js';
import { runClean } from './clean.js';
import { findRepo } from '../../github/repos.js';
import { scanDependencies } from '../../engines/deps/scanner.js';
import { runCommand } from '../../utils/shell.js';
import { trapExit } from '../../utils/exit.js';
import { isInteractive } from '../picker.js';
import { renderCompactReport, groupSecrets, groupFixes, renderSecretGroup, renderDeps } from '../../report/compact.js';
import type { ScanReport, RepoReport } from '../../report/types.js';

type Choice = 'yes' | 'skip' | 'skip-repo' | 'quit';

async function ask(message: string, yesLabel: string, skipLabel: string): Promise<Choice> {
  try {
    const { choice } = await inquirer.prompt<{ choice: Choice }>([
      {
        type: 'select',
        name: 'choice',
        message,
        choices: [
          { name: yesLabel, value: 'yes' },
          { name: skipLabel, value: 'skip' },
          { name: 'Skip this repository', value: 'skip-repo' },
          { name: 'Quit', value: 'quit' },
        ],
      },
    ]);
    return choice;
  } catch (err) {
    if (err instanceof Error && err.name === 'ExitPromptError') return 'quit';
    throw err;
  }
}

async function confirm(message: string, def: boolean): Promise<boolean> {
  try {
    const { ok } = await inquirer.prompt<{ ok: boolean }>([{ type: 'confirm', name: 'ok', message, default: def }]);
    return ok;
  } catch (err) {
    if (err instanceof Error && err.name === 'ExitPromptError') return false;
    throw err;
  }
}

const weight = (r: RepoReport): number =>
  groupSecrets(r.secrets?.findings ?? []).length * 3 +
  (r.deps?.findings ?? []).reduce((n, f) => n + (f.severity === 'critical' ? 5 : f.severity === 'high' ? 2 : 1), 0);

// ─── Dependency fix ───────────────────────────────────────────────────────────

type DepOutcome = 'pushed' | 'committed' | 'nothing' | 'failed';

export interface PreparedFix {
  outcome: 'ready' | 'nothing' | 'failed';
  branch?: string;
  before?: number;
  after?: number;
}

/**
 * Runs `npm audit fix` (lockfile only, no scripts) in `dir` and commits the result to a new
 * branch. Works on any local git checkout; never pushes.
 */
export async function prepareDependencyFix(dir: string, repoFullName: string): Promise<PreparedFix> {
  if (!existsSync(join(dir, 'package.json'))) {
    console.log(chalk.yellow('  No package.json at the repository root — nothing to fix automatically.'));
    return { outcome: 'nothing' };
  }

  // Lockfile-only: no node_modules install, no lifecycle scripts executed.
  if (!existsSync(join(dir, 'package-lock.json'))) {
    console.log(chalk.dim('  No package-lock.json — generating one...'));
    const gen = await runCommand('npm', ['install', '--package-lock-only', '--ignore-scripts'], { cwd: dir, timeoutMs: 300_000 });
    if (gen.exitCode !== 0) {
      console.log(chalk.red('  Could not generate a lockfile:\n') + chalk.dim(gen.stderr.trim().split('\n').slice(-4).join('\n')));
      return { outcome: 'failed' };
    }
  }

  const before = await scanDependencies(dir, repoFullName);
  console.log(chalk.dim('  Running npm audit fix...'));
  const fix = await runCommand('npm', ['audit', 'fix', '--package-lock-only', '--ignore-scripts'], { cwd: dir, timeoutMs: 300_000 });
  if (fix.exitCode !== 0 && !/audit/i.test(fix.stdout + fix.stderr)) {
    console.log(chalk.red('  npm audit fix failed:\n') + chalk.dim(fix.stderr.trim().split('\n').slice(-4).join('\n')));
    return { outcome: 'failed' };
  }

  // Only count changes to dependency files (a freshly generated lockfile counts as a change too).
  const status = await runCommand('git', ['status', '--porcelain', '--', 'package.json', 'package-lock.json'], { cwd: dir });
  const afterScan = await scanDependencies(dir, repoFullName);
  if (status.stdout.trim() === '' || afterScan.findings.length >= before.findings.length) {
    console.log(chalk.yellow('  npm could not fix anything automatically.'));
    const { updates } = groupFixes(before.findings.filter((f) => f.findingType === 'cve'));
    for (const u of updates.slice(0, 5)) {
      console.log(chalk.dim(`    needs a manual upgrade: ${u.label}${u.breaking ? ' (breaking change)' : ''}`));
    }
    return { outcome: 'nothing', before: before.findings.length, after: afterScan.findings.length };
  }

  console.log(
    chalk.green(`  ✓ Fixed ${before.findings.length - afterScan.findings.length} issue(s)`) +
      chalk.dim(` (${before.findings.length} → ${afterScan.findings.length} remaining)`),
  );

  const branch = `repo-guardian/fix-dependencies-${new Date().toISOString().slice(0, 10)}`;
  await runCommand('git', ['checkout', '-b', branch], { cwd: dir });
  await runCommand('git', ['add', '--', 'package.json', 'package-lock.json'], { cwd: dir });
  const hasIdentity = (await runCommand('git', ['config', 'user.email'], { cwd: dir })).stdout.trim() !== '';
  const identity = hasIdentity ? [] : ['-c', 'user.name=Repo Guardian', '-c', 'user.email=repo-guardian@users.noreply.github.com'];
  const commit = await runCommand(
    'git',
    [...identity, 'commit', '-m', 'fix(deps): apply npm audit fix\n\nAutomated by repo-guardian.'],
    { cwd: dir },
  );
  if (commit.exitCode !== 0) {
    console.log(chalk.red('  Could not commit the changes:\n') + chalk.dim(commit.stderr.trim()));
    return { outcome: 'failed' };
  }
  return { outcome: 'ready', branch, before: before.findings.length, after: afterScan.findings.length };
}

/** Clones the repo, prepares the dependency fix, and (after confirmation) pushes the branch. */
export async function fixDependencies(repoFullName: string, token: string): Promise<DepOutcome> {
  const repo = await findRepo({ token, source: 'env' }, repoFullName);
  console.log(chalk.dim('  Cloning a fresh copy...'));
  const dir = await cloneRepo(repo.cloneUrl, token);

  try {
    const prepared = await prepareDependencyFix(dir, repoFullName);
    if (prepared.outcome !== 'ready' || !prepared.branch) return prepared.outcome === 'nothing' ? 'nothing' : 'failed';
    const branch = prepared.branch;

    if (!(await confirm(`  Push branch "${branch}" to GitHub so you can open a pull request?`, true))) {
      console.log(chalk.yellow('  Not pushed. The fix was discarded with the temporary clone.'));
      return 'committed';
    }

    const push = await runCommand('git', ['push', '-u', 'origin', branch], { cwd: dir });
    if (push.exitCode !== 0) {
      const denied = /403|denied|Permission/i.test(push.stderr);
      console.log(chalk.red('  Push failed.') + chalk.dim(` ${push.stderr.trim().split('\n').slice(-2).join(' ')}`));
      if (denied) {
        console.log(
          chalk.yellow(
            '  Your GitHub token cannot write to this repository. Log in again with full access:\n' +
              '    repo-guardian auth login      (or: gh auth login -h github.com -p https -w)\n' +
              '  A fine-grained token needs "Contents: Read and write" on this repo.',
          ),
        );
      }
      return 'failed';
    }
    console.log(chalk.bold.green('  ✓ Pushed. Open a pull request here:'));
    console.log(chalk.cyan(`    ${repo.htmlUrl}/pull/new/${branch}`));
    return 'pushed';
  } finally {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  }
}

// ─── Wizard ───────────────────────────────────────────────────────────────────

export async function runFixWizard(report: ScanReport, token: string): Promise<void> {
  const repos = report.repos.filter((r) => weight(r) > 0).sort((a, b) => weight(b) - weight(a));
  if (repos.length === 0) {
    console.log(chalk.green('\n✅ Nothing to fix.\n'));
    return;
  }

  console.log(chalk.bold.cyan(`\n🛠  Guided fix — ${repos.length} repo(s) need attention. Press Enter to accept the suggested option.\n`));
  const done: string[] = [];
  const skipped: string[] = [];

  outer: for (let i = 0; i < repos.length; i++) {
    const repo = repos[i]!;
    const bar = '─'.repeat(62);
    console.log(chalk.cyan(`\n${bar}\n  [${i + 1}/${repos.length}] ${chalk.bold.white(repo.repoFullName)}\n${bar}`));

    // 1. Secrets
    const groups = groupSecrets(repo.secrets?.findings ?? []).sort((a, b) => Number(b.inCurrentFiles) - Number(a.inCurrentFiles));
    if (groups.length > 0) {
      console.log(`\n  ${chalk.bold.red('🔑 Secrets')}  ${groups.length} found ${chalk.dim('(values masked)')}`);
      for (const g of groups.slice(0, 5)) for (const line of renderSecretGroup(g)) console.log(line);
      if (groups.length > 5) console.log(chalk.dim(`    … and ${groups.length - 5} more`));

      const choice = await ask(
        'Remove these secrets from git history?',
        'Yes — clean history (asks to confirm before rewriting and before pushing)',
        'Skip secrets for this repo',
      );
      if (choice === 'quit') break outer;
      if (choice === 'skip-repo') {
        skipped.push(`${repo.repoFullName} (skipped)`);
        continue;
      }
      if (choice === 'yes') {
        const rotated = await confirm(
          chalk.bold.red('Have you ROTATED these credentials at the provider? (cleaning history does not undo exposure)'),
          false,
        );
        if (!rotated) {
          console.log(chalk.yellow('  Rotate them first, then run: repo-guardian fix --repo ' + repo.repoFullName));
          skipped.push(`${repo.repoFullName} secrets (rotate first)`);
        } else {
          const r = await trapExit(() => runClean(repo.repoFullName, {}));
          if (r.exitCode) {
            console.log(chalk.yellow('  Cleanup did not finish — see the messages above.'));
            skipped.push(`${repo.repoFullName} secrets (not completed)`);
          } else {
            done.push(`${repo.repoFullName}: secrets cleanup run`);
          }
        }
      } else {
        skipped.push(`${repo.repoFullName} secrets`);
      }
    }

    // 2. Dependencies
    const deps = repo.deps?.findings ?? [];
    if (deps.length > 0) {
      console.log('');
      for (const line of renderDeps(repo)) console.log(line);
      console.log('');
      const choice = await ask(
        'Fix dependencies?',
        'Yes — run npm audit fix in a fresh clone, on a new branch (default branch is never touched)',
        'Skip dependencies for this repo',
      );
      if (choice === 'quit') break outer;
      if (choice === 'skip-repo') {
        skipped.push(`${repo.repoFullName} (skipped)`);
        continue;
      }
      if (choice === 'yes') {
        try {
          const outcome = await fixDependencies(repo.repoFullName, token);
          if (outcome === 'pushed') done.push(`${repo.repoFullName}: dependency fix pushed to a branch`);
          else skipped.push(`${repo.repoFullName} dependencies (${outcome})`);
        } catch (err) {
          console.log(chalk.red(`  Failed: ${err instanceof Error ? err.message : String(err)}`));
          skipped.push(`${repo.repoFullName} dependencies (failed)`);
        }
      } else {
        skipped.push(`${repo.repoFullName} dependencies`);
      }
    }
  }

  console.log(chalk.bold.cyan('\n' + '─'.repeat(62)));
  console.log(chalk.bold('  Fix session summary'));
  for (const d of done) console.log(chalk.green(`   ✓ ${d}`));
  for (const s of skipped) console.log(chalk.dim(`   – ${s}`));
  if (done.length === 0 && skipped.length === 0) console.log(chalk.dim('   (no actions taken)'));
  console.log(chalk.dim('\n  Re-run `repo-guardian scan --all` to see what is left.\n'));
}

// ─── Command ──────────────────────────────────────────────────────────────────

export async function runFix(options: ScanOptions): Promise<void> {
  if (!isInteractive()) {
    console.error(chalk.red('Error: `fix` is interactive and needs a terminal. Use `scan` and `clean` in scripts.'));
    process.exit(1);
  }
  const { report, token } = await buildScanReport(options);
  process.stdout.write(renderCompactReport(report) + '\n');
  await runFixWizard(report, token);
  process.exit(0);
}

export function registerFixCommand(program: Command): void {
  program
    .command('fix')
    .description('Guided fix: scan, then walk through each repo and fix secrets and dependencies step by step')
    .option('--repo <name>', 'Work on one repository (owner/name or bare name)')
    .option('--all', 'Work through all owned repositories')
    .option('--secrets-only', 'Only handle secrets')
    .option('--deps-only', 'Only handle dependencies')
    .option('--refresh', 'Force-refresh the cached repository list')
    .action(runFix);
}
