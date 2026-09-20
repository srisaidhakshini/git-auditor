/**
 * clean.ts — The `repo-guardian clean` command.
 *
 * Implements Phase 3 & Phase 4:
 * - Fresh clone
 * - Dry-run inspection
 * - Verified backup creation
 * - Human-in-the-loop confirmation #1 (Rewrite)
 * - History rewrite execution
 * - Human-in-the-loop confirmation #2 (Force push with branch protection check)
 * - Mandatory credential rotation reminder
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import type { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';

import { resolveGitHubToken } from '../../github/auth.js';
import { findRepo } from '../../github/repos.js';
import { cloneRepo } from './scan.js';
import {
  createVerifiedBackup,
  dryRunRewrite,
  executeRewrite,
} from '../../engines/secrets/rewriter.js';
import { pushRewrittenHistory } from '../../engines/secrets/pusher.js';
import { logger } from '../../utils/logger.js';

export interface CleanOptions {
  dryRun?: boolean;
  confirm?: boolean;
  patterns?: string;
  backupDir?: string;
  branch?: string;
  forcePush?: boolean;
}

const DEFAULT_PATTERNS = ['.env', '.env.*', '*.pem', '*.key', 'id_rsa'];

export async function runClean(repoName: string, options: CleanOptions): Promise<void> {
  const targetPatterns = options.patterns
    ? options.patterns.split(',').map((p) => p.trim())
    : DEFAULT_PATTERNS;

  console.log(chalk.bold.cyan(`\n🧹 Preparing history cleanup for repository: ${repoName}`));
  console.log(chalk.dim(`   Target patterns to excise: ${targetPatterns.join(', ')}\n`));

  // 1. Authenticate & find repo
  const auth = await resolveGitHubToken().catch((err: unknown) => {
    console.error(chalk.red('\n' + (err instanceof Error ? err.message : String(err))));
    process.exit(1);
  });

  const repo = await findRepo(auth, repoName).catch((err: unknown) => {
    console.error(chalk.red(`\nCould not find repository "${repoName}":\n` + (err instanceof Error ? err.message : String(err))));
    process.exit(1);
  });

  const targetBranch = options.branch || repo.defaultBranch || 'main';

  // 2. Clone fresh copy into temporary workspace
  const clonedDir = await cloneRepo(repo.cloneUrl, auth.token).catch((err: unknown) => {
    console.error(chalk.red(`\nFailed to clone repo:\n` + (err instanceof Error ? err.message : String(err))));
    process.exit(1);
  });

  try {
    // 3. Dry-run analysis
    console.log(chalk.cyan('🔍 Running dry-run history analysis...'));
    const dryRun = await dryRunRewrite(clonedDir, targetPatterns);

    if (dryRun.totalCommitsToRewrite === 0) {
      console.log(chalk.green('\n✅ No commits in git history match target sensitive patterns. Repository is clean!'));
      return;
    }

    console.log(chalk.yellow(`\n⚠️  Found ${dryRun.totalCommitsToRewrite} commit(s) containing targeted files:`));
    for (const c of dryRun.affectedCommits) {
      console.log(
        chalk.red(`  • Commit ${c.commitSha.slice(0, 10)}`) +
          chalk.dim(` by ${c.author} on ${c.date.slice(0, 10)}:`) +
          ` "${c.message}"` +
          `\n    Files: ${chalk.yellow(c.matchedFiles.join(', '))}`,
      );
    }

    if (options.dryRun) {
      console.log(chalk.cyan('\nℹ️  Dry-run complete. No changes were made to repository history.'));
      return;
    }

    // 4. Confirmation Step 1: History Rewrite
    if (!options.confirm) {
      const { proceedRewrite } = await inquirer.prompt<{ proceedRewrite: boolean }>([
        {
          type: 'confirm',
          name: 'proceedRewrite',
          message: chalk.bold.red(
            `Proceed with rewriting local git history to purge ${dryRun.totalCommitsToRewrite} commits? (A verified backup bundle will be created first)`,
          ),
          default: false,
        },
      ]);

      if (!proceedRewrite) {
        console.log(chalk.yellow('\nOperation cancelled by user. History was not modified.'));
        return;
      }
    }

    // 5. Create verified backup
    console.log(chalk.cyan('\n📦 Creating verified repository backup bundle...'));
    const backup = await createVerifiedBackup(clonedDir, options.backupDir);
    console.log(chalk.green(`✓ Backup verified and saved to: ${backup.backupPath}`));

    // 6. Execute History Rewrite
    console.log(chalk.cyan('\n⚡ Executing history rewrite...'));
    const rewriteResult = await executeRewrite(clonedDir, targetPatterns, repo.fullName, backup.backupPath);

    if (!rewriteResult.success) {
      console.error(chalk.red(`\n❌ History rewrite failed:\n${rewriteResult.error}`));
      process.exit(1);
    }

    console.log(chalk.bold.green(`\n✓ Git history rewritten successfully in ${rewriteResult.durationMs}ms.`));
    console.log(chalk.dim(`  HEAD SHA: ${rewriteResult.headShaBefore.slice(0, 10)} → ${rewriteResult.headShaAfter.slice(0, 10)}`));

    // Mandatory rotation reminder per PRD §5
    console.log(
      chalk.bold.red(
        '\n⚠️  MANDATORY REMINDER: History rewrite does NOT undo exposure.\n' +
          '   Any secret that was previously committed must be rotated in provider consoles immediately!\n',
      ),
    );

    // 7. Confirmation Step 2: Push to GitHub (Phase 4)
    let shouldPush = options.forcePush ?? false;

    if (!shouldPush) {
      const { confirmPush } = await inquirer.prompt<{ confirmPush: boolean }>([
        {
          type: 'confirm',
          name: 'confirmPush',
          message: chalk.bold.red(
            `Do you want to FORCE-PUSH these rewritten commits to branch "${targetBranch}" on GitHub? (WARNING: This overwrites remote history and invalidates existing forks/PRs)`,
          ),
          default: false,
        },
      ]);
      shouldPush = confirmPush;
    }

    if (!shouldPush) {
      console.log(
        chalk.yellow(
          `\nℹ️  Rewritten clone preserved at: ${clonedDir}\n` +
            `   When ready, you can manually push using:\n` +
            `   cd ${clonedDir} && git push --force origin ${targetBranch}\n`,
        ),
      );
      // Avoid auto-deleting clonedDir so user can inspect or push
      return;
    }

    console.log(chalk.cyan(`\n🚀 Checking branch protection and pushing to ${repo.fullName}:${targetBranch}...`));
    const pushResult = await pushRewrittenHistory(clonedDir, repo.fullName, targetBranch, auth, true);

    if (!pushResult.success) {
      console.error(chalk.red(`\n❌ Push aborted: ${pushResult.error}`));
      if (pushResult.blockedByProtection) {
        console.error(chalk.yellow('   Branch protection is active. Please temporarily allow force pushes in GitHub repo settings or use a new branch.'));
      }
      process.exit(1);
    }

    console.log(chalk.bold.green(`\n🎉 Force push completed successfully! Remote repository history on "${targetBranch}" has been cleansed.\n`));
  } finally {
    // Only clean up cloned directory if rewrite wasn't left unpushed
    try {
      if (!options.dryRun && !options.confirm) {
        // keep if user wants to inspect
      } else {
        rmSync(clonedDir, { recursive: true, force: true });
      }
    } catch {
      // ignore cleanup errors
    }
  }
}

export function registerCleanCommand(program: Command): void {
  program
    .command('clean <repo>')
    .description('Safely strip secrets from git history with dry-run and backup')
    .option('--dry-run', 'Preview which commits and files will be removed without modifying history')
    .option('--confirm', 'Confirm history rewrite without interactive prompt')
    .option('--patterns <patterns>', 'Comma-separated file patterns to strip (e.g. .env,*.pem,secrets.json)')
    .option('--branch <name>', 'Target branch to rewrite/push (defaults to default branch)')
    .option('--backup-dir <dir>', 'Directory to store backup bundle')
    .option('--force-push', 'Confirm force push to remote GitHub branch')
    .action(runClean);
}
