/**
 * init-prevention.ts — The `repo-guardian init-prevention` command.
 *
 * Sets up .gitignore safeguards and pre-commit hooks.
 */

import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Command } from 'commander';
import chalk from 'chalk';

import { patchGitignore } from '../../engines/prevention/gitignore.js';
import { installPreCommitHook } from '../../engines/prevention/hooks.js';
import { recordAuditEvent } from '../../utils/audit.js';

export interface InitPreventionOptions {
  repo?: string;
  path?: string;
}

export async function runInitPrevention(options: InitPreventionOptions): Promise<void> {
  const targetDir = options.path ? resolve(options.path) : process.cwd();

  console.log(chalk.bold.cyan('\n🛡️  Initializing Repo Guardian Prevention Guardrails...'));
  console.log(chalk.dim(`   Target directory: ${targetDir}\n`));

  if (!existsSync(targetDir)) {
    console.error(chalk.red(`Error: Directory does not exist: ${targetDir}`));
    process.exit(1);
  }

  if (!existsSync(resolve(targetDir, '.git'))) {
    console.error(
      chalk.red(`Error: ${targetDir} is not the root of a git repository (no .git folder).
`) +
        chalk.dim('Run this from a repo root, or pass --path <repo>. Nothing was changed.'),
    );
    process.exit(1);
  }

  // 1. Patch .gitignore
  console.log(chalk.cyan('📄 Checking and updating .gitignore...'));
  const gitignoreResult = patchGitignore(targetDir);

  if (gitignoreResult.modified) {
    console.log(chalk.green(`✓ Updated .gitignore with ${gitignoreResult.addedPatterns.length} protective patterns:`));
    for (const p of gitignoreResult.addedPatterns) {
      console.log(chalk.dim(`    + ${p}`));
    }
  } else {
    console.log(chalk.dim('✓ .gitignore already covers all recommended security patterns.'));
  }

  // 2. Install pre-commit hook
  console.log(chalk.cyan('\n🪝 Installing git pre-commit hook...'));
  if (existsSync(resolve(targetDir, '.git'))) {
    const hookResult = installPreCommitHook(targetDir);
    console.log(chalk.green(`✓ Pre-commit hook installed at ${hookResult.hookPath}`));
  } else {
    console.log(chalk.yellow('⚠ Not a git repository root (no .git directory found). Skipped hook installation.'));
  }

  // 3. Log audit event
  recordAuditEvent(
    'PREVENTION_INITIALIZED',
    options.repo || targetDir,
    {
      targetDir,
      addedIgnorePatterns: gitignoreResult.addedPatterns,
    },
    true,
  );

  console.log(chalk.bold.green('\n🎉 Prevention layer successfully initialized! Future secret commits will be blocked.\n'));
}

export function registerInitPreventionCommand(program: Command): void {
  program
    .command('init-prevention')
    .description('Set up .gitignore and pre-commit hooks to block secrets')
    .option('--repo <name>', 'Target a specific repository name (for audit logging)')
    .option('--path <path>', 'Target directory path (defaults to current working directory)')
    .action(runInitPrevention);
}
