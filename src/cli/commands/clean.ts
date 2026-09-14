/**
 * clean.ts — STUB (Phase 3)
 *
 * History rewrite command. Not yet implemented.
 * Will use `git filter-repo` with mandatory two-step human confirmation.
 */

import type { Command } from 'commander';

export function registerCleanCommand(program: Command): void {
  program
    .command('clean <repo>')
    .description('Strip secrets from git history (Phase 3 — not yet implemented)')
    .option('--dry-run', 'Preview changes without executing')
    .option('--confirm', 'Required: explicit confirmation flag')
    .action((_repo: string) => {
      console.error(
        '\n🚧  repo-guardian clean is not yet implemented (coming in Phase 3).\n' +
          '    This command will safely rewrite git history using git filter-repo\n' +
          '    with mandatory backup and two-step human confirmation.\n',
      );
      process.exit(1);
    });
}
