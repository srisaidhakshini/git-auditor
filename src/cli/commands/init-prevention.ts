/**
 * init-prevention.ts — STUB (Phase 5)
 *
 * Prevention layer command. Not yet implemented.
 * Will set up .gitignore and husky pre-commit hooks via gitleaks protect.
 */

import type { Command } from 'commander';

export function registerInitPreventionCommand(program: Command): void {
  program
    .command('init-prevention')
    .description('Set up .gitignore and pre-commit hooks (Phase 5 — not yet implemented)')
    .option('--repo <name>', 'Target a specific repository')
    .action(() => {
      console.error(
        '\n🚧  repo-guardian init-prevention is not yet implemented (coming in Phase 5).\n' +
          '    This command will generate a .gitignore and install\n' +
          '    husky + gitleaks protect pre-commit hooks.\n',
      );
      process.exit(1);
    });
}
