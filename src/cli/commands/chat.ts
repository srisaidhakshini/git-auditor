/**
 * chat.ts — STUB (Phase 6)
 *
 * Conversational agent mode. Not yet implemented.
 * Will use the Anthropic SDK with tool-use to orchestrate all engines
 * in a multi-turn conversation, pausing at every destructive boundary.
 */

import type { Command } from 'commander';

export function registerChatCommand(program: Command): void {
  program
    .command('chat')
    .description('Conversational agent mode via Anthropic SDK (Phase 6 — not yet implemented)')
    .action(() => {
      console.error(
        '\n🚧  repo-guardian chat is not yet implemented (coming in Phase 6).\n' +
          '    This will open a Claude Code-like conversational interface\n' +
          '    where the agent plans and calls tools on your behalf,\n' +
          '    pausing for confirmation before any destructive action.\n',
      );
      process.exit(1);
    });
}
