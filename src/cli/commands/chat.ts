/**
 * chat.ts — The `repo-guardian chat` interactive agent command.
 *
 * Implements Phase 6 conversational agent mode.
 */

import type { Command } from 'commander';
import chalk from 'chalk';
import inquirer from 'inquirer';
import { realExit } from '../../utils/exit.js';
import { AgentOrchestrator } from '../../agent/orchestrator.js';

export async function runChat(): Promise<void> {
  console.log(chalk.bold.cyan('\n╔══════════════════════════════════════════════════════════╗'));
  console.log(chalk.bold.cyan('║            REPO GUARDIAN — AGENTIC CHAT MODE            ║'));
  console.log(chalk.bold.cyan('╚══════════════════════════════════════════════════════════╝'));
  console.log(
    chalk.dim(
      '  Conversational security assistant. Plans and executes tools on your behalf.\n' +
        '  Safety guardrails will always pause for confirmation before destructive actions.\n' +
        '  Type "exit" or "quit" to exit.\n',
    ),
  );

  // If stdin closes mid-prompt (piped input / EOF) the prompt never settles; make that a clean exit.
  let busy = false;
  let stdinClosed = false;
  const onStdinClosed = (): void => {
    stdinClosed = true;
    if (!busy) realExit(0);
  };
  process.stdin.once('end', onStdinClosed);
  process.stdin.once('close', onStdinClosed);

  const orchestrator = new AgentOrchestrator();

  while (true) {
    let userInput: string;
    try {
      ({ userInput } = await inquirer.prompt<{ userInput: string }>([
        {
          type: 'input',
          name: 'userInput',
          message: chalk.bold.green('guardian>'),
        },
      ]));
    } catch (err) {
      // Ctrl-C / EOF closes the prompt — exit cleanly
      if (err instanceof Error && err.name === 'ExitPromptError') {
        console.log(chalk.cyan('\nGoodbye! 👋\n'));
        break;
      }
      throw err;
    }

    const trimmed = userInput.trim();
    if (!trimmed) continue;

    if (['exit', 'quit', ':q'].includes(trimmed.toLowerCase())) {
      console.log(chalk.cyan('\nGoodbye! 👋\n'));
      break;
    }

    busy = true;
    try {
      const response = await orchestrator.processUserMessage(trimmed, (progress) => {
        console.log(progress);
      });

      console.log('\n' + chalk.white(response) + '\n');
    } catch (err) {
      console.error(
        chalk.red(`\nAgent error: ${err instanceof Error ? err.message : String(err)}\n`),
      );
    } finally {
      busy = false;
      if (stdinClosed) realExit(0);
    }
  }
}

export function registerChatCommand(program: Command): void {
  program
    .command('chat')
    .description('Open conversational security agent (Phase 6)')
    .action(runChat);
}
