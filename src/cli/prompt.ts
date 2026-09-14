/**
 * prompt.ts — Interactive CLI confirmation prompts.
 *
 * Phase 1: used for future destructive-action confirmations (Phase 3+).
 * Wired now so all command handlers can import from one place.
 *
 * SAFETY: The confirmation() function must be used (and passed as confirmed=true)
 * before any destructive engine call. The agent/LLM may NOT self-approve.
 */

import inquirer from 'inquirer';

/**
 * Asks the user to type a specific phrase to confirm a destructive action.
 * Returns true only if the user types the exact phrase.
 *
 * @param message - The warning message shown before the prompt.
 * @param phrase - The exact phrase the user must type (e.g. "yes, rewrite history").
 */
export async function dangerConfirm(message: string, phrase: string): Promise<boolean> {
  console.error('\n' + '⚠️  '.repeat(10));
  console.error(message);
  console.error('⚠️  '.repeat(10) + '\n');

  const { input } = await inquirer.prompt<{ input: string }>([
    {
      type: 'input',
      name: 'input',
      message: `Type exactly "${phrase}" to confirm, or press Enter to cancel:`,
    },
  ]);

  return input.trim() === phrase;
}

/**
 * A simple yes/no prompt.
 */
export async function confirm(message: string, defaultValue = false): Promise<boolean> {
  const { answer } = await inquirer.prompt<{ answer: boolean }>([
    {
      type: 'confirm',
      name: 'answer',
      message,
      default: defaultValue,
    },
  ]);
  return answer;
}

/**
 * A single-choice selection prompt.
 */
export async function select<T extends string>(
  message: string,
  choices: T[],
): Promise<T> {
  const { answer } = await inquirer.prompt<{ answer: T }>([
    {
      type: 'list',
      name: 'answer',
      message,
      choices,
    },
  ]);
  return answer;
}
