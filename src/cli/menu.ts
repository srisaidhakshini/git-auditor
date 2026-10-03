/**
 * menu.ts — Interactive main menu shown when `repo-guardian` runs with no arguments.
 */

import inquirer from 'inquirer';
import chalk from 'chalk';

/** Returns the argv (after the program name) the user chose, or null to quit. */
export async function showMainMenu(): Promise<string[] | null> {
  console.log(
    chalk.bold.cyan('\n🛡️  Repo Guardian') +
      chalk.dim('  — secrets & dependency security for your GitHub repos\n'),
  );
  try {
    const { action } = await inquirer.prompt<{ action: string }>([
      {
        type: 'select',
        name: 'action',
        message: 'What would you like to do?',
        choices: [
          { name: 'Guided fix: scan, then fix problems step by step (recommended)', value: 'fix' },
          { name: 'Scan repositories for secrets & risky dependencies', value: 'scan' },
          { name: "Clean secrets out of a repository's git history", value: 'clean' },
          { name: 'Protect this project (.gitignore + pre-commit hook)', value: 'init-prevention' },
          { name: 'Chat with the security agent', value: 'chat' },
          { name: 'Log in to GitHub', value: 'auth login' },
          { name: 'Check my setup (doctor)', value: 'doctor' },
          { name: 'Quit', value: 'quit' },
        ],
      },
    ]);
    return action === 'quit' ? null : action.split(' ');
  } catch (err) {
    if (err instanceof Error && err.name === 'ExitPromptError') return null;
    throw err;
  }
}
