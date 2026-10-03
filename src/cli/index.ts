#!/usr/bin/env node
/**
 * index.ts — CLI entry point.
 * Parses argv and routes to sub-commands via commander.
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { registerAuthCommand } from './commands/auth.js';
import { registerScanCommand } from './commands/scan.js';
import { registerCleanCommand } from './commands/clean.js';
import { registerInitPreventionCommand } from './commands/init-prevention.js';
import { registerChatCommand } from './commands/chat.js';
import { registerDoctorCommand } from './commands/doctor.js';
import { showMainMenu } from './menu.js';
import { isInteractive } from './picker.js';
import { realExit } from '../utils/exit.js';

// Read version from package.json
const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(__dirname, '../../package.json'), 'utf8'),
) as { version: string };

// On Windows, exiting while an HTTP connection is still closing trips a libuv assertion
// (exit code 127). Defer the real exit slightly and unwind the caller with a sentinel.
class ExitSignal extends Error {}
process.exit = ((code?: number) => {
  process.exitCode = code ?? process.exitCode ?? 0;
  setTimeout(() => realExit(), 100);
  throw new ExitSignal();
}) as typeof process.exit;

const program = new Command();

program
  .name('repo-guardian')
  .description(
    'Security & hygiene agent for GitHub repositories.\n' +
      'Detects leaked secrets and malicious dependencies, remediates safely.',
  )
  .version(pkg.version);

// Register all sub-commands
registerAuthCommand(program);
registerScanCommand(program);
registerCleanCommand(program);
registerInitPreventionCommand(program);
registerChatCommand(program);
registerDoctorCommand(program);

// Friendlier errors: suggest close command names and point to help on misuse
program.showSuggestionAfterError(true);
program.showHelpAfterError('(run with --help for usage)');

// No arguments in a terminal -> interactive menu; otherwise parse argv normally
let argv = process.argv;
if (process.argv.length <= 2 && isInteractive()) {
  const choice = await showMainMenu();
  if (!choice) process.exit(0);
  argv = [...process.argv.slice(0, 2), ...choice];
}
try {
  await program.parseAsync(argv);
} catch (err) {
  if (!(err instanceof ExitSignal)) throw err;
}
