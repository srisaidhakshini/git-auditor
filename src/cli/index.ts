#!/usr/bin/env node
/**
 * index.ts — CLI entry point.
 * Parses argv and routes to sub-commands via commander.
 */

import { Command } from 'commander';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { registerScanCommand } from './commands/scan.js';
import { registerCleanCommand } from './commands/clean.js';
import { registerInitPreventionCommand } from './commands/init-prevention.js';
import { registerChatCommand } from './commands/chat.js';

// Read version from package.json
const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(join(__dirname, '../../package.json'), 'utf8'),
) as { version: string };

const program = new Command();

program
  .name('repo-guardian')
  .description(
    'Security & hygiene agent for GitHub repositories.\n' +
      'Detects leaked secrets and malicious dependencies, remediates safely.',
  )
  .version(pkg.version);

// Register all sub-commands
registerScanCommand(program);
registerCleanCommand(program);
registerInitPreventionCommand(program);
registerChatCommand(program);

// Parse argv — commander handles --help and unknown commands automatically
program.parse(process.argv);
