/**
 * gitignore.ts — Safe .gitignore generator and patcher.
 *
 * Appends standard secret-bearing and sensitive patterns without
 * clobbering or overwriting any existing custom rules per PRD §4.6.
 */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export const RECOMMENDED_IGNORES = [
  '# Environment & secrets (Repo Guardian)',
  '.env',
  '.env.*',
  '!.env.example',
  '*.pem',
  '*.key',
  '*.pfx',
  '*.p12',
  'id_rsa*',
  'id_ed25519*',
  'secrets.json',
  'credentials.json',
  '',
  '# Dependency & build artifacts',
  'node_modules/',
  'dist/',
  '.npmrc',
];

export interface GitignorePatchResult {
  filePath: string;
  created: boolean;
  modified: boolean;
  addedPatterns: string[];
}

/**
 * Patches or creates a .gitignore in target repository root.
 */
export function patchGitignore(repoPath: string): GitignorePatchResult {
  const gitignorePath = join(repoPath, '.gitignore');
  const exists = existsSync(gitignorePath);

  let existingContent = '';
  if (exists) {
    existingContent = readFileSync(gitignorePath, 'utf8');
  }

  // Parse existing non-empty, non-comment lines
  const existingLines = new Set(
    existingContent
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('#')),
  );

  const missingPatterns: string[] = [];
  for (const item of RECOMMENDED_IGNORES) {
    if (!item || item.startsWith('#')) continue;
    if (!existingLines.has(item)) {
      missingPatterns.push(item);
    }
  }

  if (missingPatterns.length === 0) {
    return {
      filePath: gitignorePath,
      created: false,
      modified: false,
      addedPatterns: [],
    };
  }

  let newContent = existingContent;
  if (newContent.length > 0 && !newContent.endsWith('\n')) {
    newContent += '\n';
  }

  newContent += '\n# ─── Added by Repo Guardian Security Guardrails ─────────────\n';
  for (const pattern of missingPatterns) {
    newContent += `${pattern}\n`;
  }

  writeFileSync(gitignorePath, newContent, 'utf8');

  return {
    filePath: gitignorePath,
    created: !exists,
    modified: true,
    addedPatterns: missingPatterns,
  };
}
