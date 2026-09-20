/**
 * hooks.ts — Pre-commit hook installer for secret leak prevention.
 *
 * Configures git pre-commit hooks to block commits containing secrets.
 */

import { existsSync, mkdirSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';

export interface HookInstallResult {
  hookPath: string;
  installed: boolean;
  hookType: 'gitleaks' | 'native-staged-check';
}

const PRE_COMMIT_SCRIPT = `#!/bin/sh
# Repo Guardian Pre-Commit Hook
# Prevents committing secrets and .env files to git history

# 1. If gitleaks is installed, run gitleaks protect
if command -v gitleaks >/dev/null 2>&1; then
  gitleaks protect --staged --verbose
  EXIT_CODE=$?
  if [ $EXIT_CODE -ne 0 ]; then
    echo "\n[Repo Guardian] ❌ Commit blocked: Leaked secrets detected in staged files by gitleaks!"
    exit 1
  fi
fi

# 2. Check staged filenames against critical secret patterns
STAGED_FILES=$(git diff --cached --name-only)
for FILE in $STAGED_FILES; do
  case "$FILE" in
    .env|.env.*|*.pem|*.key|id_rsa|id_ed25519)
      if [ "$FILE" != ".env.example" ]; then
        echo "\n[Repo Guardian] ❌ Commit blocked: Sensitive file '$FILE' is staged for commit!"
        echo "[Repo Guardian] 💡 Tip: Add it to .gitignore or remove it with 'git reset HEAD $FILE'"
        exit 1
      fi
      ;;
  esac
done

exit 0
`;

/**
 * Installs pre-commit hook in the repository's .git/hooks directory.
 */
export function installPreCommitHook(repoPath: string): HookInstallResult {
  const hooksDir = join(repoPath, '.git', 'hooks');

  if (!existsSync(hooksDir)) {
    mkdirSync(hooksDir, { recursive: true });
  }

  const hookFile = join(hooksDir, 'pre-commit');
  writeFileSync(hookFile, PRE_COMMIT_SCRIPT, { encoding: 'utf8', mode: 0o755 });

  try {
    chmodSync(hookFile, 0o755);
  } catch {
    // Windows chmod may be a no-op
  }

  return {
    hookPath: hookFile,
    installed: true,
    hookType: 'gitleaks',
  };
}
