/**
 * shell.ts — Safe child_process wrapper.
 * Provides typed, promise-based exec with timeout support.
 */

import { spawn } from 'node:child_process';

export interface ShellResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

export interface ShellOptions {
  /** Working directory for the command */
  cwd?: string;
  /** Timeout in milliseconds. 0 = no timeout (default). */
  timeoutMs?: number;
  /** Environment variables to merge with process.env */
  env?: Record<string, string>;
}

/**
 * Runs a command and returns stdout/stderr/exitCode.
 * Rejects only on spawn failure (e.g. binary not found).
 * Non-zero exit codes are returned, not thrown — callers must check.
 */
export function runCommand(
  command: string,
  args: string[],
  options: ShellOptions = {},
): Promise<ShellResult> {
  return new Promise((resolve, reject) => {
    const env = { ...process.env, ...options.env } as Record<string, string>;

    const child = spawn(command, args, {
      cwd: options.cwd,
      env,
      shell: false, // never pass through shell — avoids injection
    });

    let stdout = '';
    let stderr = '';
    let timedOut = false;

    let timer: ReturnType<typeof setTimeout> | undefined;
    if (options.timeoutMs && options.timeoutMs > 0) {
      timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGTERM');
      }, options.timeoutMs);
    }

    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    child.on('error', (err: NodeJS.ErrnoException) => {
      if (timer) clearTimeout(timer);
      if (err.code === 'ENOENT') {
        reject(
          new Error(
            `Command not found: "${command}". Make sure it is installed and available in your PATH.`,
          ),
        );
      } else {
        reject(err);
      }
    });

    child.on('close', (code: number | null) => {
      if (timer) clearTimeout(timer);
      resolve({
        stdout,
        stderr,
        exitCode: timedOut ? 124 : (code ?? 1), // 124 = standard timeout exit code
      });
    });
  });
}

/**
 * Asserts that a binary exists on PATH.
 * Throws a user-friendly error with install instructions if not found.
 */
export async function assertBinaryExists(
  binary: string,
  installHint: string,
): Promise<void> {
  try {
    // `where` on Windows, `which` on Unix
    const checkCmd = process.platform === 'win32' ? 'where' : 'which';
    const result = await runCommand(checkCmd, [binary]);
    if (result.exitCode !== 0) throw new Error('not found');
  } catch {
    throw new Error(
      `Required binary "${binary}" was not found in PATH.\n` +
        `Install it with: ${installHint}\n` +
        `Then re-run repo-guardian.`,
    );
  }
}
