/**
 * exit.ts — process-exit helpers.
 *
 * `realExit` is the real process.exit, captured before the CLI entry point wraps it.
 * `trapExit` lets interactive flows call commands that use process.exit() without
 * ending the whole session: inside the trap, exit() throws ExitTrapped instead.
 */
export const realExit: (code?: number) => never = process.exit.bind(process);

export class ExitTrapped extends Error {
  constructor(public readonly code: number) {
    super(`exit ${code}`);
  }
}

let depth = 0;

export const isExitTrapped = (): boolean => depth > 0;

export async function trapExit<T>(fn: () => Promise<T>): Promise<{ value?: T; exitCode?: number }> {
  depth++;
  try {
    return { value: await fn() };
  } catch (err) {
    if (err instanceof ExitTrapped) return { exitCode: err.code };
    throw err;
  } finally {
    depth--;
  }
}
