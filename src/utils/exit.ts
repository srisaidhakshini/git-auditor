/**
 * exit.ts — captures the real process.exit before the CLI entry point wraps it.
 * Use from event handlers, where the wrapped version's sentinel throw would be uncaught.
 */
export const realExit: (code?: number) => never = process.exit.bind(process);
