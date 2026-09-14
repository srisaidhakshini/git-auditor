/**
 * mask.ts — Secret value masking utility.
 *
 * SAFETY CONTRACT: Secret values MUST pass through maskSecret() before
 * being written to stdout, stderr, log files, or JSON/HTML reports.
 * No code path may display an unmasked secret value longer than 8 characters.
 */

const VISIBLE_CHARS = 4; // show first N chars as a hint
const MASK = '****';

/**
 * Masks a secret value so it is safe to display.
 * e.g. "AKIAIOSFODNN7EXAMPLE" → "AKIA****"
 */
export function maskSecret(value: string): string {
  if (!value || value.length === 0) return MASK;
  if (value.length <= VISIBLE_CHARS) return MASK;
  return value.slice(0, VISIBLE_CHARS) + MASK;
}

/**
 * Replaces all occurrences of a known secret value within a larger string.
 * Use when sanitizing multiline output (e.g. gitleaks raw output).
 */
export function redactFromString(text: string, secret: string): string {
  if (!secret || secret.length === 0) return text;
  // escape special regex chars
  const escaped = secret.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return text.replace(new RegExp(escaped, 'g'), maskSecret(secret));
}
