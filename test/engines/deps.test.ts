import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { scanDependencies } from '../../src/engines/deps/scanner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES_DIR = join(__dirname, '../fixtures');

describe('Dependency and Malware Scanner', () => {
  it('detects malicious lifecycle scripts and typosquatting in fixture', async () => {
    const maliciousPath = join(FIXTURES_DIR, 'malicious-repo');
    const result = await scanDependencies(maliciousPath, 'test-org/malicious-repo');

    expect(result.manifestFound).toBe(true);
    expect(result.packageCount).toBeGreaterThan(0);
    expect(result.findings.length).toBeGreaterThanOrEqual(2);

    const scriptFinding = result.findings.find((f) => f.findingType === 'malicious-script');
    expect(scriptFinding).toBeDefined();
    expect(scriptFinding?.severity).toBe('critical');
    expect(scriptFinding?.details?.hook).toBe('postinstall');

    const typosquatFindings = result.findings.filter((f) => f.findingType === 'typosquat');
    expect(typosquatFindings.length).toBeGreaterThan(0);
    const names = typosquatFindings.map((f) => f.packageName);
    expect(names).toContain('expresss');
  });

  it('handles repositories without package.json gracefully', async () => {
    const dirtyRepoPath = join(FIXTURES_DIR, 'dirty-repo');
    const result = await scanDependencies(dirtyRepoPath, 'test-org/dirty-repo');

    expect(result.manifestFound).toBe(false);
    expect(result.packageCount).toBe(0);
    expect(result.findings).toHaveLength(0);
  });
});
