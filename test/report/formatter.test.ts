import { describe, it, expect } from 'vitest';
import { renderTerminalReport, renderJsonReport, renderHtmlReport } from '../../src/report/formatter.js';
import type { ScanReport } from '../../src/report/types.js';

describe('formatter.ts', () => {
  const cleanReport: ScanReport = {
    generatedAt: '2026-09-14T22:00:00Z',
    totalRepos: 1,
    totalFindings: 0,
    repos: [
      {
        repoFullName: 'my-org/clean-repo',
        htmlUrl: 'https://github.com/my-org/clean-repo',
        secrets: {
          repoFullName: 'my-org/clean-repo',
          scannedPath: '/tmp/clean-repo',
          mode: 'full-history',
          findings: [],
          durationMs: 120,
          success: true,
        },
      },
    ],
  };

  const dirtyReport: ScanReport = {
    generatedAt: '2026-09-14T22:00:00Z',
    totalRepos: 1,
    totalFindings: 1,
    repos: [
      {
        repoFullName: 'my-org/dirty-repo',
        htmlUrl: 'https://github.com/my-org/dirty-repo',
        secrets: {
          repoFullName: 'my-org/dirty-repo',
          scannedPath: '/tmp/dirty-repo',
          mode: 'full-history',
          findings: [
            {
              secretType: 'aws-access-key',
              maskedValue: 'AKIA****',
              ruleId: 'aws-access-key-id',
              filePath: '.env',
              commitSha: 'a1b2c3d4e5f6',
              author: 'Developer',
              commitDate: '2026-09-10',
              lineNumber: 4,
              fingerprint: 'fp-12345',
            },
          ],
          durationMs: 250,
          success: true,
        },
      },
    ],
  };

  it('renders clean report with success message', () => {
    const output = renderTerminalReport(cleanReport);
    expect(output).toContain('No secrets found');
    expect(output).toContain('All repos clean');
    expect(output).not.toContain('Cleaning history does NOT undo exposure');
  });

  it('renders dirty report with masked values and mandatory rotation reminder', () => {
    const output = renderTerminalReport(dirtyReport);
    expect(output).toContain('AWS-ACCESS-KEY');
    expect(output).toContain('.env');
    expect(output).toContain('AKIA****');
    // Check mandatory rotation reminder from PRD §5
    expect(output).toContain('Cleaning history does NOT undo exposure');
    expect(output).toContain('Rotate it at your provider console');
  });

  it('renders json report correctly and parses back', () => {
    const jsonStr = renderJsonReport(dirtyReport);
    const parsed = JSON.parse(jsonStr) as ScanReport;
    expect(parsed.totalFindings).toBe(1);
    expect(parsed.repos[0]?.secrets?.findings[0]?.maskedValue).toBe('AKIA****');
  });

  it('renders html report with dashboard cards and masked values', () => {
    const html = renderHtmlReport(dirtyReport);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('AKIA****');
    expect(html).toContain('my-org/dirty-repo');
    expect(html).toContain('CRITICAL REMINDER');
  });
});
