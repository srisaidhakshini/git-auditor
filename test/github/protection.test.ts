import { describe, it, expect, vi } from 'vitest';
import {
  checkBranchProtection,
  checkOpenPullRequests,
} from '../../src/github/protection.js';

describe('GitHub Protection Checks', () => {
  it('returns default protection status when branch protection returns 404', async () => {
    const fakeAuth = { token: 'ghp_fake_token', source: 'env' as const };
    const status = await checkBranchProtection(fakeAuth, 'test-owner', 'test-repo', 'main');
    expect(status.isProtected).toBe(false);
    expect(status.allowForcePushes).toBe(true);
  });

  it('handles PR check errors gracefully', async () => {
    const fakeAuth = { token: 'ghp_fake_token', source: 'env' as const };
    const prStatus = await checkOpenPullRequests(fakeAuth, 'test-owner', 'test-repo', 'main');
    expect(prStatus.hasOpenPRs).toBe(false);
    expect(prStatus.openPRCount).toBe(0);
  });
});
