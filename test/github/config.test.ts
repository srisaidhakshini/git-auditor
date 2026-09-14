import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadStoredConfig, saveStoredToken, clearStoredToken } from '../../src/github/config.js';
import { resolveGitHubToken } from '../../src/github/auth.js';

describe('config.ts & auth.ts', () => {
  const originalEnvToken = process.env['GITHUB_TOKEN'];

  beforeEach(() => {
    delete process.env['GITHUB_TOKEN'];
    clearStoredToken();
  });

  afterEach(() => {
    if (originalEnvToken !== undefined) {
      process.env['GITHUB_TOKEN'] = originalEnvToken;
    } else {
      delete process.env['GITHUB_TOKEN'];
    }
    clearStoredToken();
  });

  it('saves, loads, and clears token in local config', () => {
    expect(loadStoredConfig()?.githubToken).toBeUndefined();

    saveStoredToken('ghp_testToken12345', 'testuser', 'device-flow');

    const config = loadStoredConfig();
    expect(config?.githubToken).toBe('ghp_testToken12345');
    expect(config?.githubUser).toBe('testuser');
    expect(config?.authMethod).toBe('device-flow');

    clearStoredToken();
    expect(loadStoredConfig()?.githubToken).toBeUndefined();
  });

  it('resolves token from environment variable with highest precedence', async () => {
    process.env['GITHUB_TOKEN'] = 'ghp_envToken';
    saveStoredToken('ghp_configToken', 'configuser');

    const auth = await resolveGitHubToken();
    expect(auth.source).toBe('env');
    expect(auth.token).toBe('ghp_envToken');
  });

  it('resolves token from stored config if env variable is not set', async () => {
    saveStoredToken('ghp_configToken', 'configuser');

    const auth = await resolveGitHubToken();
    expect(auth.source).toBe('config');
    expect(auth.token).toBe('ghp_configToken');
    expect(auth.user).toBe('configuser');
  });

  it('throws friendly error when no token is available and gh is not present', async () => {
    await expect(resolveGitHubToken()).rejects.toThrow('No GitHub authentication found');
  });
});
