// Set environment variables before any imports
process.env.REDASH_URL = 'https://redash.example.com';
process.env.REDASH_API_KEY = 'test-api-key';
process.env.REDIS_URL = 'redis://localhost:6379/0';

import { jest } from '@jest/globals';

// In-memory store to back the mocked Redis
const store = new Map<string, { value: string; expiry?: number }>();

// Mock Redis before importing auth module
const mockMultiExec = jest.fn(async () => [[null, 'OK'], [null, 'OK'], [null, 1]]);
const mockMultiSet = jest.fn().mockReturnThis();
const mockMultiExpire = jest.fn().mockReturnThis();

jest.mock('../redis.js', () => ({
  redis: {
    get: jest.fn(async (key: string) => {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiry && Date.now() > entry.expiry) {
        store.delete(key);
        return null;
      }
      return entry.value;
    }),
    getdel: jest.fn(async (key: string) => {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiry && Date.now() > entry.expiry) {
        store.delete(key);
        return null;
      }
      const value = entry.value;
      store.delete(key);
      return value;
    }),
    set: jest.fn(async (key: string, value: string, _ex?: string, ttl?: number) => {
      store.set(key, {
        value,
        expiry: ttl ? Date.now() + ttl * 1000 : undefined,
      });
      return 'OK';
    }),
    del: jest.fn(async (key: string) => {
      return store.delete(key) ? 1 : 0;
    }),
    expire: jest.fn(async (_key: string, _ttl: number) => {
      return 1;
    }),
    multi: jest.fn(() => ({
      set: mockMultiSet,
      expire: mockMultiExpire,
      exec: mockMultiExec,
    })),
    status: 'ready',
  },
  redisKey: jest.fn(
    (store: string, id: string) => `redash-mcp:${store}:${id}`
  ),
  connectRedis: jest.fn(async () => {}),
}));

// Mock logger
jest.mock('../logger.js', () => ({
  logger: {
    debug: jest.fn(),
    info: jest.fn(),
    warning: jest.fn(),
    error: jest.fn(),
    log: jest.fn(),
  },
}));

import { RedashOAuthProvider, getRedashApiKeyFromAuth } from '../auth.js';
import { redis, redisKey } from '../redis.js';
import { logger } from '../logger.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';

// Helper to build a minimal client object
function makeClient(overrides: Partial<OAuthClientInformationFull> = {}): OAuthClientInformationFull {
  return {
    client_id: 'test-client-id',
    client_secret: 'test-client-secret',
    client_id_issued_at: Math.floor(Date.now() / 1000),
    redirect_uris: ['http://localhost:3000/callback'],
    token_endpoint_auth_method: 'client_secret_post',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    client_name: 'Test App',
    ...overrides,
  } as OAuthClientInformationFull;
}

// Helper to build a mock Express Response
function mockResponse() {
  const res: any = {};
  res.status = jest.fn().mockReturnValue(res);
  res.send = jest.fn().mockReturnValue(res);
  res.setHeader = jest.fn().mockReturnValue(res);
  res.redirect = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

describe('RedashOAuthProvider', () => {
  let provider: RedashOAuthProvider;

  beforeEach(() => {
    store.clear();
    jest.clearAllMocks();
    mockMultiSet.mockReturnThis();
    mockMultiExpire.mockReturnThis();
    mockMultiExec.mockResolvedValue([[null, 'OK'], [null, 'OK'], [null, 1]]);
    provider = new RedashOAuthProvider();
  });

  // --- Client registration ---

  describe('clientsStore.registerClient', () => {
    it('should register a client with localhost redirect URI', async () => {
      const client = makeClient({ redirect_uris: ['http://localhost:3000/callback'] });
      const result = await provider.clientsStore.registerClient!(client);

      expect(result.client_id).toBeDefined();
      expect(result.client_secret).toBeDefined();
      expect(result.client_id_issued_at).toBeDefined();
      expect(redis.set).toHaveBeenCalled();
    });

    it('should register a client with 127.0.0.1 redirect URI', async () => {
      const client = makeClient({ redirect_uris: ['http://127.0.0.1:8080/callback'] });
      const result = await provider.clientsStore.registerClient!(client);

      expect(result.client_id).toBeDefined();
    });

    it('should reject registration with external redirect URI', async () => {
      const client = makeClient({ redirect_uris: ['https://evil.example.com/steal'] });

      await expect(provider.clientsStore.registerClient!(client)).rejects.toThrow(
        /redirect_uri not allowed/
      );
      expect(logger.warning).toHaveBeenCalledWith(
        expect.stringContaining('disallowed redirect_uri')
      );
    });

    it('should reject registration with no redirect URIs', async () => {
      const client = makeClient({ redirect_uris: [] });

      await expect(provider.clientsStore.registerClient!(client)).rejects.toThrow(
        /at least one redirect_uri/i
      );
    });

    it('should reject if any redirect URI in the list is external', async () => {
      const client = makeClient({
        redirect_uris: [
          'http://localhost:3000/callback',
          'https://attacker.com/phish',
        ],
      });

      await expect(provider.clientsStore.registerClient!(client)).rejects.toThrow(
        /redirect_uri not allowed/
      );
    });

    it('should reject invalid URL in redirect URIs', async () => {
      const client = makeClient({ redirect_uris: ['not-a-valid-url'] });

      await expect(provider.clientsStore.registerClient!(client)).rejects.toThrow(
        /redirect_uri not allowed/
      );
    });
  });

  // --- Client lookup ---

  describe('clientsStore.getClient', () => {
    it('should return a stored client', async () => {
      const client = makeClient();
      store.set('redash-mcp:client:test-client-id', {
        value: JSON.stringify(client),
      });

      const result = await provider.clientsStore.getClient('test-client-id');
      expect(result).toEqual(client);
    });

    it('should return undefined for unknown client', async () => {
      const result = await provider.clientsStore.getClient('nonexistent');
      expect(result).toBeUndefined();
    });
  });

  // --- Authorization page ---

  describe('authorize', () => {
    it('should render HTML form with CSRF token', async () => {
      const res = mockResponse();
      const client = makeClient();
      const params = {
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'test-challenge',
        state: 'test-state',
      };

      await provider.authorize(client, params as any, res);

      expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/html');
      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('csrf_token'));
      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('test-challenge'));
      expect(res.send).toHaveBeenCalledWith(expect.stringContaining('test-state'));
      expect(redis.set).toHaveBeenCalled();
    });

    it('should escape HTML in client name', async () => {
      const res = mockResponse();
      const client = makeClient({ client_name: '<script>alert("xss")</script>' });
      const params = {
        redirectUri: 'http://localhost:3000/callback',
        codeChallenge: 'c',
        state: '',
      };

      await provider.authorize(client, params as any, res);

      const html = (res.send as jest.Mock).mock.calls[0][0] as string;
      expect(html).not.toContain('<script>');
      expect(html).toContain('&lt;script&gt;');
    });
  });

  // --- Authorization code exchange ---

  describe('exchangeAuthorizationCode', () => {
    const authCodeData = {
      clientId: 'test-client-id',
      codeChallenge: 'challenge',
      redirectUri: 'http://localhost:3000/callback',
      redashApiKey: 'redash-key-123',
      state: 'some-state',
    };

    it('should exchange a valid auth code for tokens', async () => {
      store.set('redash-mcp:code:valid-code', {
        value: JSON.stringify(authCodeData),
      });

      const client = makeClient({ client_id: 'test-client-id' });
      const tokens = await provider.exchangeAuthorizationCode(
        client,
        'valid-code',
        undefined,
        'http://localhost:3000/callback'
      );

      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
      expect(tokens.token_type).toBe('Bearer');
      expect(tokens.expires_in).toBeGreaterThan(0);
      // Auth code should be atomically consumed via getdel
      expect(redis.getdel).toHaveBeenCalledWith('redash-mcp:code:valid-code');
      // Token writes should use a multi/exec transaction
      expect(redis.multi).toHaveBeenCalled();
      expect(mockMultiExec).toHaveBeenCalled();
    });

    it('should reject invalid auth code', async () => {
      const client = makeClient();
      await expect(
        provider.exchangeAuthorizationCode(client, 'bogus-code')
      ).rejects.toThrow('Invalid authorization code');
      expect(logger.warning).toHaveBeenCalledWith(
        expect.stringContaining('invalid code')
      );
    });

    it('should reject client mismatch', async () => {
      store.set('redash-mcp:code:code-1', {
        value: JSON.stringify(authCodeData),
      });

      const wrongClient = makeClient({ client_id: 'wrong-client' });
      await expect(
        provider.exchangeAuthorizationCode(wrongClient, 'code-1')
      ).rejects.toThrow('Client mismatch');
      expect(logger.warning).toHaveBeenCalledWith(
        expect.stringContaining('client mismatch')
      );
    });

    it('should reject redirect_uri mismatch', async () => {
      store.set('redash-mcp:code:code-2', {
        value: JSON.stringify(authCodeData),
      });

      const client = makeClient({ client_id: 'test-client-id' });
      await expect(
        provider.exchangeAuthorizationCode(
          client,
          'code-2',
          undefined,
          'http://localhost:9999/other'
        )
      ).rejects.toThrow('redirect_uri mismatch');
      expect(logger.warning).toHaveBeenCalledWith(
        expect.stringContaining('redirect_uri mismatch')
      );
    });

    it('should handle Redis errors gracefully', async () => {
      (redis.getdel as jest.Mock<any>).mockRejectedValueOnce(new Error('Connection lost'));

      const client = makeClient();
      await expect(
        provider.exchangeAuthorizationCode(client, 'any-code')
      ).rejects.toThrow('Token exchange failed due to an internal error');
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Connection lost')
      );
    });

    it('should throw when Redis pipeline partially fails', async () => {
      store.set('redash-mcp:code:pipeline-fail', {
        value: JSON.stringify(authCodeData),
      });
      mockMultiExec.mockResolvedValueOnce([
        [null, 'OK'],
        [new Error('READONLY') as any, null],
        [null, 1],
      ]);

      const client = makeClient({ client_id: 'test-client-id' });
      await expect(
        provider.exchangeAuthorizationCode(client, 'pipeline-fail', undefined, 'http://localhost:3000/callback')
      ).rejects.toThrow('Token exchange failed due to an internal error');
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Redis pipeline partially failed')
      );
    });
  });

  // --- Refresh token exchange ---

  describe('exchangeRefreshToken', () => {
    it('should issue new tokens and rotate the refresh token', async () => {
      const refreshData = {
        clientId: 'test-client-id',
        redashApiKey: 'redash-key-456',
      };
      store.set('redash-mcp:refresh:old-refresh', {
        value: JSON.stringify(refreshData),
      });

      const client = makeClient({ client_id: 'test-client-id' });
      const tokens = await provider.exchangeRefreshToken(client, 'old-refresh');

      expect(tokens.access_token).toBeDefined();
      expect(tokens.refresh_token).toBeDefined();
      expect(tokens.refresh_token).not.toBe('old-refresh');
      // Old refresh token should be atomically consumed via getdel
      expect(redis.getdel).toHaveBeenCalledWith('redash-mcp:refresh:old-refresh');
      // Token writes should use a multi/exec transaction
      expect(redis.multi).toHaveBeenCalled();
      expect(mockMultiExec).toHaveBeenCalled();
    });

    it('should reject invalid refresh token', async () => {
      const client = makeClient();
      await expect(
        provider.exchangeRefreshToken(client, 'nonexistent')
      ).rejects.toThrow('Invalid refresh token');
      expect(logger.warning).toHaveBeenCalledWith(
        expect.stringContaining('invalid token')
      );
    });

    it('should reject client mismatch on refresh', async () => {
      store.set('redash-mcp:refresh:rf-1', {
        value: JSON.stringify({ clientId: 'client-a', redashApiKey: 'k' }),
      });

      const wrongClient = makeClient({ client_id: 'client-b' });
      await expect(
        provider.exchangeRefreshToken(wrongClient, 'rf-1')
      ).rejects.toThrow('Client mismatch');
      expect(logger.warning).toHaveBeenCalledWith(
        expect.stringContaining('client mismatch')
      );
    });

    it('should handle Redis errors gracefully', async () => {
      (redis.getdel as jest.Mock<any>).mockRejectedValueOnce(new Error('Redis timeout'));

      const client = makeClient();
      await expect(
        provider.exchangeRefreshToken(client, 'any-token')
      ).rejects.toThrow('Token refresh failed due to an internal error');
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Redis timeout')
      );
    });

    it('should throw when Redis pipeline partially fails', async () => {
      store.set('redash-mcp:refresh:rf-pipeline-fail', {
        value: JSON.stringify({ clientId: 'test-client-id', redashApiKey: 'k' }),
      });
      mockMultiExec.mockResolvedValueOnce([
        [null, 'OK'],
        [new Error('READONLY') as any, null],
        [null, 1],
      ]);

      const client = makeClient({ client_id: 'test-client-id' });
      await expect(
        provider.exchangeRefreshToken(client, 'rf-pipeline-fail')
      ).rejects.toThrow('Token refresh failed due to an internal error');
      expect(logger.error).toHaveBeenCalledWith(
        expect.stringContaining('Redis pipeline partially failed')
      );
    });
  });

  // --- Access token verification ---

  describe('verifyAccessToken', () => {
    it('should return AuthInfo for a valid token', async () => {
      const tokenData = {
        clientId: 'test-client-id',
        redashApiKey: 'redash-key-789',
      };
      store.set('redash-mcp:token:valid-token', {
        value: JSON.stringify(tokenData),
      });

      const authInfo = await provider.verifyAccessToken('valid-token');

      expect(authInfo.token).toBe('valid-token');
      expect(authInfo.clientId).toBe('test-client-id');
      expect(authInfo.extra?.redashApiKey).toBe('redash-key-789');
      expect(authInfo.scopes).toEqual([]);
      // Should refresh TTL (sliding expiry)
      expect(redis.expire).toHaveBeenCalledWith(
        'redash-mcp:token:valid-token',
        expect.any(Number)
      );
    });

    it('should reject an invalid token', async () => {
      await expect(
        provider.verifyAccessToken('bad-token')
      ).rejects.toThrow('Invalid access token');
      expect(logger.warning).toHaveBeenCalledWith(
        expect.stringContaining('verification failed')
      );
    });
  });

  // --- Token revocation ---

  describe('revokeToken', () => {
    it('should delete both access and refresh token entries', async () => {
      const client = makeClient();
      await provider.revokeToken(client, { token: 'some-token' } as any);

      expect(redis.del).toHaveBeenCalledWith('redash-mcp:token:some-token');
      expect(redis.del).toHaveBeenCalledWith('redash-mcp:refresh:some-token');
    });
  });

  // --- CSRF and authorize submit ---

  describe('handleAuthorizeSubmit', () => {
    it('should reject an invalid CSRF token', async () => {
      const res = mockResponse();

      await provider.handleAuthorizeSubmit(
        'bad-csrf',
        'client-1',
        'http://localhost:3000/cb',
        'challenge',
        undefined,
        'api-key',
        res
      );

      expect(res.status).toHaveBeenCalledWith(403);
      expect(res.send).toHaveBeenCalledWith(
        expect.stringContaining('Invalid or expired')
      );
    });

    it('should reject an unknown client_id', async () => {
      // Store a valid CSRF token
      store.set('redash-mcp:csrf:good-csrf', { value: '1' });

      const res = mockResponse();
      await provider.handleAuthorizeSubmit(
        'good-csrf',
        'nonexistent-client',
        'http://localhost:3000/cb',
        'challenge',
        undefined,
        'api-key',
        res
      );

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.send).toHaveBeenCalledWith('Invalid client_id');
    });

    it('should reject a redirect_uri not registered on the client', async () => {
      store.set('redash-mcp:csrf:csrf-2', { value: '1' });
      const client = makeClient({
        client_id: 'c1',
        redirect_uris: ['http://localhost:3000/callback'],
      });
      store.set('redash-mcp:client:c1', { value: JSON.stringify(client) });

      const res = mockResponse();
      await provider.handleAuthorizeSubmit(
        'csrf-2',
        'c1',
        'http://localhost:9999/other',
        'challenge',
        undefined,
        'api-key',
        res
      );

      expect(res.status).toHaveBeenCalledWith(400);
      expect(res.send).toHaveBeenCalledWith('Invalid redirect_uri');
    });

    it('should issue auth code and redirect on success', async () => {
      store.set('redash-mcp:csrf:csrf-ok', { value: '1' });
      const client = makeClient({
        client_id: 'c2',
        redirect_uris: ['http://localhost:3000/callback'],
      });
      store.set('redash-mcp:client:c2', { value: JSON.stringify(client) });

      const res = mockResponse();
      await provider.handleAuthorizeSubmit(
        'csrf-ok',
        'c2',
        'http://localhost:3000/callback',
        'challenge-abc',
        'state-xyz',
        'my-redash-key',
        res
      );

      expect(res.redirect).toHaveBeenCalledWith(
        302,
        expect.stringContaining('code=')
      );
      expect(res.redirect).toHaveBeenCalledWith(
        302,
        expect.stringContaining('state=state-xyz')
      );
      // Auth code should be stored in Redis
      expect(redis.set).toHaveBeenCalledWith(
        expect.stringContaining('redash-mcp:code:'),
        expect.stringContaining('my-redash-key'),
        'EX',
        expect.any(Number)
      );
    });

    it('should consume the CSRF token (single-use)', async () => {
      store.set('redash-mcp:csrf:csrf-once', { value: '1' });
      const client = makeClient({
        client_id: 'c3',
        redirect_uris: ['http://localhost:3000/callback'],
      });
      store.set('redash-mcp:client:c3', { value: JSON.stringify(client) });

      const res1 = mockResponse();
      await provider.handleAuthorizeSubmit(
        'csrf-once', 'c3', 'http://localhost:3000/callback',
        'ch', undefined, 'key', res1
      );
      expect(res1.redirect).toHaveBeenCalled();

      // Second attempt with same CSRF should fail
      const res2 = mockResponse();
      await provider.handleAuthorizeSubmit(
        'csrf-once', 'c3', 'http://localhost:3000/callback',
        'ch', undefined, 'key', res2
      );
      expect(res2.status).toHaveBeenCalledWith(403);
    });
  });
});

// --- getRedashApiKeyFromAuth ---

describe('getRedashApiKeyFromAuth', () => {
  it('should extract the API key from auth info', () => {
    const auth: AuthInfo = {
      token: 'tok',
      clientId: 'c',
      scopes: [],
      extra: { redashApiKey: 'my-key' },
    };
    expect(getRedashApiKeyFromAuth(auth)).toBe('my-key');
  });

  it('should throw when API key is missing', () => {
    const auth: AuthInfo = {
      token: 'tok',
      clientId: 'c',
      scopes: [],
    };
    expect(() => getRedashApiKeyFromAuth(auth)).toThrow(
      'No Redash API key in auth info'
    );
  });

  it('should throw when API key is empty string', () => {
    const auth: AuthInfo = {
      token: 'tok',
      clientId: 'c',
      scopes: [],
      extra: { redashApiKey: '' },
    };
    expect(() => getRedashApiKeyFromAuth(auth)).toThrow(
      'No Redash API key in auth info'
    );
  });
});
