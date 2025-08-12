import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SignJWT, jwtDecrypt, EncryptJWT, importJWK, jwtVerify } from 'jose';
import { TextEncoder } from 'util';

// Helper to convert base64url to Uint8Array
const base64urlToUint8Array = (base64url: string): Uint8Array => {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(base64);
  const uint8Array = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    uint8Array[i] = bin.charCodeAt(i);
  }
  return uint8Array;
};

// Helper to generate a code_challenge from a code_verifier
const generateCodeChallenge = async (codeVerifier: string): Promise<string> => {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
};

describe('/token endpoint', () => {
  const MOCK_OIDC_CLIENT_ID = 'oidc-client-id';
  const MOCK_OIDC_CLIENT_SECRET = 'oidc-client-secret';
  const MOCK_CODE_SECRET = 'orqOuV+sLB0mH0/EM58AC7pOS13buKMYAt/qSIgH2h8=';
  const MOCK_JWT_PRIVATE_KEY = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\",\"d\":\"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI\",\"kid\":\"1\"}";

  beforeEach(() => {
    // Mock the global fetch function for Discord API calls
    global.fetch = vi.fn((input: RequestInfo | URL) => {
      if (typeof input === 'string' && input.startsWith('https://discord.com/api/users/@me')) {
        return Promise.resolve(new Response(JSON.stringify({
          id: 'discord_user_id',
          username: 'testuser',
          avatar: 'testavatar',
          email: 'test@example.com',
          verified: true,
        }), { status: 200 }));
      }
      return Promise.reject(new Error(`Unexpected fetch call to: ${input}`));
    }) as any;
  });

  it('should successfully exchange authorization code for tokens with PKCE', async () => {
    const discordAccessToken = 'mock_discord_access_token';
    const nonce = 'test_nonce';
    const scope = 'openid profile email';
    const codeVerifier = 'test_code_verifier_123456789012345678901234567890';
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Create a mock OIDC authorization code (JWE)
    const oidcCode = await new EncryptJWT({
      discord_access_token: discordAccessToken,
      nonce: nonce,
      scope: scope,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt()
      .setIssuer('http://localhost')
      .setAudience(MOCK_OIDC_CLIENT_ID)
      .setExpirationTime('5m')
      .encrypt(base64urlToUint8Array(MOCK_CODE_SECRET));

    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: MOCK_OIDC_CLIENT_ID,
      code: oidcCode,
      code_verifier: codeVerifier,
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(200);
    const body = await response.json();

    expect(body.access_token).toBeDefined();
    expect(body.token_type).toBe('Bearer');
    expect(body.expires_in).toBe(3600);
    expect(body.scope).toBe(scope);
    expect(body.id_token).toBeDefined();

    // Verify id_token
    const privateJwk = JSON.parse(MOCK_JWT_PRIVATE_KEY);
    const publicKey = await importJWK({ ...privateJwk, d: undefined }, 'ES256');
    const { payload: idTokenPayload } = await jwtVerify(body.id_token, publicKey, {
      issuer: 'http://localhost',
      audience: MOCK_OIDC_CLIENT_ID,
    });

    expect(idTokenPayload.name).toBe('testuser');
    expect(idTokenPayload.picture).toBe('https://cdn.discordapp.com/avatars/discord_user_id/testavatar.png');
    expect(idTokenPayload.email).toBe('test@example.com');
    expect(idTokenPayload.email_verified).toBe(true);
    expect(idTokenPayload.nonce).toBe(nonce);
    expect(idTokenPayload.iss).toBe('http://localhost');
    expect(idTokenPayload.aud).toBe(MOCK_OIDC_CLIENT_ID);
    expect(idTokenPayload.sub).toBe('discord_user_id');
  });

  it('should return 400 for invalid grant_type', async () => {
    const formData = new URLSearchParams({
      grant_type: 'invalid_grant',
      client_id: MOCK_OIDC_CLIENT_ID,
      code: 'some_code',
      code_verifier: 'some_verifier',
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'unsupported_grant_type', error_description: 'invalid grant_type' });
  });

  it('should return 401 for invalid client_id', async () => {
    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'wrong_client_id',
      code: 'some_code',
      code_verifier: 'some_verifier',
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'invalid_client', error_description: 'invalid client_id' });
  });

  it('should return 401 for invalid client_secret when PKCE is not used', async () => {
    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: MOCK_OIDC_CLIENT_ID,
      client_secret: 'wrong_secret',
      code: 'some_code',
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'invalid_client', error_description: 'client_secret is required or invalid' });
  });

  it('should return 400 if code is missing', async () => {
    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: MOCK_OIDC_CLIENT_ID,
      code_verifier: 'some_verifier',
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({ error: 'invalid_request', error_description: 'code is required' });
  });

  it('should return 400 if code_verifier is missing for PKCE flow', async () => {
    const discordAccessToken = 'mock_discord_access_token';
    const nonce = 'test_nonce';
    const scope = 'openid profile email';
    const codeChallenge = 'some_challenge'; // This will be ignored if code_verifier is missing

    // Create a mock OIDC authorization code (JWE)
    const oidcCode = await new EncryptJWT({
      discord_access_token: discordAccessToken,
      nonce: nonce,
      scope: scope,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt()
      .setIssuer('http://localhost')
      .setAudience(MOCK_OIDC_CLIENT_ID)
      .setExpirationTime('5m')
      .encrypt(base64urlToUint8Array(MOCK_CODE_SECRET));

    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: MOCK_OIDC_CLIENT_ID,
      code: oidcCode,
      // code_verifier is missing
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'invalid_client', error_description: 'client_secret is required or invalid' });
  });

  it('should return 401 for invalid code_verifier', async () => {
    const discordAccessToken = 'mock_discord_access_token';
    const nonce = 'test_nonce';
    const scope = 'openid profile email';
    const codeChallenge = await generateCodeChallenge('correct_code_verifier');

    // Create a mock OIDC authorization code (JWE) with a valid code_challenge
    const oidcCode = await new EncryptJWT({
      discord_access_token: discordAccessToken,
      nonce: nonce,
      scope: scope,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt()
      .setIssuer('http://localhost')
      .setAudience(MOCK_OIDC_CLIENT_ID)
      .setExpirationTime('5m')
      .encrypt(base64urlToUint8Array(MOCK_CODE_SECRET));

    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: MOCK_OIDC_CLIENT_ID,
      code: oidcCode,
      code_verifier: 'invalid_code_verifier', // Mismatch
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(401);
    expect(await response.json()).toEqual({ error: 'invalid_grant', error_description: 'invalid code_verifier' });
  });

  it('should return 500 if Discord user info fetch fails', async () => {
    // Temporarily override fetch to simulate a failed Discord user info fetch
    global.fetch = vi.fn(() => Promise.resolve(new Response('{}', { status: 400 }))) as any;

    const discordAccessToken = 'mock_discord_access_token';
    const nonce = 'test_nonce';
    const scope = 'openid profile email';
    const codeVerifier = 'test_code_verifier_123456789012345678901234567890';
    const codeChallenge = await generateCodeChallenge(codeVerifier);

    // Create a mock OIDC authorization code (JWE)
    const oidcCode = await new EncryptJWT({
      discord_access_token: discordAccessToken,
      nonce: nonce,
      scope: scope,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
    })
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .setIssuedAt()
      .setIssuer('http://localhost')
      .setAudience(MOCK_OIDC_CLIENT_ID)
      .setExpirationTime('5m')
      .encrypt(base64urlToUint8Array(MOCK_CODE_SECRET));

    const formData = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: MOCK_OIDC_CLIENT_ID,
      code: oidcCode,
      code_verifier: codeVerifier,
    });

    const response = await SELF.fetch('http://localhost/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
    });

    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({ error: 'server_error', error_description: 'Failed to fetch user from Discord' });
  });
});
