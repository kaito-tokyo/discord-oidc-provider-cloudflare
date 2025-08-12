import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi } from 'vitest';

describe('OIDC Provider', () => {
  it('should return OpenID configuration', async () => {
    const response = await SELF.fetch('http://localhost/.well-known/openid-configuration', { redirect: 'manual' });
    expect(response.status).toBe(200);
    const body = await response.json();
    const issuer = 'http://localhost';
    expect(body).toEqual({
      issuer: issuer,
      authorization_endpoint: `${issuer}/auth`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/jwks.json`,
      userinfo_endpoint: `${issuer}/userinfo`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_post'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'picture', 'email'],
      code_challenge_methods_supported: ['S256'],
    });
  });

  it('should return JWKS', async () => {
    const privateJwk = {
      kty: 'EC',
      crv: 'P-256',
      x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
      y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
      d: 'jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI',
      kid: '1',
    };
    vi.stubEnv('JWT_PRIVATE_KEY', JSON.stringify(privateJwk));

    const response = await SELF.fetch('http://localhost/jwks.json', { redirect: 'manual' });
    expect(response.status).toBe(200);
    const body = await response.json() as any;
    expect(body.keys).toBeInstanceOf(Array);
    expect(body.keys.length).toBe(1);
    const jwk = body.keys[0];
    expect(jwk.kty).toBe('EC');
    expect(jwk.crv).toBe('P-256');
    expect(jwk.alg).toBe('ES256');
    expect(jwk.use).toBe('sig');
    expect(typeof jwk.kid).toBe('string');
    expect(typeof jwk.x).toBe('string');
    expect(typeof jwk.y).toBe('string');
  });

  
});
