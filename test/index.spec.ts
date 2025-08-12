import { SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';

describe('OIDC Provider', () => {
  it('should return OpenID configuration', async () => {
    const response = await SELF.fetch('http://localhost/.well-known/openid-configuration');
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
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_post'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'picture', 'email'],
    });
  });
});