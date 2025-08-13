import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { SignJWT, jwtVerify, EncryptJWT, jwtDecrypt, importJWK } from 'jose';
import type { JWK } from 'jose';
import { v7 as uuidv7 } from 'uuid';

interface TokenErrorResponse {
  error: string;
  error_description?: string;
  error_uri?: string;
}

const base64urlToUint8Array = (base64url: string): Uint8Array => {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(base64);
  const uint8Array = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    uint8Array[i] = bin.charCodeAt(i);
  }
  return uint8Array;
};

const app = new Hono<{ Bindings: Env }>();

// .well-known/openid-configuration
app.get('/.well-known/openid-configuration', (c) => {
  const issuer = new URL(c.req.url).origin;
  return c.json({
    issuer: issuer,
    authorization_endpoint: `${issuer}/auth`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks.json`,
    userinfo_endpoint: `${issuer}/userinfo`, // Add userinfo endpoint
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['ES256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'picture', 'email'],
    code_challenge_methods_supported: ['S256'],
  });
});

// /jwks.json - Endpoint to expose the public key
app.get('/jwks.json', (c) => {
  try {
    const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
    // Extract only public key information from the private key
    const publicJwk: JWK = {
      kty: privateJwk.kty,
      crv: privateJwk.crv,
      x: privateJwk.x,
      y: privateJwk.y,
      alg: 'ES256',
      kid: privateJwk.kid,
      use: 'sig',
    };
    return c.json({ keys: [publicJwk] });
  } catch (e) {
    console.error('Failed to parse JWT_PRIVATE_KEY or create public JWK:', e);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

// /auth - Authorization endpoint
app.get('/auth', async (c) => {
  const { response_type, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method } =
    c.req.query();

  // Validate parameters
  // Validate redirect_uri first, as it's crucial for error redirection
  if (redirect_uri !== c.env.OIDC_REDIRECT_URI) {
    throw new HTTPException(400, { message: 'invalid redirect_uri' });
  }

  const redirectToError = (error: string, error_description: string) => {
    // At this point, redirect_uri is guaranteed to be valid due to the check above
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('error', error);
    redirectUrl.searchParams.set('error_description', error_description);
    if (state) {
      redirectUrl.searchParams.set('state', state);
    }
    return c.redirect(redirectUrl.toString());
  };

  if (response_type !== 'code') return redirectToError('invalid_request', 'invalid response_type');
  if (client_id !== c.env.OIDC_CLIENT_ID) return redirectToError('unauthorized_client', 'invalid client_id');
  if (!scope?.includes('openid')) return redirectToError('invalid_scope', 'invalid scope');
  if (!state) return redirectToError('invalid_request', 'state is required');
  if (!code_challenge) return redirectToError('invalid_request', 'code_challenge is required');
  if (code_challenge_method && code_challenge_method !== 'S256') {
    return redirectToError('invalid_request', 'code_challenge_method is not supported');
  }

  const discordScopes = ['identify'];
  if (scope.includes('email')) discordScopes.push('email');

  // Pack the original request info into a JWT and pass it to Discord as state
  const stateJwt = await new SignJWT({
    jti: uuidv7(),
    original_state: state,
    redirect_uri: redirect_uri,
    nonce: nonce,
    scope: scope,
    code_challenge: code_challenge,
    code_challenge_method: code_challenge_method || 'S256',
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setIssuer(new URL(c.req.url).origin)
    .setAudience(c.env.DISCORD_CLIENT_ID)
    .setExpirationTime('10m')
    .sign(base64urlToUint8Array(c.env.STATE_SECRET));

  const discordAuthUrl = new URL('https://discord.com/api/oauth2/authorize');
  discordAuthUrl.searchParams.set('client_id', c.env.DISCORD_CLIENT_ID);
  discordAuthUrl.searchParams.set('redirect_uri', new URL('/callback', c.req.url).toString());
  discordAuthUrl.searchParams.set('response_type', 'code');
  discordAuthUrl.searchParams.set('scope', discordScopes.join(' '));
  discordAuthUrl.searchParams.set('state', stateJwt);

  return c.redirect(discordAuthUrl.toString());
});

// /callback - Redirect target from Discord
app.get('/callback', async (c) => {
  const { code, state } = c.req.query();
  const issuer = new URL(c.req.url).origin;

  if (!code) throw new HTTPException(400, { message: 'code is required' });
  if (!state) throw new HTTPException(400, { message: 'state is required' });

  // Verify the state (JWT)
  const { payload: statePayload } = await jwtVerify(state, base64urlToUint8Array(c.env.STATE_SECRET), {
    issuer: issuer,
    audience: c.env.DISCORD_CLIENT_ID,
  });

  // Exchange the Discord authorization code for an access token
  const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      client_id: c.env.DISCORD_CLIENT_ID,
      client_secret: c.env.DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: code,
      redirect_uri: new URL('/callback', c.req.url).toString(),
    }),
  });

  if (!tokenResponse.ok) {
    console.error('Discord token exchange failed:', await tokenResponse.text());
    throw new HTTPException(500, { message: 'Discord token exchange failed' });
  }
  const discordTokens = (await tokenResponse.json()) as { access_token: string };

  // Encrypt the Discord access token etc. into a JWE to be used as the OIDC authorization code
  const oidcCode = await new EncryptJWT({
    discord_access_token: discordTokens.access_token,
    nonce: statePayload.nonce,
    scope: statePayload.scope,
    code_challenge: statePayload.code_challenge,
    code_challenge_method: statePayload.code_challenge_method,
  })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(c.env.OIDC_CLIENT_ID)
    .setExpirationTime('5m')
    .encrypt(base64urlToUint8Array(c.env.CODE_SECRET));

  // Redirect to the original client
  const finalRedirectUri = new URL(statePayload.redirect_uri as string);
  finalRedirectUri.searchParams.set('code', oidcCode);
  finalRedirectUri.searchParams.set('state', statePayload.original_state as string);

  return c.redirect(finalRedirectUri.toString());
});

// /token - Token endpoint
app.post('/token', async (c) => {
  const issuer = new URL(c.req.url).origin;
  const body = await c.req.parseBody();
	console.log(await c.req.header("content-type"))
	console.log(await c.req.text())

  // Validate request
  if (body.grant_type !== 'authorization_code') {
    return c.json<TokenErrorResponse>({ error: 'unsupported_grant_type', error_description: 'invalid grant_type' }, 400);
  }

  const isPkceFlowRequest = !!body.code_verifier;

  // Validate client_id
  if (!isPkceFlowRequest && body.client_id !== c.env.OIDC_CLIENT_ID) {
    return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'invalid client_id' }, 401);
  }

  // Validate code
  if (!body.code) {
    return c.json<TokenErrorResponse>({ error: 'invalid_request', error_description: 'code is required' }, 400);
  }

	if (!isPkceFlowRequest && body.client_secret !== c.env.OIDC_CLIENT_SECRET) {
    return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'client_secret is required or invalid' }, 401);
	}

  // Decrypt the authorization code (JWE) early to get codePayload
  let codePayload;
  try {
    const { payload } = await jwtDecrypt(body.code as string, base64urlToUint8Array(c.env.CODE_SECRET), {
      issuer: issuer,
      audience: c.env.OIDC_CLIENT_ID,
    });
    codePayload = payload;
  } catch (e) {
    return c.json<TokenErrorResponse>({ error: 'invalid_grant', error_description: 'invalid authorization code' }, 400);
  }

  const isPkceFlowCode = !!codePayload.code_challenge;

  // Handle PKCE vs. non-PKCE flows
  if (isPkceFlowCode) { // The authorization code was issued for a PKCE flow
    if (!isPkceFlowRequest) { // But the token request is missing code_verifier
      return c.json<TokenErrorResponse>({ error: 'invalid_request', error_description: 'code_verifier is required for PKCE flow' }, 400);
    }
    // Perform PKCE challenge verification
    const code_verifier = body.code_verifier as string;
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code_verifier));
    const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');
    if (challenge !== codePayload.code_challenge) {
      return c.json<TokenErrorResponse>({ error: 'invalid_grant', error_description: 'invalid code_verifier' }, 400);
    }
  } else { // The authorization code was issued for a non-PKCE flow
    if (isPkceFlowRequest) { // But the token request includes code_verifier
      return c.json<TokenErrorResponse>({ error: 'invalid_request', error_description: 'PKCE code_verifier not expected for non-PKCE flow' }, 400);
    }
  }

  // Fetch user information from Discord
  const userResponse = await fetch('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${codePayload.discord_access_token}` },
  });

  if (!userResponse.ok) {
    console.error('Discord token exchange failed:', await userResponse.text());
    return c.json<TokenErrorResponse>({ error: 'server_error', error_description: 'Failed to fetch user from Discord' }, 500);
  }
  const user = (await userResponse.json()) as { id: string; username: string; avatar: string; email?: string; verified?: boolean };

  const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
  const privateKey = await importJWK(privateJwk, 'ES256');

  // Generate ID token
  const idToken = await new SignJWT({
    name: user.username,
    picture: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
    email: user.email,
    email_verified: user.verified,
    nonce: codePayload.nonce as string,
  })
    .setProtectedHeader({ alg: 'ES256', kid: privateJwk.kid, typ: 'JWT' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(c.env.OIDC_CLIENT_ID)
    .setSubject(user.id)
    .setExpirationTime('1h')
    .sign(privateKey);

  // Generate access token for the UserInfo endpoint
  const accessToken = await new SignJWT({
    // Include claims to be returned by userinfo
    sub: user.id,
    name: user.username,
    picture: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
    email: user.email,
    email_verified: user.verified,
    scope: codePayload.scope,
  })
    .setProtectedHeader({ alg: 'ES256', kid: privateJwk.kid, typ: 'JWT' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(issuer) // Audience is the provider itself (the userinfo endpoint)
    .setSubject(user.id)
    .setExpirationTime('1h')
    .sign(privateKey);

  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 3600,
    scope: codePayload.scope,
    id_token: idToken,
  });
});

export default app;
