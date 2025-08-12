import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { SignJWT, jwtVerify, EncryptJWT, jwtDecrypt, importJWK } from 'jose';
import type { JWK } from 'jose';
import { v7 as uuidv7 } from 'uuid';

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
  if (!nonce) return redirectToError('invalid_request', 'nonce is required');
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
    .sign(new TextEncoder().encode(c.env.STATE_SECRET));

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
  const { payload: statePayload } = await jwtVerify(state, new TextEncoder().encode(c.env.STATE_SECRET), {
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
    console.error('Discord token exchange failed:', await tokenResponse.json());
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
    .encrypt(new TextEncoder().encode(c.env.CODE_SECRET));

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

  // Validate request
  if (body.grant_type !== 'authorization_code') throw new HTTPException(400, { message: 'invalid grant_type' });
  if (body.client_id !== c.env.OIDC_CLIENT_ID || body.client_secret !== c.env.OIDC_CLIENT_SECRET) {
    throw new HTTPException(401, { message: 'invalid client credentials' });
  }
  if (!body.code) throw new HTTPException(400, { message: 'code is required' });

  // Decrypt the authorization code (JWE)
  const { payload: codePayload } = await jwtDecrypt(body.code as string, new TextEncoder().encode(c.env.CODE_SECRET), {
    issuer: issuer,
    audience: c.env.OIDC_CLIENT_ID,
  });

  // PKCE verification
  const code_verifier = body.code_verifier as string;
  if (!code_verifier) throw new HTTPException(400, { message: 'code_verifier is required' });
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code_verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  if (challenge !== codePayload.code_challenge) {
    throw new HTTPException(401, { message: 'invalid code_verifier' });
  }

  // Fetch user information from Discord
  const userResponse = await fetch('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${codePayload.discord_access_token}` },
  });

  if (!userResponse.ok) {
    throw new HTTPException(500, { message: 'Failed to fetch user from Discord' });
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

// /userinfo - UserInfo endpoint
app.get('/userinfo', async (c) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new HTTPException(401, { message: 'Missing or invalid Authorization header' });
  }
  const token = authHeader.substring(7);
  const issuer = new URL(c.req.url).origin;

  const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
  const publicKey = await importJWK({ ...privateJwk, d: undefined }, 'ES256');

  try {
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: issuer,
      audience: issuer,
    });

    // Filter claims to be returned based on scope
    const claims: { [key: string]: any } = { sub: payload.sub };
    const scopes = (payload.scope as string).split(' ');

    if (scopes.includes('profile')) {
      claims.name = payload.name;
      claims.picture = payload.picture;
    }
    if (scopes.includes('email')) {
      claims.email = payload.email;
      claims.email_verified = payload.email_verified;
    }

    return c.json(claims);
  } catch (err) {
    console.error('userinfo token verification failed', err);
    throw new HTTPException(401, { message: 'Invalid token' });
  }
});

export default app;
