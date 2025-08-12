import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { SignJWT, jwtVerify, EncryptJWT, jwtDecrypt, importJWK } from 'jose';
import type { JWK } from 'jose';

// Honoの型定義に環境変数の型を追加
type Env = {
	DISCORD_CLIENT_ID: string;
	DISCORD_CLIENT_SECRET: string;
	JWT_PRIVATE_KEY: string; // RSA秘密鍵のJWK形式の文字列
	OIDC_CLIENT_ID: string;
	OIDC_CLIENT_SECRET: string;
	OIDC_REDIRECT_URI: string;
	STATE_SECRET: string; // 状態JWTの署名用共通鍵
	CODE_SECRET: string; // 認可コードJWEの暗号化用共通鍵
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
    userinfo_endpoint: `${issuer}/userinfo`, // userinfoエンドポイントを追加
    response_types_supported: ['code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email'],
    token_endpoint_auth_methods_supported: ['client_secret_post'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'picture', 'email'],
  });
});

// /jwks.json - 公開鍵を公開するエンドポイント
app.get('/jwks.json', (c) => {
  try {
    const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
    // 秘密鍵から公開鍵情報のみを抽出
    const publicJwk: JWK = {
      kty: privateJwk.kty,
      n: privateJwk.n,
      e: privateJwk.e,
      alg: 'RS256',
      kid: privateJwk.kid,
      use: 'sig',
    };
    return c.json({ keys: [publicJwk] });
  } catch (e) {
    console.error('Failed to parse JWT_PRIVATE_KEY or create public JWK:', e);
    return c.json({ error: 'Internal Server Error' }, 500);
  }
});

// /auth - 認可エンドポイント
app.get('/auth', async (c) => {
  const { response_type, client_id, redirect_uri, scope, state, nonce } = c.req.query();

  // パラメータ検証
  if (response_type !== 'code') throw new HTTPException(400, { message: 'invalid response_type' });
  if (client_id !== c.env.OIDC_CLIENT_ID) throw new HTTPException(400, { message: 'invalid client_id' });
  if (redirect_uri !== c.env.OIDC_REDIRECT_URI) throw new HTTPException(400, { message: 'invalid redirect_uri' });
  if (!scope?.includes('openid')) throw new HTTPException(400, { message: 'invalid scope' });
  if (!state) throw new HTTPException(400, { message: 'state is required' });
  if (!nonce) throw new HTTPException(400, { message: 'nonce is required' });

  const discordScopes = ['identify'];
  if (scope.includes('email')) discordScopes.push('email');

  // 元のリクエスト情報をJWTに詰めてstateとしてDiscordに渡す
  const stateJwt = await new SignJWT({
    jti: crypto.randomUUID(),
    original_state: state,
    redirect_uri: redirect_uri,
    nonce: nonce,
    scope: scope,
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

// /callback - Discordからのリダイレクト先
app.get('/callback', async (c) => {
  const { code, state } = c.req.query();
  const issuer = new URL(c.req.url).origin;

  if (!code) throw new HTTPException(400, { message: 'code is required' });
  if (!state) throw new HTTPException(400, { message: 'state is required' });

  // state (JWT) を検証
  const { payload: statePayload } = await jwtVerify(state, new TextEncoder().encode(c.env.STATE_SECRET), {
    issuer: issuer,
    audience: c.env.DISCORD_CLIENT_ID,
  });

  // Discordの認可コードをアクセストークンに交換
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

  // Discordのアクセストークン等をJWEに暗号化してOIDCの認可コードとする
  const oidcCode = await new EncryptJWT({
    discord_access_token: discordTokens.access_token,
    nonce: statePayload.nonce,
    scope: statePayload.scope,
  })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(c.env.OIDC_CLIENT_ID)
    .setExpirationTime('5m')
    .encrypt(new TextEncoder().encode(c.env.CODE_SECRET));

  // 元のクライアントにリダイレクト
  const finalRedirectUri = new URL(statePayload.redirect_uri as string);
  finalRedirectUri.searchParams.set('code', oidcCode);
  finalRedirectUri.searchParams.set('state', statePayload.original_state as string);

  return c.redirect(finalRedirectUri.toString());
});

// /token - トークンエンドポイント
app.post('/token', async (c) => {
  const issuer = new URL(c.req.url).origin;
  const body = await c.req.parseBody();

  // リクエスト検証
  if (body.grant_type !== 'authorization_code') throw new HTTPException(400, { message: 'invalid grant_type' });
  if (body.client_id !== c.env.OIDC_CLIENT_ID || body.client_secret !== c.env.OIDC_CLIENT_SECRET) {
    throw new HTTPException(401, { message: 'invalid client credentials' });
  }
  if (!body.code) throw new HTTPException(400, { message: 'code is required' });

  // 認可コード(JWE)を復号
  const { payload: codePayload } = await jwtDecrypt(body.code as string, new TextEncoder().encode(c.env.CODE_SECRET), {
    issuer: issuer,
    audience: c.env.OIDC_CLIENT_ID,
  });

  // Discordのユーザー情報を取得
  const userResponse = await fetch('https://discord.com/api/users/@me', {
    headers: { Authorization: `Bearer ${codePayload.discord_access_token}` },
  });

  if (!userResponse.ok) {
    throw new HTTPException(500, { message: 'Failed to fetch user from Discord' });
  }
  const user = (await userResponse.json()) as { id: string; username: string; avatar: string; email?: string; verified?: boolean };

  const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
  const privateKey = await importJWK(privateJwk, 'RS256');

  // IDトークンを生成
  const idToken = await new SignJWT({
    name: user.username,
    picture: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
    email: user.email,
    email_verified: user.verified,
    nonce: codePayload.nonce as string,
  })
    .setProtectedHeader({ alg: 'RS256', kid: privateJwk.kid, typ: 'JWT' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(c.env.OIDC_CLIENT_ID)
    .setSubject(user.id)
    .setExpirationTime('1h')
    .sign(privateKey);

  // UserInfoエンドポイント用のアクセストークンを生成
  const accessToken = await new SignJWT({
    // userinfoで返すクレームを内包させる
    sub: user.id,
    name: user.username,
    picture: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
    email: user.email,
    email_verified: user.verified,
    scope: codePayload.scope,
  })
    .setProtectedHeader({ alg: 'RS256', kid: privateJwk.kid, typ: 'JWT' })
    .setIssuedAt()
    .setIssuer(issuer)
    .setAudience(issuer) // Audienceは自分自身(userinfoエンドポイント)
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

// /userinfo - UserInfoエンドポイント
app.get('/userinfo', async (c) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new HTTPException(401, { message: 'Missing or invalid Authorization header' });
  }
  const token = authHeader.substring(7);
  const issuer = new URL(c.req.url).origin;

  const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
  const publicKey = await importJWK({ ...privateJwk, d: undefined }, 'RS256');

  try {
    const { payload } = await jwtVerify(token, publicKey, {
      issuer: issuer,
      audience: issuer,
    });

    // scopeに応じて返すクレームをフィルタリング
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