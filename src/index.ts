import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { SignJWT, jwtVerify, EncryptJWT, jwtDecrypt, importJWK } from 'jose';
import type { JWK, JWTPayload } from 'jose';
import { v7 as uuidv7 } from 'uuid';

interface TokenErrorResponse {
	error: string;
	error_description?: string;
	error_uri?: string;
}

interface OidcClient {
	client_secret_hash: string;
	redirect_uris: string[];
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

const getPublicJwk = (privateJwk: JWK): JWK => {
	return {
		kty: privateJwk.kty,
		crv: privateJwk.crv,
		x: privateJwk.x,
		y: privateJwk.y,
		alg: 'ES256',
		kid: privateJwk.kid,
		use: 'sig',
	};
};

// .well-known/openid-configuration
app.get('/.well-known/openid-configuration', (c) => {
	const issuer = new URL(c.req.url).origin;
	return c.json({
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

// /jwks.json - Endpoint to expose the public key
app.get('/jwks.json', (c) => {
	try {
		const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
		const publicJwk = getPublicJwk(privateJwk);
		return c.json({ keys: [publicJwk] });
	} catch (e) {
		console.error('Failed to parse JWT_PRIVATE_KEY or create public JWK:', e);
		return c.json({ error: 'Internal Server Error' }, 500);
	}
});

// /auth - Authorization endpoint
app.get('/auth', async (c) => {
	const { response_type, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method } = c.req.query();

	// Fetch client configuration from KV
	if (!client_id) {
		throw new HTTPException(400, { message: 'client_id is required' });
	}
	const client: OidcClient | null = await c.env.OIDC_CLIENTS.get(client_id, 'json');
	if (!client) {
		throw new HTTPException(400, { message: 'invalid client_id' });
	}

	// Validate redirect_uri first, as it's crucial for error redirection
	if (!client.redirect_uris.includes(redirect_uri)) {
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
	if (!scope?.includes('openid')) return redirectToError('invalid_scope', 'invalid scope');
	if (!state) return redirectToError('invalid_request', 'state is required');
	if (!code_challenge) return redirectToError('invalid_request', 'code_challenge is required');
	if (code_challenge_method && code_challenge_method !== 'S256') {
		return redirectToError('invalid_request', 'code_challenge_method is not supported');
	}

	const discordScopes = ['identify'];
	if (scope.includes('email')) discordScopes.push('email');
	// Add the new scope for reading guild members
	if (c.env.DISCORD_GUILD_IDS) {
		// Only request if guild ID is configured
		discordScopes.push('guilds.members.read');
	}

	// Pack the original request info into a JWT and pass it to Discord as state
	const stateJwt = await new SignJWT({
		jti: uuidv7(),
		original_state: state,
		redirect_uri: redirect_uri,
		nonce: nonce,
		scope: scope,
		code_challenge: code_challenge,
		code_challenge_method: code_challenge_method || 'S256',
		client_id: client_id, // Add client_id to state
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
		console.error(`Discord token exchange failed with status: ${tokenResponse.status}`, await tokenResponse.text());
		throw new HTTPException(500, { message: 'Discord token exchange failed' });
	}
	const discordTokens = (await tokenResponse.json()) as { access_token: string };

	// Encrypt the Discord access token etc. into a JWE to be used as the OIDC authorization code
	const codePrivateJsonKey = JSON.parse(c.env.CODE_PRIVATE_KEY) as JWK;
	const codePublicKey = await importJWK({
		alg: codePrivateJsonKey.alg,
		kty: codePrivateJsonKey.kty,
		crv: codePrivateJsonKey.crv,
		x: codePrivateJsonKey.x,
		y: codePrivateJsonKey.y,
	} satisfies JWK);

	const oidcCode = await new EncryptJWT({
		discord_access_token: discordTokens.access_token,
		nonce: statePayload.nonce,
		scope: statePayload.scope,
		code_challenge: statePayload.code_challenge,
		code_challenge_method: statePayload.code_challenge_method,
	})
		.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
		.setIssuedAt()
		.setIssuer(issuer)
		.setAudience(statePayload.client_id as string) // Use client_id from state
		.setExpirationTime('5m')
		.encrypt(codePublicKey);

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
	if (body.grant_type !== 'authorization_code') {
		return c.json<TokenErrorResponse>({ error: 'unsupported_grant_type', error_description: 'invalid grant_type' }, 400);
	}

	// Validate code
	if (!body.code) {
		return c.json<TokenErrorResponse>({ error: 'invalid_request', error_description: 'code is required' }, 400);
	}

	// Decrypt the authorization code (JWE) early to get codePayload
	let codePayload;
	try {
		const codePrivateKey = await importJWK(JSON.parse(c.env.CODE_PRIVATE_KEY) as JWK);
		// Decrypt without audience verification first to get the client_id from the payload
		const { payload: tempPayload } = await jwtDecrypt(body.code as string, codePrivateKey, {
			issuer: issuer,
		});

		// Now verify the audience using the client_id from the request body if present,
		// or fallback to the audience from the token.
		const clientIdFromRequest = body.client_id as string | undefined;
		const audience = tempPayload.aud as string;

		if (clientIdFromRequest && clientIdFromRequest !== audience) {
			throw new Error('client_id mismatch');
		}

		codePayload = tempPayload;
	} catch (e) {
		console.error(e);
		return c.json<TokenErrorResponse>({ error: 'invalid_grant', error_description: 'invalid authorization code' }, 400);
	}

	const client_id = codePayload.aud as string;
	const isPkceFlowCode = !!codePayload.code_challenge;

	// Handle PKCE vs. non-PKCE flows
	if (isPkceFlowCode) {
		// The authorization code was issued for a PKCE flow
		if (!body.code_verifier) {
			// But the token request is missing code_verifier
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
	} else {
		// The authorization code was issued for a non-PKCE flow
		if (body.code_verifier) {
			// But the token request includes code_verifier
			return c.json<TokenErrorResponse>(
				{ error: 'invalid_request', error_description: 'PKCE code_verifier not expected for non-PKCE flow' },
				400,
			);
		}
		// For non-PKCE flow, validate client_id and client_secret
		const client: OidcClient | null = await c.env.OIDC_CLIENTS.get(client_id, 'json');
		if (!client) {
			return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'invalid client_id' }, 401);
		}

		// Validate client_secret by hashing it
		if (!body.client_secret || typeof body.client_secret !== 'string') {
			return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'client_secret is required' }, 401);
		}
		const secretDigest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body.client_secret as string));
		const secretHash = Array.from(new Uint8Array(secretDigest))
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('');

		if (secretHash !== client.client_secret_hash) {
			return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'client_secret is invalid' }, 401);
		}
	}

	// Fetch user information from Discord
	const userResponse = await fetch('https://discord.com/api/users/@me', {
		headers: { Authorization: `Bearer ${codePayload.discord_access_token}` },
	});

	if (!userResponse.ok) {
		console.error(`Failed to fetch user from Discord with status: ${userResponse.status}`, await userResponse.text());
		return c.json<TokenErrorResponse>({ error: 'server_error', error_description: 'Failed to fetch user from Discord' }, 500);
	}
	const user = (await userResponse.json()) as { id: string; username: string; avatar: string; email?: string; verified?: boolean };

	let userRoles: string[] = [];
	if (typeof c.env.DISCORD_GUILD_IDS === 'string' && c.env.DISCORD_GUILD_IDS.trim().length > 0) {
		const guildIds = c.env.DISCORD_GUILD_IDS.split(',')
			.map((id) => id.trim())
			.filter((id) => id.length > 0);
		if (guildIds.length > 0) {
			const memberPromises = guildIds.map(async (guildId) => {
				const res = await fetch(`https://discord.com/api/users/@me/guilds/${guildId}/member`, {
					headers: { Authorization: `Bearer ${codePayload.discord_access_token}` },
				});
				if (res.ok) {
					return (await res.json()) as { roles: string[] };
				} else {
					console.warn(`Failed to fetch guild member roles for guild ${guildId} with status: ${res.status}`, await res.text());
					return null;
				}
			});

			const memberResults = await Promise.all(memberPromises);
			userRoles = memberResults.filter((member): member is { roles: string[] } => member !== null).flatMap((member) => member.roles);
		}
	}

	const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
	const privateKey = await importJWK(privateJwk, 'ES256');

	const generateToken = async (payload: JWTPayload, audience: string, expiresIn: string) => {
		return await new SignJWT({ ...payload, sub: user.id })
			.setProtectedHeader({ alg: 'ES256', kid: privateJwk.kid, typ: 'JWT' })
			.setIssuedAt()
			.setIssuer(issuer)
			.setAudience(audience)
			.setSubject(user.id)
			.setExpirationTime(expiresIn)
			.sign(privateKey);
	};

	// Generate ID token
	const idToken = await generateToken(
		{
			name: user.username,
			picture: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
			email: user.email,
			email_verified: user.verified,
			nonce: codePayload.nonce as string,
			roles: userRoles, // Add roles claim here
		},
		client_id,
		'1h',
	);

	// Generate access token for the UserInfo endpoint
	const accessToken = await generateToken(
		{
			// Include claims to be returned by userinfo
			name: user.username,
			picture: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
			email: user.email,
			email_verified: user.verified,
			scope: codePayload.scope,
		},
		issuer, // Audience is the provider itself (the userinfo endpoint)
		'1h',
	);

	return c.json({
		access_token: accessToken,
		token_type: 'Bearer',
		expires_in: 3600,
		scope: codePayload.scope,
		id_token: idToken,
	});
});

export default app;
