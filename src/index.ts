import { Hono } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { SignJWT, importJWK } from 'jose';
import type { JWK, JWTPayload } from 'jose';
import { exchangeCode, getDiscordUser, getDiscordUserRoles, DiscordAPIError } from './discord';
import { type StatePayload, type CodePayload, encodeState, decodeState, encodeCode, decodeCode } from './coder';

interface TokenErrorResponse {
	error: string;
	error_description?: string;
	error_uri?: string;
}

interface OidcClient {
	client_secret_hash: string;
	redirect_uris: string[];
}

// /.well-known/openid-configuration
interface OpenIDConfiguration {
	issuer: string;
	authorization_endpoint: string;
	token_endpoint: string;
	jwks_uri: string;
	userinfo_endpoint: string;
	response_types_supported: string[];
	subject_types_supported: string[];
	id_token_signing_alg_values_supported: string[];
	scopes_supported: string[];
	token_endpoint_auth_methods_supported: string[];
	claims_supported: string[];
	code_challenge_methods_supported: string[];
}

// /.well-known/jwks.json
interface JWKS {
	keys: JWK[];
}

// /token
export interface TokenResponse {
	access_token: string;
	token_type: 'Bearer';
	expires_in: number;
	scope: string;
	id_token: string;
}

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

const getCodePublicJwk = (privateJwk: JWK): JWK => {
	return {
		kty: privateJwk.kty,
		crv: privateJwk.crv,
		x: privateJwk.x,
		y: privateJwk.y,
		alg: 'ECDH-ES',
		kid: privateJwk.kid,
		use: 'enc',
	};
};

// .well-known/openid-configuration
app.get('/.well-known/openid-configuration', (c) => {
	const issuer = new URL(c.req.url).origin;
	return c.json({
		issuer: issuer,
		authorization_endpoint: `${issuer}/auth`,
		token_endpoint: `${issuer}/token`,
		jwks_uri: `${issuer}/.well-known/jwks.json`,
		userinfo_endpoint: `${issuer}/userinfo`,
		response_types_supported: ['code'],
		subject_types_supported: ['public'],
		id_token_signing_alg_values_supported: ['ES256'],
		scopes_supported: ['openid', 'profile', 'email'],
		token_endpoint_auth_methods_supported: ['client_secret_post'],
		claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'nonce', 'name', 'picture', 'email'],
		code_challenge_methods_supported: ['S256'],
	} satisfies OpenIDConfiguration);
});

// /.well-known/jwks.json - Endpoint to expose the public key
app.get('/.well-known/jwks.json', (c) => {
	try {
		const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK;
		const publicJwk = getPublicJwk(privateJwk);
		return c.json({ keys: [publicJwk] } satisfies JWKS);
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
	const stateJwt = await encodeState(
		{
			original_state: state,
			redirect_uri: redirect_uri,
			nonce: nonce,
			scope: scope,
			code_challenge: code_challenge,
			code_challenge_method: code_challenge_method || 'S256',
			client_id: client_id,
		},
		c.env.STATE_SECRET,
		new URL(c.req.url).origin,
		c.env.DISCORD_CLIENT_ID,
	);

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
	const statePayload = await decodeState(state, c.env.STATE_SECRET, issuer, c.env.DISCORD_CLIENT_ID);

	// Exchange the Discord authorization code for an access token
	let discordTokens;
	try {
		discordTokens = await exchangeCode(
			c.env.DISCORD_CLIENT_ID,
			c.env.DISCORD_CLIENT_SECRET,
			code,
			new URL('/callback', c.req.url).toString(),
		);
	} catch (e) {
		if (e instanceof DiscordAPIError) {
			throw new HTTPException(500, { message: e.message });
		}
		throw e;
	}

	// Encrypt the Discord access token etc. into a JWE to be used as the OIDC authorization code
	const codePrivateJsonKey = JSON.parse(c.env.CODE_PRIVATE_KEY) as JWK;
	const oidcCode = await encodeCode(
		{
			discord_access_token: discordTokens.access_token,
			nonce: statePayload.nonce,
			scope: statePayload.scope,
			code_challenge: statePayload.code_challenge,
			code_challenge_method: statePayload.code_challenge_method,
		},
		getCodePublicJwk(codePrivateJsonKey),
		issuer,
		statePayload.client_id,
	);

	// Redirect to the original client
	const finalRedirectUri = new URL(statePayload.redirect_uri);
	finalRedirectUri.searchParams.set('code', oidcCode);
	finalRedirectUri.searchParams.set('state', statePayload.original_state);

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
	let codePayload: CodePayload;
	try {
		const codePrivateKey = JSON.parse(c.env.CODE_PRIVATE_KEY) as JWK;
		const tempPayload = await decodeCode(body.code as string, codePrivateKey, issuer);

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

	try {
		// Fetch user information from Discord
		const user = await getDiscordUser(codePayload.discord_access_token as string);

		let userRoles: string[] = [];
		if (typeof c.env.DISCORD_GUILD_IDS === 'string' && c.env.DISCORD_GUILD_IDS.trim().length > 0) {
			const guildIds = c.env.DISCORD_GUILD_IDS.split(',').map((id) => id.trim());
			userRoles = await getDiscordUserRoles(codePayload.discord_access_token as string, guildIds);
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
				name: user.global_name || user.username,
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
				name: user.global_name || user.username,
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
		} satisfies TokenResponse);
	} catch (e) {
		if (e instanceof DiscordAPIError) {
			return c.json<TokenErrorResponse>({ error: 'server_error', error_description: e.message }, 500);
		}
		if (e instanceof HTTPException) {
			return c.json<TokenErrorResponse>({ error: 'server_error', error_description: e.message }, e.status);
		}
		console.error(e);
		return c.json<TokenErrorResponse>({ error: 'server_error', error_description: 'An unexpected error occurred' }, 500);
	}
});

export default app;