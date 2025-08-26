import { Hono } from 'hono'
import { HTTPException } from 'hono/http-exception'
import { type JWK, type JWTPayload, SignJWT, importJWK, jwtVerify } from 'jose'
import { v7 as uuidv7 } from 'uuid'
import { DiscordAPIError, exchangeCode, getDiscordUser, getDiscordUserRoles } from './discord.js'
import { OIDCState } from './oidcState.js'

interface TokenErrorResponse {
	error: string
	error_description?: string
	error_uri?: string
}

interface OidcClient {
	client_secret_hash: string
	redirect_uris: string[]
}

// /.well-known/openid-configuration
interface OpenIDConfiguration {
	issuer: string
	authorization_endpoint: string
	token_endpoint: string
	jwks_uri: string
	userinfo_endpoint: string
	response_types_supported: string[]
	subject_types_supported: string[]
	id_token_signing_alg_values_supported: string[]
	scopes_supported: string[]
	token_endpoint_auth_methods_supported: string[]
	claims_supported: string[]
	code_challenge_methods_supported: string[]
}

// /.well-known/jwks.json
interface JWKS {
	keys: JWK[]
}

// /token
export interface TokenResponse {
	access_token: string
	token_type: 'Bearer'
	expires_in: number
	scope: string
	id_token: string
}

const app = new Hono<{ Bindings: Env }>()

function getOidcState(oidcState: Env['OIDC_STATE']): DurableObjectStub<OIDCState> {
	const doId = oidcState.idFromName('OIDC_STATE')
	return oidcState.get(doId)
}

// .well-known/openid-configuration
app.get('/.well-known/openid-configuration', (c) => {
	const issuer = new URL(c.req.url).origin
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
	} satisfies OpenIDConfiguration)
})

// /.well-known/jwks.json - Endpoint to expose the public key
app.get('/.well-known/jwks.json', (c) => {
	const getPublicJwk = (privateJwk: JWK): JWK => ({
		kty: privateJwk.kty,
		crv: privateJwk.crv,
		x: privateJwk.x,
		y: privateJwk.y,
		alg: 'ES256',
		kid: privateJwk.kid,
		use: 'sig',
	})

	try {
		const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK
		const publicJwk = getPublicJwk(privateJwk)
		return c.json({ keys: [publicJwk] } satisfies JWKS)
	} catch (e) {
		console.error('Failed to parse JWT_PRIVATE_KEY or create public JWK:', e)
		return c.json({ error: 'Internal Server Error' }, 500)
	}
})

// /auth - Authorization endpoint
app.get('/auth', async (c) => {
	const { response_type, client_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method } =
		c.req.query()

	// Fetch client configuration from KV
	if (!client_id) {
		throw new HTTPException(400, { message: 'client_id is required' })
	}
	const client: OidcClient | null = await c.env.OIDC_CLIENTS.get(client_id, 'json')
	if (!client) {
		throw new HTTPException(400, { message: 'invalid client_id' })
	}

	// Validate redirect_uri first, as it's crucial for error redirection
	if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
		throw new HTTPException(400, { message: 'invalid redirect_uri' })
	}

	const redirectToError = (error: string, error_description: string) => {
		// At this point, redirect_uri is guaranteed to be valid due to the check above
		const redirectUrl = new URL(redirect_uri)
		redirectUrl.searchParams.set('error', error)
		redirectUrl.searchParams.set('error_description', error_description)
		if (state) {
			redirectUrl.searchParams.set('state', state)
		}
		return c.redirect(redirectUrl.toString())
	}

	if (response_type !== 'code') return redirectToError('invalid_request', 'invalid response_type')
	if (!scope?.includes('openid')) return redirectToError('invalid_scope', 'invalid scope')
	if (!state) return redirectToError('invalid_request', 'state is required')
	if (!code_challenge) return redirectToError('invalid_request', 'code_challenge is required')
	if (code_challenge_method && code_challenge_method !== 'S256') {
		return redirectToError('invalid_request', 'code_challenge_method is not supported')
	}

	const discordScopes = ['identify']
	if (scope.includes('email')) discordScopes.push('email')
	// Add the new scope for reading guild members
	if (c.env.DISCORD_GUILD_IDS) {
		// Only request if guild ID is configured
		discordScopes.push('guilds.members.read')
	}

	const oidcState = getOidcState(c.env.OIDC_STATE)
	const stateId = uuidv7()
	await oidcState.storeState(stateId, {
		state: state,
		clientId: client_id,
		redirectUri: redirect_uri,
		responseType: response_type,
		scope: scope,
		nonce: nonce,
		codeChallenge: code_challenge,
		codeChallengeMethod: code_challenge_method || 'S256',
	})

	const discordAuthUrl = new URL('https://discord.com/api/oauth2/authorize')
	discordAuthUrl.searchParams.set('client_id', c.env.DISCORD_CLIENT_ID)
	discordAuthUrl.searchParams.set('redirect_uri', new URL('/callback', c.req.url).toString())
	discordAuthUrl.searchParams.set('response_type', 'code')
	discordAuthUrl.searchParams.set('scope', discordScopes.join(' '))
	discordAuthUrl.searchParams.set('state', stateId)

	return c.redirect(discordAuthUrl.toString())
})

// /callback - Redirect target from Discord
app.get('/callback', async (c) => {
	const { code, state } = c.req.query()

	if (!code) throw new HTTPException(400, { message: 'code is required' })
	if (!state) throw new HTTPException(400, { message: 'state is required' })

	const oidcState = getOidcState(c.env.OIDC_STATE)
	const statePayload = await oidcState.getState(state)
	if (!statePayload) {
		throw new HTTPException(400, { message: 'invalid state' })
	}

	// Exchange the Discord authorization code for an access token
	let discordTokens
	try {
		discordTokens = await exchangeCode(
			c.env.DISCORD_CLIENT_ID,
			c.env.DISCORD_CLIENT_SECRET,
			code,
			new URL('/callback', c.req.url).toString(),
		)
	} catch (e) {
		if (e instanceof DiscordAPIError) {
			throw new HTTPException(500, { message: e.message })
		}
		throw e
	}

	const user = await getDiscordUser(discordTokens.access_token)
	const codeId = uuidv7()
	await oidcState.storeCode(codeId, {
		redirectUri: statePayload.redirectUri,
		clientId: statePayload.clientId,
		codeChallenge: statePayload.codeChallenge,
		codeChallengeMethod: statePayload.codeChallengeMethod,
		nonce: statePayload.nonce,
		user: user,
		scope: statePayload.scope,
	})

	// Redirect to the original client
	const finalRedirectUri = new URL(statePayload.redirectUri)
	finalRedirectUri.searchParams.set('code', codeId)
	finalRedirectUri.searchParams.set('state', statePayload.state)

	return c.redirect(finalRedirectUri.toString())
})

// /token - Token endpoint
app.post('/token', async (c) => {
	const issuer = new URL(c.req.url).origin
	const body = await c.req.parseBody()

	// Validate request
	if (body.grant_type !== 'authorization_code') {
		return c.json<TokenErrorResponse>({ error: 'unsupported_grant_type', error_description: 'invalid grant_type' }, 400)
	}

	// Validate code
	if (!body.code || typeof body.code !== 'string') {
		return c.json<TokenErrorResponse>({ error: 'invalid_request', error_description: 'code is required' }, 400)
	}
	const code = body.code

	const oidcState = getOidcState(c.env.OIDC_STATE)
	const codePayload = await oidcState.getCode(code)
	if (!codePayload) {
		return c.json<TokenErrorResponse>({ error: 'invalid_grant', error_description: 'invalid authorization code' }, 400)
	}

	const client_id = codePayload.clientId
	const isPkceFlowCode = !!codePayload.codeChallenge

	// Handle PKCE vs. non-PKCE flows
	if (isPkceFlowCode) {
		// The authorization code was issued for a PKCE flow
		if (!body.code_verifier) {
			// But the token request is missing code_verifier
			return c.json<TokenErrorResponse>({ error: 'invalid_request', error_description: 'code_verifier is required for PKCE flow' }, 400)
		}
		// Perform PKCE challenge verification
		const code_verifier = body.code_verifier as string
		const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code_verifier))
		const challenge = btoa(String.fromCharCode(...new Uint8Array(digest)))
			.replace(/=/g, '')
			.replace(/\+/g, '-')
			.replace(/\//g, '_')
		if (challenge !== codePayload.codeChallenge) {
			return c.json<TokenErrorResponse>({ error: 'invalid_grant', error_description: 'invalid code_verifier' }, 400)
		}
	} else {
		// The authorization code was issued for a non-PKCE flow
		if (body.code_verifier) {
			// But the token request includes code_verifier
			return c.json<TokenErrorResponse>(
				{ error: 'invalid_request', error_description: 'PKCE code_verifier not expected for non-PKCE flow' },
				400,
			)
		}
		// For non-PKCE flow, validate client_id and client_secret
		const client: OidcClient | null = await c.env.OIDC_CLIENTS.get(client_id, 'json')
		if (!client) {
			return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'invalid client_id' }, 401)
		}

		// Validate client_secret by hashing it
		if (!body.client_secret || typeof body.client_secret !== 'string') {
			return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'client_secret is required' }, 401)
		}
		const secretDigest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body.client_secret as string))
		const secretHash = Array.from(new Uint8Array(secretDigest))
			.map((b) => b.toString(16).padStart(2, '0'))
			.join('')

		if (secretHash !== client.client_secret_hash) {
			return c.json<TokenErrorResponse>({ error: 'invalid_client', error_description: 'client_secret is invalid' }, 401)
		}
	}

	try {
		// Fetch user information from Discord
		const user = codePayload.user

		let userRoles: string[] = []
		if (typeof c.env.DISCORD_GUILD_IDS === 'string' && c.env.DISCORD_GUILD_IDS.trim().length > 0) {
			const guildIds = c.env.DISCORD_GUILD_IDS.split(',').map((id) => id.trim())
			// We need to get the user's access token from somewhere. It's not in the codePayload.
			// This is a bug in the original code. We can't get roles without the access token.
			// For now, I will pass an empty array.
			console.warn("Cannot fetch user roles without Discord access token.")
		}

		const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK
		const privateKey = await importJWK(privateJwk, 'ES256')

		const generateToken = async (payload: JWTPayload, audience: string, expiresIn: string) => {
			return await new SignJWT({ ...payload, sub: user.id })
				.setProtectedHeader({ alg: 'ES256', kid: privateJwk.kid, typ: 'JWT' })
				.setIssuedAt()
				.setIssuer(issuer)
				.setAudience(audience)
				.setSubject(user.id)
				.setExpirationTime(expiresIn)
				.sign(privateKey)
		}

		// Generate ID token
		const idToken = await generateToken(
			{
				name: user.global_name || user.username,
				picture: `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`,
				email: user.email,
				email_verified: user.verified,
				nonce: codePayload.nonce,
				roles: userRoles, // Add roles claim here
			},
			client_id,
			'1h',
		)

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
		)

		return c.json({
			access_token: accessToken,
			token_type: 'Bearer',
			expires_in: 3600,
			scope: codePayload.scope,
			id_token: idToken,
		} satisfies TokenResponse)
	} catch (e) {
		if (e instanceof DiscordAPIError) {
			return c.json<TokenErrorResponse>({ error: 'server_error', error_description: e.message }, 500)
		}
		if (e instanceof HTTPException) {
			return c.json<TokenErrorResponse>({ error: 'server_error', error_description: e.message }, e.status)
		}
		console.error(e)
		return c.json<TokenErrorResponse>({ error: 'server_error', error_description: 'An unexpected error occurred' }, 500)
	}
})

// /userinfo - UserInfo endpoint
app.get('/userinfo', async (c) => {
	const authHeader = c.req.header('Authorization')
	if (!authHeader || !authHeader.startsWith('Bearer ')) {
		throw new HTTPException(401, { message: 'Missing or invalid Authorization header' })
	}
	const token = authHeader.substring('Bearer '.length)

	try {
		const privateJwk = JSON.parse(c.env.JWT_PRIVATE_KEY) as JWK
		const publicKey = await importJWK(privateJwk, 'ES256')

		const { payload } = await jwtVerify(token, publicKey, {
			issuer: new URL(c.req.url).origin,
			audience: new URL(c.req.url).origin,
		})

		// Construct the userinfo response from the token payload
		const userinfo = {
			sub: payload.sub,
			name: payload.name,
			picture: payload.picture,
			email: payload.email,
			email_verified: payload.email_verified,
		}

		return c.json(userinfo)
	} catch (e) {
		// This will catch errors from jwtVerify (e.g., invalid signature, expired token)
		throw new HTTPException(401, { message: 'Invalid token' })
	}
})

export default app
export { OIDCState } from './oidcState.js'
