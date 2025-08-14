import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { EncryptJWT, importJWK, jwtVerify } from 'jose';
import { TextEncoder } from 'util';

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
	const MOCK_CODE_PRIVATE_KEY =
		'{"kty":"EC","x":"BNo3Mq2cH_F3gjVMNarajk6CEe7ACnog1AYEnUO0N8g","y":"PsSNgkm5Jpy8p8rc8HH0U9fa4-dCEJG81kxI2yQArH8","crv":"P-256","d":"y2y53r0Z9e2OorJwFDlezhLBNv7qekxDOft2dzbFTRo","use":"enc","alg":"ECDH-ES+A256KW","kid":"0198a59b-82af-765a-b25b-3e378297a2a0"}';
	const MOCK_JWT_PRIVATE_KEY =
		'{"kty":"EC","x":"Vb5MIA7WsDQzqjsV8udvwNIvhZ7HWZxzyAstzCyR5xk","y":"8Lc4Y0Ke0wBH9T7v6179zjaCeCaiDNRK2OtUA_YVbn8","crv":"P-256","d":"teLx5xvxFjeXua4rfvaxegX2andBE2F8Ysa8qLNf8Bo","use":"sig","alg":"ES256","kid":"0198a5b0-a018-7756-a4e3-ebf3f0dd9cfe"}';

	beforeEach(() => {
		// Mock the global fetch function for Discord API calls
		global.fetch = vi.fn((input: RequestInfo | URL) => {
			if (typeof input === 'string' && input.startsWith('https://discord.com/api/users/@me')) {
				return Promise.resolve(
					new Response(
						JSON.stringify({
							id: 'discord_user_id',
							username: 'testuser',
							avatar: 'testavatar',
							email: 'test@example.com',
							verified: true,
						}),
						{ status: 200 },
					),
				);
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
		const codePrivateKey = JSON.parse(MOCK_CODE_PRIVATE_KEY);
		const codePublicKey = await importJWK({ ...codePrivateKey, d: undefined });
		const oidcCode = await new EncryptJWT({
			discord_access_token: discordAccessToken,
			nonce: nonce,
			scope: scope,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
		})
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_OIDC_CLIENT_ID)
			.setExpirationTime('5m')
			.encrypt(codePublicKey);

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

	it('should successfully exchange authorization code for tokens with PKCE without client_id', async () => {
		const discordAccessToken = 'mock_discord_access_token';
		const nonce = 'test_nonce';
		const scope = 'openid profile email';
		const codeVerifier = 'test_code_verifier_123456789012345678901234567890';
		const codeChallenge = await generateCodeChallenge(codeVerifier);

		// Create a mock OIDC authorization code (JWE)
		const codePrivateKey = JSON.parse(MOCK_CODE_PRIVATE_KEY);
		const codePublicKey = await importJWK({ ...codePrivateKey, d: undefined });
		const oidcCode = await new EncryptJWT({
			discord_access_token: discordAccessToken,
			nonce: nonce,
			scope: scope,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
		})
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_OIDC_CLIENT_ID)
			.setExpirationTime('5m')
			.encrypt(codePublicKey);

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			// client_id is omitted for PKCE flow
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

	it('should return 400 for invalid client_id', async () => {
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

		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: 'invalid_grant', error_description: 'invalid authorization code' });
	});

	it('should return 401 for invalid client_secret when PKCE is not used', async () => {
		const discordAccessToken = 'mock_discord_access_token';
		const nonce = 'test_nonce';
		const scope = 'openid profile email';

		// Create a mock OIDC authorization code (JWE) without a code_challenge
		const codePrivateKey = JSON.parse(MOCK_CODE_PRIVATE_KEY);
		const codePublicKey = await importJWK({ ...codePrivateKey, d: undefined });
		const oidcCode = await new EncryptJWT({
			discord_access_token: discordAccessToken,
			nonce: nonce,
			scope: scope,
		})
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_OIDC_CLIENT_ID)
			.setExpirationTime('5m')
			.encrypt(codePublicKey);

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: MOCK_OIDC_CLIENT_ID,
			client_secret: 'wrong_secret',
			code: oidcCode,
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
		const codePrivateKey = JSON.parse(MOCK_CODE_PRIVATE_KEY);
		const codePublicKey = await importJWK({ ...codePrivateKey, d: undefined });
		const oidcCode = await new EncryptJWT({
			discord_access_token: discordAccessToken,
			nonce: nonce,
			scope: scope,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
		})
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_OIDC_CLIENT_ID)
			.setExpirationTime('5m')
			.encrypt(codePublicKey);

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

		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({
			error: 'invalid_request',
			error_description: 'code_verifier is required for PKCE flow',
		});
	});

	it('should return 400 for invalid code_verifier', async () => {
		const discordAccessToken = 'mock_discord_access_token';
		const nonce = 'test_nonce';
		const scope = 'openid profile email';
		const codeChallenge = await generateCodeChallenge('correct_code_verifier');

		// Create a mock OIDC authorization code (JWE) with a valid code_challenge
		const codePrivateKey = JSON.parse(MOCK_CODE_PRIVATE_KEY);
		const codePublicKey = await importJWK({ ...codePrivateKey, d: undefined });
		const oidcCode = await new EncryptJWT({
			discord_access_token: discordAccessToken,
			nonce: nonce,
			scope: scope,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
		})
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_OIDC_CLIENT_ID)
			.setExpirationTime('5m')
			.encrypt(codePublicKey);

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

		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: 'invalid_grant', error_description: 'invalid code_verifier' });
	});

	it('should return 500 if Discord user info fetch fails', async () => {
		const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		// Temporarily override fetch to simulate a failed Discord user info fetch
		global.fetch = vi.fn(() => Promise.resolve(new Response('{}', { status: 400 }))) as any;

		const discordAccessToken = 'mock_discord_access_token';
		const nonce = 'test_nonce';
		const scope = 'openid profile email';
		const codeVerifier = 'test_code_verifier_123456789012345678901234567890';
		const codeChallenge = await generateCodeChallenge(codeVerifier);

		// Create a mock OIDC authorization code (JWE)
		const codePrivateKey = JSON.parse(MOCK_CODE_PRIVATE_KEY);
		const codePublicKey = await importJWK({ ...codePrivateKey, d: undefined });
		const oidcCode = await new EncryptJWT({
			discord_access_token: discordAccessToken,
			nonce: nonce,
			scope: scope,
			code_challenge: codeChallenge,
			code_challenge_method: 'S256',
		})
			.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_OIDC_CLIENT_ID)
			.setExpirationTime('5m')
			.encrypt(codePublicKey);

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
		consoleErrorSpy.mockRestore();
	});
});
