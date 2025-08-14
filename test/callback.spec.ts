import { SELF } from 'cloudflare:test';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SignJWT, jwtDecrypt, importJWK } from 'jose';

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

describe('/callback endpoint', () => {
	const MOCK_STATE_SECRET = 'q9DpQgBtc4yoUFYtZgHDXfJNhxfgbRc3qJttmqyLjWI=';
	const MOCK_DISCORD_CLIENT_ID = 'discord-client-id';
	const MOCK_OIDC_CLIENT_ID = 'oidc-client-id';
	const MOCK_OIDC_REDIRECT_URI = 'http://localhost/redirect';
	const MOCK_CODE_PRIVATE_KEY =
		'{"kty":"EC","x":"BNo3Mq2cH_F3gjVMNarajk6CEe7ACnog1AYEnUO0N8g","y":"PsSNgkm5Jpy8p8rc8HH0U9fa4-dCEJG81kxI2yQArH8","crv":"P-256","d":"y2y53r0Z9e2OorJwFDlezhLBNv7qekxDOft2dzbFTRo","use":"enc","alg":"ECDH-ES+A256KW","kid":"0198a59b-82af-765a-b25b-3e378297a2a0"}';

	beforeEach(() => {
		// Mock the global fetch function
		global.fetch = vi.fn((input: RequestInfo | URL, _init?: RequestInit) => {
			if (typeof input === 'string' && input.startsWith('https://discord.com/api/oauth2/token')) {
				return Promise.resolve(new Response(JSON.stringify({ access_token: 'mock_discord_access_token' }), { status: 200 }));
			}
			return Promise.reject(new Error(`Unexpected fetch call to: ${input}`));
		}) as any;
	});

	it('should handle successful callback and redirect with OIDC code', async () => {
		const originalState = 'random_state_string';
		const redirectUri = MOCK_OIDC_REDIRECT_URI;
		const nonce = 'random_nonce_string';
		const scope = 'openid profile email';
		const codeChallenge = 'mock_code_challenge';
		const codeChallengeMethod = 'S256';

		// Create a mock state JWT
		const stateJwt = await new SignJWT({
			original_state: originalState,
			redirect_uri: redirectUri,
			nonce: nonce,
			scope: scope,
			code_challenge: codeChallenge,
			code_challenge_method: codeChallengeMethod,
		})
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_DISCORD_CLIENT_ID)
			.setExpirationTime('10m')
			.sign(base64urlToUint8Array(MOCK_STATE_SECRET));

		const discordAuthCode = 'mock_discord_auth_code';

		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}&state=${stateJwt}`, { redirect: 'manual' });

		expect(response.status).toBe(302); // Expect a redirect
		const redirectLocation = response.headers.get('location');
		expect(redirectLocation).toBeDefined();

		const redirectUrl = new URL(redirectLocation!);
		expect(redirectUrl.origin).toBe(new URL(redirectUri).origin);
		expect(redirectUrl.pathname).toBe(new URL(redirectUri).pathname);
		expect(redirectUrl.searchParams.get('state')).toBe(originalState);

		const oidcCode = redirectUrl.searchParams.get('code');
		expect(oidcCode).toBeDefined();

		const codePrivateKey = await importJWK(JSON.parse(MOCK_CODE_PRIVATE_KEY));

		// Verify the OIDC code (JWE)
		const { payload: oidcCodePayload } = await jwtDecrypt(oidcCode!, codePrivateKey, {
			issuer: 'http://localhost',
			audience: MOCK_OIDC_CLIENT_ID,
		});

		expect(oidcCodePayload.discord_access_token).toBe('mock_discord_access_token');
		expect(oidcCodePayload.nonce).toBe(nonce);
		expect(oidcCodePayload.scope).toBe(scope);
		expect(oidcCodePayload.code_challenge).toBe(codeChallenge);
		expect(oidcCodePayload.code_challenge_method).toBe(codeChallengeMethod);
	});

	it('should return 400 if code is missing', async () => {
		const stateJwt = 'some_state_jwt'; // A dummy state, as the check for code comes first
		const response = await SELF.fetch(`http://localhost/callback?state=${stateJwt}`, { redirect: 'manual' });
		expect(response.status).toBe(400);
		const body = await response.text();
		expect(body).toBe('code is required');
	});

	it('should return 400 if state is missing', async () => {
		const discordAuthCode = 'mock_discord_auth_code';
		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}`, { redirect: 'manual' });
		expect(response.status).toBe(400);
		const body = await response.text();
		expect(body).toBe('state is required');
	});

	it('should return 500 if state JWT verification fails', async () => {
		const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		const discordAuthCode = 'mock_discord_auth_code';
		const invalidStateJwt = 'invalid.jwt.signature'; // An invalid JWT
		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}&state=${invalidStateJwt}`, { redirect: 'manual' });
		expect(response.status).toBe(500); // Hono's HTTPException for JWT verification failure
		consoleErrorSpy.mockRestore();
	});

	it('should return 500 if Discord token exchange fails', async () => {
		const consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
		// Temporarily override fetch to simulate a failed Discord token exchange
		global.fetch = vi.fn(() => Promise.resolve(new Response('{}', { status: 400 }))) as any;

		const originalState = 'random_state_string';
		const redirectUri = MOCK_OIDC_REDIRECT_URI;
		const nonce = 'random_nonce_string';
		const scope = 'openid profile email';
		const codeChallenge = 'mock_code_challenge';
		const codeChallengeMethod = 'S256';

		const stateJwt = await new SignJWT({
			original_state: originalState,
			redirect_uri: redirectUri,
			nonce: nonce,
			scope: scope,
			code_challenge: codeChallenge,
			code_challenge_method: codeChallengeMethod,
		})
			.setProtectedHeader({ alg: 'HS256' })
			.setIssuedAt()
			.setIssuer('http://localhost')
			.setAudience(MOCK_DISCORD_CLIENT_ID)
			.setExpirationTime('10m')
			.sign(base64urlToUint8Array(MOCK_STATE_SECRET));

		const discordAuthCode = 'mock_discord_auth_code';

		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}&state=${stateJwt}`, { redirect: 'manual' });
		expect(response.status).toBe(500);
		const body = await response.text();
		expect(body).toBe('Discord token exchange failed');
		consoleErrorSpy.mockRestore();
	});
});
