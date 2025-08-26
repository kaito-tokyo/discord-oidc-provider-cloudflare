import { SELF, env } from 'cloudflare:test';
import { importJWK, jwtVerify } from 'jose';
import { v7 as uuidv7 } from 'uuid';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as discord from '../../src/discord.js';
import { DiscordAPIError } from '../../src/discord.js';
import type { TokenResponse } from '../../src/index.js';
import { OidcState } from '../../src/oidcState.js';
import wranglerJson from '../../wrangler.json';
import { setUpOidcClients, TEST_OIDC_CLIENT_ID, TEST_OIDC_CLIENT_SECRET, TEST_OIDC_REDIRECT_URI } from '../test_helpers.js';

// Helper to generate a code_challenge from a code_verifier
const generateCodeChallenge = async (codeVerifier: string): Promise<string> => {
	const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
	return btoa(String.fromCharCode(...new Uint8Array(digest)))
		.replace(/=/g, '')
		.replace(/\+/g, '-')
		.replace(/\//g, '_');
};

describe('/token endpoint', () => {
	const { JWT_PRIVATE_KEY } = wranglerJson.env.test.vars;
	const user = {
		id: 'discord_user_id',
		username: 'testuser',
		avatar: 'testavatar',
		email: 'test@example.com',
		verified: true,
	};

	beforeEach(async () => {
		vi.spyOn(discord, 'getDiscordUserRoles').mockResolvedValue([]);
		await setUpOidcClients();
		vi.spyOn(console, 'error').mockImplementation(() => {});
		vi.spyOn(console, 'warn').mockImplementation(() => {});
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('should successfully exchange authorization code for tokens with PKCE', async () => {
		const nonce = 'test_nonce';
		const scope = 'openid profile email';
		const codeVerifier = 'test_code_verifier_123456789012345678901234567890';
		const codeChallenge = await generateCodeChallenge(codeVerifier);

		const codeId = uuidv7();
		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeCode(codeId, {
			redirectUri: TEST_OIDC_REDIRECT_URI,
			clientId: TEST_OIDC_CLIENT_ID,
			codeChallenge: codeChallenge,
			codeChallengeMethod: 'S256',
			nonce: nonce,
			user: user,
			scope: scope,
			fetched_at: new Date().toISOString(),
		});

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID, // client_id is technically optional for PKCE, but we include it
			code: codeId,
			code_verifier: codeVerifier,
		});

		const response = await SELF.fetch('http://localhost/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: formData.toString(),
		});

		expect(response.status).toBe(200);
		const body = (await response.json()) as TokenResponse;

		expect(body.access_token).toBeDefined();
		expect(body.token_type).toBe('Bearer');
		expect(body.expires_in).toBe(3600);
		expect(body.scope).toBe(scope);
		expect(body.id_token).toBeDefined();

		// Verify id_token
		const privateJwk = JSON.parse(JWT_PRIVATE_KEY);
		const publicKey = await importJWK({ ...privateJwk, d: undefined }, 'ES256');
		const { payload: idTokenPayload } = await jwtVerify(body.id_token, publicKey, {
			issuer: 'http://localhost',
			audience: TEST_OIDC_CLIENT_ID,
		});

		expect(idTokenPayload.name).toBe('testuser');
		expect(idTokenPayload.picture).toBe('https://cdn.discordapp.com/avatars/discord_user_id/testavatar.png');
		expect(idTokenPayload.email).toBe('test@example.com');
		expect(idTokenPayload.email_verified).toBe(true);
		expect(idTokenPayload.nonce).toBe(nonce);
		expect(idTokenPayload.iss).toBe('http://localhost');
		expect(idTokenPayload.aud).toBe(TEST_OIDC_CLIENT_ID);
		expect(idTokenPayload.sub).toBe('discord_user_id');
	});

	it('should return 400 for invalid grant_type', async () => {
		const formData = new URLSearchParams({
			grant_type: 'invalid_grant',
			client_id: TEST_OIDC_CLIENT_ID,
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

	it('should return 400 for invalid code (not found)', async () => {
		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID,
			code: 'invalid_code',
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
		const codeId = uuidv7();
		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeCode(codeId, {
			redirectUri: TEST_OIDC_REDIRECT_URI,
			clientId: TEST_OIDC_CLIENT_ID,
			// No code_challenge for this flow
			nonce: 'test_nonce',
			user: user,
			scope: 'openid',
			fetched_at: new Date().toISOString(),
		});

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID,
			client_secret: 'wrong_secret',
			code: codeId,
		});

		const response = await SELF.fetch('http://localhost/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: formData.toString(),
		});

		expect(response.status).toBe(401);
		expect(await response.json()).toEqual({ error: 'invalid_client', error_description: 'client_secret is invalid' });
	});

	it('should successfully exchange authorization code for tokens without PKCE (client_secret)', async () => {
		const nonce = 'test_nonce';
		const scope = 'openid profile email';

		const codeId = uuidv7();
		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeCode(codeId, {
			redirectUri: TEST_OIDC_REDIRECT_URI,
			clientId: TEST_OIDC_CLIENT_ID,
			// No code_challenge for this flow
			nonce: nonce,
			user: user,
			scope: scope,
			fetched_at: new Date().toISOString(),
		});

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID,
			client_secret: TEST_OIDC_CLIENT_SECRET,
			code: codeId,
		});

		const response = await SELF.fetch('http://localhost/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: formData.toString(),
		});

		expect(response.status).toBe(200);
		const body = (await response.json()) as TokenResponse;

		expect(body.access_token).toBeDefined();
		expect(body.token_type).toBe('Bearer');
		expect(body.expires_in).toBe(3600);
		expect(body.scope).toBe(scope);
		expect(body.id_token).toBeDefined();

		// Verify id_token
		const privateJwk = JSON.parse(JWT_PRIVATE_KEY);
		const publicKey = await importJWK({ ...privateJwk, d: undefined }, 'ES256');
		const { payload: idTokenPayload } = await jwtVerify(body.id_token, publicKey, {
			issuer: 'http://localhost',
			audience: TEST_OIDC_CLIENT_ID,
		});

		expect(idTokenPayload.name).toBe('testuser');
		expect(idTokenPayload.nonce).toBe(nonce);
		expect(idTokenPayload.sub).toBe('discord_user_id');
	});

	it('should return 400 if code is missing', async () => {
		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID,
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
		const codeId = uuidv7();
		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeCode(codeId, {
			redirectUri: TEST_OIDC_REDIRECT_URI,
			clientId: TEST_OIDC_CLIENT_ID,
			codeChallenge: 'some_challenge',
			codeChallengeMethod: 'S256',
			user: user,
			scope: 'openid',
			fetched_at: new Date().toISOString(),
		});

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID,
			code: codeId,
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
		const codeVerifier = 'correct_code_verifier';
		const codeChallenge = await generateCodeChallenge(codeVerifier);

		const codeId = uuidv7();
		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeCode(codeId, {
			redirectUri: TEST_OIDC_REDIRECT_URI,
			clientId: TEST_OIDC_CLIENT_ID,
			codeChallenge: codeChallenge,
			codeChallengeMethod: 'S256',
			user: user,
			scope: 'openid',
			fetched_at: new Date().toISOString(),
		});

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID,
			code: codeId,
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

		it('should return 200 if Discord user info is already in code', async () => {
		// This test requires a valid code flow up to the point of token generation
		const nonce = 'test_nonce';
		const scope = 'openid profile email';
		const codeVerifier = 'test_code_verifier_123456789012345678901234567890';
		const codeChallenge = await generateCodeChallenge(codeVerifier);

		const codeId = uuidv7();
		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeCode(codeId, {
			redirectUri: TEST_OIDC_REDIRECT_URI,
			clientId: TEST_OIDC_CLIENT_ID,
			codeChallenge: codeChallenge,
			codeChallengeMethod: 'S256',
			nonce: nonce,
			user: user,
			scope: scope,
			fetched_at: new Date().toISOString(),
		});

		const formData = new URLSearchParams({
			grant_type: 'authorization_code',
			client_id: TEST_OIDC_CLIENT_ID,
			code: codeId,
			code_verifier: codeVerifier,
		});

		const response = await SELF.fetch('http://localhost/token', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: formData.toString(),
		});

		expect(response.status).toBe(200);
	});
});
