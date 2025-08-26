import { SELF, env } from 'cloudflare:test';
import { v7 as uuidv7 } from 'uuid';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as discord from '../../src/discord.js';
import { DiscordAPIError } from '../../src/discord.js';
import { setUpOidcClients, TEST_OIDC_CLIENT_ID, TEST_OIDC_REDIRECT_URI } from '../test_helpers.js';

describe('/callback endpoint', () => {
	beforeEach(async () => {
		vi.spyOn(discord, 'exchangeCode').mockResolvedValue({
			access_token: 'discord_access_token',
		});
		vi.spyOn(discord, 'getDiscordUser').mockResolvedValue({
			id: 'discord_user_id',
			username: 'testuser',
			avatar: 'testavatar',
			email: 'test@example.com',
			verified: true,
		});

		await setUpOidcClients();
	});

	afterEach(() => {
		vi.restoreAllMocks();
	});

	it('should handle successful callback and redirect with OIDC code', async () => {
		const stateId = uuidv7();
		const statePayload = {
			state: 'random_state_string',
			clientId: TEST_OIDC_CLIENT_ID,
			redirectUri: TEST_OIDC_REDIRECT_URI,
			responseType: 'code',
			scope: 'openid profile email',
			nonce: 'random_nonce_string',
			codeChallenge: 'code_challenge',
			codeChallengeMethod: 'S256',
		};

		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeState(stateId, statePayload);

		const discordAuthCode = 'discord_auth_code';
		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}&state=${stateId}`, {
			redirect: 'manual',
		});

		expect(response.status).toBe(302); // Expect a redirect
		const redirectLocation = response.headers.get('location');
		expect(redirectLocation).toBeDefined();

		const redirectUrl = new URL(redirectLocation!);
		expect(redirectUrl.origin).toBe(new URL(statePayload.redirectUri).origin);
		expect(redirectUrl.pathname).toBe(new URL(statePayload.redirectUri).pathname);
		expect(redirectUrl.searchParams.get('state')).toBe(statePayload.state);

		const oidcCodeId = redirectUrl.searchParams.get('code');
		expect(oidcCodeId).toBeDefined();

		// Verify the stored OIDC code payload
		const codePayload = await oidcState.getCode(oidcCodeId!);
		expect(codePayload).toBeDefined();
		expect(codePayload!.clientId).toBe(statePayload.clientId);
		expect(codePayload!.redirectUri).toBe(statePayload.redirectUri);
		expect(codePayload!.nonce).toBe(statePayload.nonce);
		expect(codePayload!.scope).toBe(statePayload.scope);
		expect(codePayload!.codeChallenge).toBe(statePayload.codeChallenge);
		expect(codePayload!.codeChallengeMethod).toBe(statePayload.codeChallengeMethod);
		expect(codePayload!.user.id).toBe('discord_user_id');
	});

	it('should return 400 if code is missing', async () => {
		const stateId = 'some_state_id';
		const response = await SELF.fetch(`http://localhost/callback?state=${stateId}`, { redirect: 'manual' });
		expect(response.status).toBe(400);
		const body = await response.text();
		expect(body).toBe('code is required');
	});

	it('should return 400 if state is missing', async () => {
		const discordAuthCode = 'discord_auth_code';
		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}`, { redirect: 'manual' });
		expect(response.status).toBe(400);
		const body = await response.text();
		expect(body).toBe('state is required');
	});

	it('should return 400 if state is invalid', async () => {
		const discordAuthCode = 'discord_auth_code';
		const invalidStateId = 'invalid_state_id';
		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}&state=${invalidStateId}`, {
			redirect: 'manual',
		});
		expect(response.status).toBe(400);
		const body = await response.text();
		expect(body).toBe('invalid state');
	});

	it('should return 500 if Discord token exchange fails', async () => {
		vi.spyOn(discord, 'exchangeCode').mockRejectedValue(new DiscordAPIError('Discord token exchange failed'));

		const stateId = uuidv7();
		const statePayload = {
			state: 'random_state_string',
			clientId: TEST_OIDC_CLIENT_ID,
			redirectUri: TEST_OIDC_REDIRECT_URI,
			responseType: 'code',
			scope: 'openid profile email',
		};

		const doId = env.OIDC_STATE.idFromName('OIDC_STATE');
		const oidcState = env.OIDC_STATE.get(doId);
		await oidcState.storeState(stateId, statePayload);

		const discordAuthCode = 'discord_auth_code';

		const response = await SELF.fetch(`http://localhost/callback?code=${discordAuthCode}&state=${stateId}`, {
			redirect: 'manual',
		});
		expect(response.status).toBe(500);
		const body = await response.text();
		expect(body).toBe('Discord token exchange failed');
	});
});
