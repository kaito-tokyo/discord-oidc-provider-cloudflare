import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { DiscordAPIError, exchangeCode, getDiscordUser, getDiscordUserRoles } from '../src/discord';

afterEach(() => {
	vi.restoreAllMocks();
});

describe('exchangeCode', () => {
	beforeEach(() => {
		vi.spyOn(console, 'error').mockImplementation(() => {});
	});
	it('should exchange code for token', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (url, options) => {
			expect(url).toBe('https://discord.com/api/oauth2/token');
			expect(options?.method).toBe('POST');
			expect(options?.headers).toEqual({ 'Content-Type': 'application/x-www-form-urlencoded' });
			expect(options?.body?.toString()).toBe(
				'client_id=test-client-id&client_secret=test-client-secret&grant_type=authorization_code&code=test-code&redirect_uri=http%3A%2F%2Flocalhost%2Fcallback',
			);
			return new Response(JSON.stringify({ access_token: 'test-access-token' }), {
				status: 200,
				headers: { 'Content-Type': 'application/json' },
			});
		});

		const result = await exchangeCode('test-client-id', 'test-client-secret', 'test-code', 'http://localhost/callback');
		expect(result).toEqual({ access_token: 'test-access-token' });
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it('should throw DiscordAPIError on failed exchange', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (_url, _options) => {
			return new Response('error', { status: 400 });
		});

		await expect(
			exchangeCode('test-client-id', 'test-client-secret', 'test-code', 'http://localhost/callback'),
		).rejects.toThrow(DiscordAPIError);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});
});

describe('getDiscordUser', () => {
	beforeEach(() => {
		vi.spyOn(console, 'error').mockImplementation(() => {});
	});
	it('should get user from Discord', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (url, options) => {
			expect(url).toBe('https://discord.com/api/users/@me');
			expect(options?.method).toBe('GET');
			expect(options?.headers).toEqual({ Authorization: 'Bearer test-access-token' });
			return new Response(
				JSON.stringify({
					id: 'test-user-id',
					username: 'test-user',
					avatar: 'test-avatar',
					global_name: 'Test User',
				}),
				{
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				},
			);
		});

		const user = await getDiscordUser('test-access-token');
		expect(user).toEqual({
			id: 'test-user-id',
			username: 'test-user',
			avatar: 'test-avatar',
			global_name: 'Test User',
		});
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});

	it('should throw DiscordAPIError on failed user fetch', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (_url, _options) => {
			return new Response('unauthorized', { status: 401 });
		});

		await expect(getDiscordUser('test-access-token')).rejects.toThrow(DiscordAPIError);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});
});

describe('getDiscordUserRoles', () => {
	beforeEach(() => {
		vi.spyOn(console, 'error').mockImplementation(() => {});
	});
	it('should get user roles from multiple guilds', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (url, _options) => {
			if (url === 'https://discord.com/api/users/@me/guilds/guild1/member') {
				return new Response(JSON.stringify({ roles: ['role1', 'role2'] }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			if (url === 'https://discord.com/api/users/@me/guilds/guild2/member') {
				return new Response(JSON.stringify({ roles: ['role3'] }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			return new Response('not found', { status: 404 });
		});

		const roles = await getDiscordUserRoles('test-access-token', ['guild1', 'guild2']);
		expect(roles).toEqual(['role1', 'role2', 'role3']);
		expect(fetchSpy).toHaveBeenCalledTimes(2);
	});

	it('should throw DiscordAPIError if one of the guild fetches fails', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (url, _options) => {
			if (url === 'https://discord.com/api/users/@me/guilds/guild1/member') {
				return new Response(JSON.stringify({ roles: ['role1', 'role2'] }), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				});
			}
			if (url === 'https://discord.com/api/users/@me/guilds/guild2/member') {
				return new Response('server error', { status: 500 });
			}
			return new Response('not found', { status: 404 });
		});

		await expect(getDiscordUserRoles('test-access-token', ['guild1', 'guild2'])).rejects.toThrow(DiscordAPIError);
		expect(fetchSpy).toHaveBeenCalledTimes(2);
	});

	it('should throw DiscordAPIError for a user not in a guild', async () => {
		const fetchSpy = vi.spyOn(global, 'fetch').mockImplementation(async (_url, _options) => {
			return new Response('not found', { status: 404 });
		});

		await expect(getDiscordUserRoles('test-access-token', ['guild1'])).rejects.toThrow(DiscordAPIError);
		expect(fetchSpy).toHaveBeenCalledTimes(1);
	});
});