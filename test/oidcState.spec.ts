import { env } from 'cloudflare:test';
import { describe, it, expect, beforeEach, beforeAll, afterAll, vi } from 'vitest';
import type { OidcState, State, Code } from '../src/oidcState';

describe('OidcState', () => {
	let stub: DurableObjectStub<OidcState>;

	beforeEach(() => {
		// Get a new stub for each test
		const id = env.OIDC_STATE.idFromName('test-oidc-state');
		stub = env.OIDC_STATE.get(id);
	});

	describe('State management', () => {
		it('should store and retrieve state, then delete it', async () => {
			const stateId = 'test-state';
			const stateData: State = {
				state: 'random-state-string',
				clientId: 'test-client',
				redirectUri: 'http://localhost/callback',
				responseType: 'code',
				scope: 'openid profile',
			};

			await stub.storeState(stateId, stateData);
			const retrievedState = await stub.getState(stateId);

			expect(retrievedState).toEqual(stateData);

			// Check that the state has been deleted after retrieval
			const secondRetrieval = await stub.getState(stateId);
			expect(secondRetrieval).toBeUndefined();
		});

		it('should return undefined for non-existent state', async () => {
			const retrievedState = await stub.getState('non-existent-state');
			expect(retrievedState).toBeUndefined();
		});
	});

	describe('Code management', () => {
		it('should store and retrieve a code, then delete it', async () => {
			const codeId = 'test-code';
			const codeData: Code = {
				redirectUri: 'http://localhost/callback',
				clientId: 'test-client',
				user: { id: 'user1', username: 'user1', avatar: '', global_name: 'User One' },
				scope: 'openid',
				discordAccessToken: 'test_discord_access_token',
			};

			await stub.storeCode(codeId, codeData);
			const retrievedCode = await stub.getCode(codeId);

			// Check that the retrieved code is correct
			expect(retrievedCode).toEqual(codeData);

			// Check that the code has been deleted after retrieval
			const secondRetrieval = await stub.getCode(codeId);
			expect(secondRetrieval).toBeUndefined();
		});

		it('should return undefined for non-existent code', async () => {
			const retrievedCode = await stub.getCode('non-existent-code');
			expect(retrievedCode).toBeUndefined();
		});
	});

	describe('alarm', () => {
		beforeAll(() => {
			vi.useFakeTimers();
		});

		afterAll(() => {
			vi.useRealTimers();
		});

		it('should delete expired entries via alarm', async () => {
			const startTime = new Date('2024-08-26T12:20:00Z');
			vi.setSystemTime(startTime);

			const generateFakeUuidv7 = (timestamp: number): string => {
				const hexTimestamp = timestamp.toString(16).padStart(12, '0');
				return `${hexTimestamp.slice(0, 8)}-${hexTimestamp.slice(8, 12)}-7000-8000-000000000000`;
			};

			const expiredId = generateFakeUuidv7(startTime.getTime());
			await stub.storeCode(expiredId, {
				clientId: 'test-client',
				redirectUri: 'http://localhost',
				user: { id: 'user1', username: 'user1', avatar: '', global_name: 'User One' },
				scope: 'openid',
				discordAccessToken: 'test_discord_access_token',
			});

			const timeAfter9Minutes = new Date(startTime.getTime() + 1000 * 60 * 9);
			vi.setSystemTime(timeAfter9Minutes);

			const validId = generateFakeUuidv7(timeAfter9Minutes.getTime());
			await stub.storeCode(validId, {
				clientId: 'test-client',
				redirectUri: 'http://localhost',
				user: { id: 'user2', username: 'user2', avatar: '', global_name: 'User Two' },
				scope: 'openid',
				discordAccessToken: 'test_discord_access_token_2',
			});

			// Alarm is now set for timeAfter9Minutes + 10 minutes.
			// Advance time by 10 minutes to trigger the alarm.
			await vi.advanceTimersByTimeAsync(1000 * 60 * 10);
			await vi.runOnlyPendingTimersAsync();

			// Check that expired code is deleted.
			const expiredCode = await stub.getCode(expiredId);
			expect(expiredCode).toBeUndefined();

			// Check that valid code is still there.
			const validCode = await stub.getCode(validId);
			expect(validCode).toBeDefined();
		});
	});
});
