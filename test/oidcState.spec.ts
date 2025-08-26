import { env, runDurableObjectAlarm } from 'cloudflare:test';
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
			const now = new Date('2024-08-26T12:20:00Z');
			vi.setSystemTime(now);

			const expiredTimestamp = now.getTime() - 1000 * 60 * 11; // 11 minutes ago
			const validTimestamp = now.getTime() - 1000 * 60 * 5; // 5 minutes ago

			const generateFakeUuidv7 = (timestamp: number): string => {
				const hexTimestamp = timestamp.toString(16).padStart(12, '0');
				return `${hexTimestamp.slice(0, 8)}-${hexTimestamp.slice(8, 12)}-7000-8000-000000000000`;
			};

			const expiredCodeId = generateFakeUuidv7(expiredTimestamp);
			const validCodeId = generateFakeUuidv7(validTimestamp);
			const expiredStateId = generateFakeUuidv7(expiredTimestamp);

			// Store an expired code
			await stub.storeCode(expiredCodeId, {
				clientId: 'test-client',
				redirectUri: 'http://localhost',
				user: { id: 'user1', username: 'user1', avatar: '', global_name: 'User One' },
				scope: 'openid',
			});

			// Store a valid code
			await stub.storeCode(validCodeId, {
				clientId: 'test-client',
				redirectUri: 'http://localhost',
				user: { id: 'user2', username: 'user2', avatar: '', global_name: 'User Two' },
				scope: 'openid',
			});

			// Store an expired state
			await stub.storeState(expiredStateId, {
				state: 'random-state-string',
				clientId: 'test-client',
				redirectUri: 'http://localhost/callback',
				responseType: 'code',
				scope: 'openid profile',
			});

			// Trigger the alarm
			const response = await runDurableObjectAlarm(stub);
			expect(response).toBe(true);

			// wait for alarm to complete
			await vi.advanceTimersByTimeAsync(0);

			// Check that the expired code is gone
			const expiredCode = await stub.getCode(expiredCodeId);
			expect(expiredCode).toBeUndefined();

			// Check that the valid code is still there (it will be deleted upon read)
			const validCode = await stub.getCode(validCodeId);
			expect(validCode).toBeDefined();
			const validCodeAfterRead = await stub.getCode(validCodeId);
			expect(validCodeAfterRead).toBeUndefined();

			// Check that the expired state is gone
			const expiredState = await stub.getState(expiredStateId);
			expect(expiredState).toBeUndefined();
		});
	});
});
