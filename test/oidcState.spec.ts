import { env, runDurableObjectAlarm } from 'cloudflare:test';
import { describe, it, expect, beforeEach } from 'vitest';
import type { OidcState, State, Code } from '../src/oidcState';

describe('OidcState', () => {
	let stub: DurableObjectStub<OidcState>;

	beforeEach(() => {
		// Get a new stub for each test
		const id = env.OIDC_STATE.idFromName('test-oidc-state');
		stub = env.OIDC_STATE.get(id);
	});

	describe('State management', () => {
		it('should store and retrieve state', async () => {
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
				fetched_at: new Date().toISOString(),
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
		it('should delete expired codes via alarm', async () => {
			const expiredCodeId = 'expired-code';
			const validCodeId = 'valid-code';

			// Store a code that is already expired (fetched_at > 10 minutes ago)
			await stub.storeCode(expiredCodeId, {
				clientId: 'test-client',
				redirectUri: 'http://localhost',
				user: { id: 'user1', username: 'user1', avatar: '', global_name: 'User One' },
				scope: 'openid',
				fetched_at: new Date(Date.now() - 1000 * 60 * 11).toISOString(), // 11 minutes ago
			});

			// Store a code that is not expired
			await stub.storeCode(validCodeId, {
				clientId: 'test-client',
				redirectUri: 'http://localhost',
				user: { id: 'user2', username: 'user2', avatar: '', global_name: 'User Two' },
				scope: 'openid',
				fetched_at: new Date().toISOString(), // now
			});

			// Trigger the alarm
			const response = await runDurableObjectAlarm(stub);
			expect(response).toBe(true);

			// Check that the expired code is gone
			const expiredCode = await stub.getCode(expiredCodeId);
			expect(expiredCode).toBeUndefined();

			// Check that the valid code is still there
			const validCode = await stub.getCode(validCodeId);
			expect(validCode).toBeDefined();
		});
	});
});
