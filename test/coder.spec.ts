import { exportJWK, generateKeyPair, type JWK } from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { type CodePayload, type StatePayload, decodeCode, decodeState, encodeCode, encodeState } from '../src/coder.js';

describe('State', () => {
	const secret = 'test-secret';
	const issuer = 'test-issuer';
	const audience = 'test-audience';
	const payload: Omit<StatePayload, 'jti'> = {
		original_state: 'original-state',
		redirect_uri: 'http://localhost/callback',
		scope: 'openid profile',
		code_challenge: 'challenge',
		code_challenge_method: 'S256',
		client_id: 'test-client-id',
	};

	it('should encode and decode a state JWT', async () => {
		const token = await encodeState(payload, secret, issuer, audience);
		const decoded = await decodeState(token, secret, issuer, audience);
		expect(decoded.original_state).toBe(payload.original_state);
		expect(decoded.redirect_uri).toBe(payload.redirect_uri);
		expect(decoded.scope).toBe(payload.scope);
		expect(decoded.code_challenge).toBe(payload.code_challenge);
		expect(decoded.code_challenge_method).toBe(payload.code_challenge_method);
		expect(decoded.client_id).toBe(payload.client_id);
	});

	it('should throw an error for an invalid state JWT', async () => {
		await expect(decodeState('invalid-token', secret, issuer, audience)).rejects.toThrow();
	});
});

describe('Code', () => {
	let privateJwk: JWK;
	let publicJwk: JWK;
	const issuer = 'test-issuer';
	const audience = 'test-audience';
	const payload: CodePayload = {
		discord_access_token: 'discord-token',
		scope: 'openid profile',
		code_challenge: 'challenge',
		code_challenge_method: 'S256',
	};

	beforeAll(async () => {
		const { privateKey, publicKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
		privateJwk = await exportJWK(privateKey);
		publicJwk = await exportJWK(publicKey);
		privateJwk.alg = 'ECDH-ES';
		publicJwk.alg = 'ECDH-ES';
	});

	it('should encode and decode a code JWE', async () => {
		const token = await encodeCode(payload, publicJwk, issuer, audience);
		const decoded = await decodeCode(token, privateJwk, issuer);
		expect(decoded.discord_access_token).toBe(payload.discord_access_token);
		expect(decoded.scope).toBe(payload.scope);
		expect(decoded.code_challenge).toBe(payload.code_challenge);
		expect(decoded.code_challenge_method).toBe(payload.code_challenge_method);
	});

	it('should throw an error for an invalid code JWE', async () => {
		await expect(decodeCode('invalid-token', privateJwk, issuer)).rejects.toThrow();
	});
});
