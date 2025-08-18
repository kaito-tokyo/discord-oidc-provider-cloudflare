import { type JWK, type JWTPayload, EncryptJWT, SignJWT, importJWK, jwtDecrypt, jwtVerify } from 'jose';
import { v7 as uuidv7 } from 'uuid';

export interface StatePayload extends JWTPayload {
	original_state: string;
	redirect_uri: string;
	nonce?: string;
	scope: string;
	code_challenge: string;
	code_challenge_method: string;
	client_id: string;
}

export const encodeState = async (payload: Omit<StatePayload, 'jti'>, secret: Uint8Array, issuer: string, audience: string) => {
	const stateJwt = await new SignJWT({
		jti: uuidv7(),
		...payload,
	})
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setIssuer(issuer)
		.setAudience(audience)
		.setExpirationTime('10m')
		.sign(secret);
	return stateJwt;
};

export const decodeState = async (token: string, secret: Uint8Array, issuer: string, audience: string): Promise<StatePayload> => {
	const { payload } = await jwtVerify(token, secret, {
		issuer: issuer,
		audience: audience,
		algorithms: ['HS256'],
	});
	return payload as StatePayload;
};

export interface CodePayload extends JWTPayload {
	discord_access_token: string;
	nonce?: string;
	scope: string;
	code_challenge: string;
	code_challenge_method: string;
}

export const encodeCode = async (payload: CodePayload, publicJwk: JWK, issuer: string, audience: string) => {
	const codePublicKey = await importJWK(publicJwk);

	return await new EncryptJWT(payload)
		.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
		.setIssuedAt()
		.setIssuer(issuer)
		.setAudience(audience)
		.setExpirationTime('5m')
		.encrypt(codePublicKey);
};

export const decodeCode = async (token: string, privateJwk: JWK, issuer: string): Promise<CodePayload> => {
	const codePrivateKey = await importJWK(privateJwk);
	const { payload } = await jwtDecrypt(token, codePrivateKey, {
		issuer: issuer,
		keyManagementAlgorithms: ['ECDH-ES'],
		contentEncryptionAlgorithms: ['A256GCM'],
	});
	return payload as CodePayload;
};
