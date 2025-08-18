import { decodeBase64Url } from 'hono/utils/encode';
import { SignJWT, jwtVerify, EncryptJWT, jwtDecrypt, importJWK } from 'jose';
import type { JWK, JWTPayload } from 'jose';
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

export const encodeState = async (payload: Omit<StatePayload, 'jti'>, secret: string, issuer: string, audience: string) => {
	const stateJwt = await new SignJWT({
		jti: uuidv7(),
		...payload,
	})
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setIssuer(issuer)
		.setAudience(audience)
		.setExpirationTime('10m')
		.sign(decodeBase64Url(secret));
	return stateJwt;
};

export const decodeState = async (token: string, secret: string, issuer: string, audience: string): Promise<StatePayload> => {
	const { payload } = await jwtVerify(token, decodeBase64Url(secret), {
		issuer: issuer,
		audience: audience,
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
	});
	return payload as CodePayload;
};
