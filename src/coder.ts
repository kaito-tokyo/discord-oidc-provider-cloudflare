import { decodeBase64Url } from 'hono/utils/encode';
import { SignJWT, jwtVerify, EncryptJWT, jwtDecrypt, importJWK } from 'jose';
import type { JWK } from 'jose';
import { v7 as uuidv7 } from 'uuid';

export const encodeState = async (
	state: string,
	redirect_uri: string,
	nonce: string | undefined,
	scope: string,
	code_challenge: string,
	code_challenge_method: string | undefined,
	client_id: string,
	secret: string,
	issuer: string,
	audience: string,
) => {
	return await new SignJWT({
		jti: uuidv7(),
		original_state: state,
		redirect_uri: redirect_uri,
		nonce: nonce,
		scope: scope,
		code_challenge: code_challenge,
		code_challenge_method: code_challenge_method || 'S256',
		client_id: client_id,
	})
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuedAt()
		.setIssuer(issuer)
		.setAudience(audience)
		.setExpirationTime('10m')
		.sign(decodeBase64Url(secret));
};

export const decodeState = async (token: string, secret: string, issuer: string, audience: string) => {
	const { payload } = await jwtVerify(token, decodeBase64Url(secret), {
		issuer: issuer,
		audience: audience,
	});
	return payload;
};

export const encodeCode = async (
	discord_access_token: string,
	nonce: unknown,
	scope: unknown,
	code_challenge: unknown,
	code_challenge_method: unknown,
	privateJwk: JWK,
	issuer: string,
	audience: string,
) => {
	const codePublicKey = await importJWK({
		alg: privateJwk.alg,
		kty: privateJwk.kty,
		crv: privateJwk.crv,
		x: privateJwk.x,
		y: privateJwk.y,
	} satisfies JWK);

	return await new EncryptJWT({
		discord_access_token: discord_access_token,
		nonce: nonce,
		scope: scope,
		code_challenge: code_challenge,
		code_challenge_method: code_challenge_method,
	})
		.setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
		.setIssuedAt()
		.setIssuer(issuer)
		.setAudience(audience)
		.setExpirationTime('5m')
		.encrypt(codePublicKey);
};

export const decodeCode = async (token: string, privateJwk: JWK, issuer: string) => {
	const codePrivateKey = await importJWK(privateJwk);
	const { payload } = await jwtDecrypt(token, codePrivateKey, {
		issuer: issuer,
	});
	return payload;
};