import { generateKeyPair, exportJWK } from 'jose';
import { v7 as uuidv7 } from 'uuid';

async function generateKey() {
	const { privateKey } = await generateKeyPair('ECDH-ES+A256KW', { crv: 'P-256' });
	const jwk = await exportJWK(privateKey);
	jwk.use = 'enc';
	jwk.alg = 'ECDH-ES+A256KW';
	jwk.kid = uuidv7();
	console.log(JSON.stringify(jwk));
}

generateKey();
