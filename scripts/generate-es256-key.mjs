import { generateKeyPair, exportJWK } from 'jose';
import { v7 as uuidv7 } from 'uuid';

async function generateKey() {
	const { privateKey } = await generateKeyPair('ES256');
	const jwk = await exportJWK(privateKey);
	jwk.use = 'sig';
	jwk.alg = 'ES256';
	jwk.kid = uuidv7();
	console.log(JSON.stringify(jwk));
}

generateKey();
