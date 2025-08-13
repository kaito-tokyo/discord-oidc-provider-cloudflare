import { generateKeyPair, exportJWK } from 'jose';

async function generateKey() {
  const { privateKey } = await generateKeyPair('ECDH-ES', { crv: 'P-256' });
  const jwk = await exportJWK(privateKey);
  console.log(JSON.stringify(jwk));
}

generateKey();
