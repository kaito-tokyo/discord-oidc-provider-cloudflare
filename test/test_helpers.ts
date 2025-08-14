import { env } from 'cloudflare:test';

export const TEST_OIDC_CLIENT_ID = 'oidc-client-id';
export const TEST_OIDC_REDIRECT_URI = 'http://localhost/callback';
export const TEST_OIDC_CLIENT_SECRET = 'ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb';

export async function setUpOidcClients() {
	await env.OIDC_CLIENTS.delete(TEST_OIDC_CLIENT_ID);
	await env.OIDC_CLIENTS.put(
		TEST_OIDC_CLIENT_ID,
		JSON.stringify({
			redirect_uri: TEST_OIDC_REDIRECT_URI,
			client_secret_hash: TEST_OIDC_CLIENT_SECRET,
		}),
	);
}
