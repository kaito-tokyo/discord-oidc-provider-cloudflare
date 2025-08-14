import { env } from 'cloudflare:test';

export const TEST_OIDC_CLIENT_ID = 'oidc-client-id';
export const TEST_OIDC_REDIRECT_URI = 'http://localhost/callback';
export const TEST_OIDC_CLIENT_SECRET = 'K6lG3eUQMmo2KAVriCsijKxhdQJgB8jvmGGaNaDFnKEGrZWs7LFmMFwH1vPmwi4J';
export const TEST_OIDC_CLIENT_SECRET_HASH = '9905ac160a1bc501c24c9a1d998c8054ddf12bfa42faff75374927faeaecde34';

export async function setUpOidcClients() {
	await env.OIDC_CLIENTS.delete(TEST_OIDC_CLIENT_ID);
	await env.OIDC_CLIENTS.put(
		TEST_OIDC_CLIENT_ID,
		JSON.stringify({
			redirect_uris: [TEST_OIDC_REDIRECT_URI],
			client_secret_hash: TEST_OIDC_CLIENT_SECRET_HASH,
		}),
	);
}
