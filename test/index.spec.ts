import { SELF } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';

describe('OIDC Provider', () => {
	it('redirects to Discord for authorization', async () => {
		const params = new URLSearchParams({
			response_type: 'code',
			client_id: 'test_oidc_client_id',
			redirect_uri: 'http://localhost:8787/callback',
			scope: 'openid profile email',
			state: 'af0ifjsldkj',
			nonce: 'n-0s6_W4_W4',
		});
		const response = await SELF.fetch(`https://example.com/auth?${params.toString()}`);
		expect(response.status).toBe(302);
		const location = response.headers.get('Location');
		expect(location).not.toBeNull();
		const locationUrl = new URL(location!);
		expect(locationUrl.hostname).toBe('discord.com');
		expect(locationUrl.searchParams.get('client_id')).toBe('test_discord_client_id');
		expect(locationUrl.searchParams.get('scope')).toBe('identify email');
	});
});
