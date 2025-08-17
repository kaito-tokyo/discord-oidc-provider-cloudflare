export class DiscordAPIError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'DiscordAPIError';
	}
}

export interface DiscordTokenResponse {
	access_token: string;
}

export interface DiscordUser {
	id: string;
	username: string;
	avatar: string;
	email?: string;
	verified?: boolean;
}

export async function exchangeCode(
	clientId: string,
	clientSecret: string,
	code: string,
	redirectUri: string,
): Promise<DiscordTokenResponse> {
	const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({
			client_id: clientId,
			client_secret: clientSecret,
			grant_type: 'authorization_code',
			code: code,
			redirect_uri: redirectUri,
		}),
	});

	if (!tokenResponse.ok) {
		console.error(`Discord token exchange failed with status: ${tokenResponse.status}`, await tokenResponse.text());
		throw new DiscordAPIError('Discord token exchange failed');
	}
	return (await tokenResponse.json()) as DiscordTokenResponse;
}

export async function getDiscordUser(accessToken: string): Promise<DiscordUser> {
	const userResponse = await fetch('https://discord.com/api/users/@me', {
		headers: { Authorization: `Bearer ${accessToken}` },
	});

	if (!userResponse.ok) {
		console.error(`Failed to fetch user from Discord with status: ${userResponse.status}`, await userResponse.text());
		throw new DiscordAPIError('Failed to fetch user from Discord');
	}
	return (await userResponse.json()) as DiscordUser;
}

export async function getDiscordUserRoles(accessToken: string, guildIds: string[]): Promise<string[]> {
	const memberPromises = guildIds.map(async (guildId) => {
		const res = await fetch(`https://discord.com/api/users/@me/guilds/${guildId}/member`, {
			headers: { Authorization: `Bearer ${accessToken}` },
		});
		if (res.ok) {
			return (await res.json()) as { roles: string[] };
		} else {
			const errorText = await res.text();
			console.error(`Failed to fetch guild member roles for guild ${guildId} with status: ${res.status}`, errorText);
			throw new DiscordAPIError(`Failed to fetch guild member roles for guild ${guildId}: ${errorText}`);
		}
	});

	const memberResults = await Promise.all(memberPromises);
	return memberResults.flatMap((member) => member.roles);
}
