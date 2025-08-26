import { DurableObject } from "cloudflare:workers"
import { DiscordUser } from "./discord"

export interface State {
	state: string
	clientId: string
	redirectUri: string
	responseType: string
	scope: string
	nonce?: string
	codeChallenge?: string
	codeChallengeMethod?: string
}

export interface Code {
	redirectUri: string
	clientId: string
	codeChallenge?: string
	codeChallengeMethod?: string
	nonce?: string
	user: DiscordUser
	scope: string
}

export class OidcState extends DurableObject {
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env)
	}

	async storeState(stateId: string, data: State): Promise<void> {
		await this.ctx.storage.put(`state:${stateId}`, data)
		this.ctx.storage.setAlarm(Date.now() + 1000 * 60 * 10) // 10 minutes
	}

	async getState(stateId: string): Promise<State | undefined> {
		const state = await this.ctx.storage.get<State>(`state:${stateId}`)
		if (state) {
			// To prevent replay attacks, states should be single-use.
			await this.ctx.storage.delete(`state:${stateId}`)
		}
		return state
	}

	async storeCode(codeId: string, data: Code): Promise<void> {
		// Codes should only be valid for a short time
		await this.ctx.storage.put(`code:${codeId}`, data, { allowUnconfirmed: true })
		this.ctx.storage.setAlarm(Date.now() + 1000 * 60 * 10) // 10 minutes
	}

	async getCode(codeId: string): Promise<Code | undefined> {
		const code = await this.ctx.storage.get<Code>(`code:${codeId}`)
		if (code) {
			// To prevent replay attacks, codes should be single-use.
			await this.ctx.storage.delete(`code:${codeId}`)
		}
		return code
	}

	async alarm() {
		// Clean up expired codes and states
		const now = Date.now()
		const oldEntries = await this.ctx.storage.list({ allowConcurrency: true })
		const toDelete: string[] = []

		for (const key of oldEntries.keys()) {
			if (!key.startsWith("code:") && !key.startsWith("state:")) {
				continue
			}

			const id = key.substring(key.indexOf(":") + 1)
			// Extract timestamp from UUIDv7
			const timestampHex = id.substring(0, 8) + id.substring(9, 13)
			const issuedAt = parseInt(timestampHex, 16)

			if (now - issuedAt > 1000 * 60 * 10) {
				// 10 minutes for both
				toDelete.push(key)
			}
		}

		if (toDelete.length > 0) {
			await this.ctx.storage.delete(toDelete)
		}
	}
}
