import { DurableObject } from "cloudflare:workers"

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
	// eslint-disable-next-line @typescript-eslint/no-explicit-any
	user: any
	scope: string
}

export class OidcState extends DurableObject {
	constructor(ctx: DurableObjectState, env: Env) {
		super(ctx, env)
	}

	async storeState(stateId: string, data: State): Promise<void> {
		await this.ctx.storage.put(`state:${stateId}`, data)
	}

	async getState(stateId: string): Promise<State | undefined> {
		return await this.ctx.storage.get<State>(`state:${stateId}`)
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
		// Clean up expired codes
		const now = Date.now()
		const oldCodes = await this.ctx.storage.list<Code>({ prefix: 'code:', allowConcurrency: true })
		const toDelete: string[] = []
		for (const [key, value] of oldCodes.entries()) {
			// This is a bit of a hack, but there's no way to get metadata otherwise
			const issuedAt = new Date(value.user.fetched_at).getTime()
			if (now - issuedAt > 1000 * 60 * 10) {
				toDelete.push(key)
			}
		}
		await this.ctx.storage.delete(toDelete)
	}
}
