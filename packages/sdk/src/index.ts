// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** @akketix/did-issuer — thin typed client SDK for the did-issuer service.
 * PRIVATE: distributed to licensees / vendored for air-gap; NOT published to public npm.
 * Uses the x-mneurix-service-token header + a canonical error shape. Inject the
 * `fetch` for zero-network tests. */
export interface ClientOptions {
	baseUrl: string;
	serviceToken: string;
	/** Injectable for tests (defaults to global fetch). */
	fetch?: typeof fetch;
}

export class Client {
	constructor(private readonly opts: ClientOptions) {}

	private async req(path: string, init: RequestInit): Promise<unknown> {
		const fetchFn = this.opts.fetch ?? fetch;
		const res = await fetchFn(this.opts.baseUrl.replace(/\/$/, "") + path, {
			...init,
			headers: { "content-type": "application/json", "x-mneurix-service-token": this.opts.serviceToken, ...(init.headers ?? {}) },
		});
		const body = await res.json().catch(() => ({ error: { code: "NON_JSON", message: "empty/non-JSON response" } }));
		if (!res.ok) {
			const e = (body as { error?: { code?: string; message?: string } }).error;
			throw new Error(`did-issuer ${res.status}: ${e?.code ?? "ERROR"} ${e?.message ?? ""}`.trim());
		}
		return body;
	}

	async dids(body?: unknown): Promise<unknown> {
		return this.req("/v1/dids", { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}

	async dids_did(did: string, body?: unknown): Promise<unknown> {
		return this.req("/v1/dids/${did}", { method: "GET", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}

	async vcs_issue(body?: unknown): Promise<unknown> {
		return this.req("/v1/vcs:issue", { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}

	async presentations_verify(body?: unknown): Promise<unknown> {
		return this.req("/v1/presentations:verify", { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}

	async dids_did_keys_rotate(did: string, body?: unknown): Promise<unknown> {
		return this.req("/v1/dids/${did}/keys:rotate", { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}

	async dids_did_keys_revoke(did: string, body?: unknown): Promise<unknown> {
		return this.req("/v1/dids/${did}/keys:revoke", { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}

	async credentials_id_status(id: string, body?: unknown): Promise<unknown> {
		return this.req("/v1/credentials/${id}/status", { method: "GET", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}

	async dids_did_publish(did: string, body?: unknown): Promise<unknown> {
		return this.req("/v1/dids/${did}/publish", { method: "POST", ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
	}
}
