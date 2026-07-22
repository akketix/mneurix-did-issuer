import { test } from "node:test";
import assert from "node:assert/strict";
import { Client } from "../src/index";

test("SDK: sends x-mneurix-service-token + parses a 200 response", async () => {
	let captured: { url?: string; headers?: Record<string, string>; body?: string } = {};
	const fakeFetch = (async (url: string | URL | Request, init?: RequestInit) => {
		captured = {
			url: String(url),
			headers: init?.headers as Record<string, string>,
			body: init?.body as string,
		};
		return new Response(JSON.stringify({ ok: true }), {
			status: 200,
			headers: { "content-type": "application/json" },
		});
	}) as unknown as typeof fetch;
	const client = new Client({ baseUrl: "https://svc.test", serviceToken: "tok-123", fetch: fakeFetch });
	const out = (await client.dids({ x: 1 })) as { ok: boolean };
	assert.deepEqual(out, { ok: true });
	assert.ok(
		captured.url?.startsWith("https://svc.test/v1/"),
		"url is under the service base + /v1",
	);
	assert.equal(captured.headers?.["x-mneurix-service-token"], "tok-123");
	assert.equal(captured.body, JSON.stringify({ x: 1 }));
});

test("SDK: throws on a non-ok response with the canonical error shape", async () => {
	const fakeFetch = (async () =>
		new Response(JSON.stringify({ error: { code: "NOT_IMPLEMENTED", message: "stub" } }), {
			status: 501,
			headers: { "content-type": "application/json" },
		})) as unknown as typeof fetch;
	const client = new Client({ baseUrl: "https://svc.test", serviceToken: "tok", fetch: fakeFetch });
	await assert.rejects(() => client.dids(), /NOT_IMPLEMENTED/);
});
