// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { app } from "../src/index";
import { _resetForTests } from "../src/store";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const enc = encodeURIComponent;

interface MockOrigin {
	url: string;
	/** Make every request return 503 (origin "down"). */
	setBroken: (b: boolean) => void;
	/** Make PUT return 503 (origin rejects writes). */
	setRejectPut: (b: boolean) => void;
	/** Overwrite the served document (tamper, keeping id so it still matches). */
	tamper: (doc: Record<string, unknown>) => void;
	/** Direct GET status (bypasses the issuer) — proves what an origin serves. */
	rawGet: () => Promise<number>;
	stop: () => Promise<void>;
}

/** A tiny did.json host: PUT/GET/DELETE at /.well-known/did.json, in-memory. */
function mockOrigin(): Promise<MockOrigin> {
	let doc: Record<string, unknown> | null = null;
	let broken = false;
	let rejectPut = false;
	return new Promise((resolve) => {
		const server: Server = createServer((req, res) => {
			if (broken) {
				res.writeHead(503);
				res.end();
				return;
			}
			if (req.url !== "/.well-known/did.json") {
				res.writeHead(404);
				res.end();
				return;
			}
			if (req.method === "GET") {
				if (!doc) {
					res.writeHead(404);
					res.end();
					return;
				}
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify(doc));
				return;
			}
			if (req.method === "PUT") {
				if (rejectPut) {
					res.writeHead(503);
					res.end();
					return;
				}
				let body = "";
				req.on("data", (c) => (body += c));
				req.on("end", () => {
					doc = JSON.parse(body) as Record<string, unknown>;
					res.writeHead(204);
					res.end();
				});
				return;
			}
			if (req.method === "DELETE") {
				doc = null;
				res.writeHead(204);
				res.end();
				return;
			}
			res.writeHead(405);
			res.end();
		});
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address() as { port: number };
			resolve({
				url: `http://127.0.0.1:${addr.port}`,
				setBroken: (b) => {
					broken = b;
				},
				setRejectPut: (b) => {
					rejectPut = b;
				},
				tamper: (d) => {
					doc = d;
				},
				rawGet: async () => (await fetch(`http://127.0.0.1:${addr.port}/.well-known/did.json`)).status,
				stop: () => new Promise<void>((r) => server.close(() => r())),
			});
		});
	});
}

const created: MockOrigin[] = [];
async function threeOrigins(): Promise<MockOrigin[]> {
	const o = await Promise.all([mockOrigin(), mockOrigin(), mockOrigin()]);
	created.push(...o);
	return o;
}
after(async () => {
	await Promise.all(created.map((o) => o.stop()));
	created.length = 0;
});

async function mintAndPublish(did: string, origins: MockOrigin[]): Promise<void> {
	const mint = await app.request("/v1/dids", {
		method: "POST",
		headers: H,
		body: JSON.stringify({ origin: did }),
	});
	assert.equal(mint.status, 201);
	const pub = await app.request(`/v1/dids/${enc("did:web:" + did)}/publish`, {
		method: "POST",
		headers: H,
		body: JSON.stringify({ origins: origins.map((o) => o.url) }),
	});
	assert.equal(pub.status, 200);
	const pb = (await pub.json()) as { confirmed: number; quorum: number };
	assert.equal(pb.confirmed, 3);
	assert.equal(pb.quorum, 2);
}

test("M4: publish reaches quorum + resolve verifies:true across 3 origins", async () => {
	_resetForTests();
	const o = await threeOrigins();
	await mintAndPublish("acme.test", o);

	const res = await app.request(`/v1/dids/${enc("did:web:acme.test")}`, { headers: H });
	assert.equal(res.status, 200);
	const rb = (await res.json()) as { verified: boolean; resolvedFrom: string[]; document: { id: string }; docHash: string };
	assert.equal(rb.verified, true);
	assert.equal(rb.resolvedFrom.length, 3);
	assert.equal(rb.document.id, "did:web:acme.test");
	assert.ok(rb.docHash.length > 0);
});

test("M4: one origin down -> still verified:true (2-of-3 quorum)", async () => {
	_resetForTests();
	const o = await threeOrigins();
	await mintAndPublish("beta.test", o);

	o[2]!.setBroken(true); // kill the third origin
	const res = await app.request(`/v1/dids/${enc("did:web:beta.test")}`, { headers: H });
	const rb = (await res.json()) as { verified: boolean; resolvedFrom: string[] };
	assert.equal(rb.verified, true);
	assert.equal(rb.resolvedFrom.length, 2);
});

test("M4: two disagreeing origins -> verified:false + fallback to the matching origin", async () => {
	_resetForTests();
	const o = await threeOrigins();
	await mintAndPublish("gamma.test", o);

	// Capture the good published doc, then tamper origins 2+3 to *different* docs
	// (id is preserved so they pass the id filter, but their hashes diverge).
	const goodRes = await app.request(`/v1/dids/${enc("did:web:gamma.test")}`, { headers: H });
	const good = (await goodRes.json()) as { document: Record<string, unknown> };
	o[1]!.tamper({ ...good.document, tampered: "A" });
	o[2]!.tamper({ ...good.document, tampered: "B" });

	const res = await app.request(`/v1/dids/${enc("did:web:gamma.test")}`, { headers: H });
	const rb = (await res.json()) as { verified: boolean; document: { id: string }; mismatches: unknown[]; resolvedFrom: string[] };
	assert.equal(rb.verified, false);
	assert.equal(rb.document.id, "did:web:gamma.test"); // fallback doc present
	assert.equal(rb.mismatches.length, 2);
	assert.equal(rb.resolvedFrom.length, 1); // only the untampered origin agrees with itself
});

test("M4: failed quorum rolls back — no half-published document on any origin", async () => {
	_resetForTests();
	const o = await threeOrigins();
	const mint = await app.request("/v1/dids", {
		method: "POST",
		headers: H,
		body: JSON.stringify({ origin: "delta.test" }),
	});
	assert.equal(mint.status, 201);

	// Two of three origins reject the write -> only one stages -> below quorum.
	o[1]!.setRejectPut(true);
	o[2]!.setRejectPut(true);
	const pub = await app.request(`/v1/dids/${enc("did:web:delta.test")}/publish`, {
		method: "POST",
		headers: H,
		body: JSON.stringify({ origins: o.map((x) => x.url) }),
	});
	assert.equal(pub.status, 503);

	// The one origin that staged must have been rolled back (DELETE) -> 404 everywhere.
	for (const x of o) {
		assert.equal(await x.rawGet(), 404);
	}
});

test("M4: resolve without origins configured falls back to the local store (verified)", async () => {
	_resetForTests();
	const mint = await app.request("/v1/dids", {
		method: "POST",
		headers: H,
		body: JSON.stringify({ origin: "epsilon.test" }),
	});
	assert.equal(mint.status, 201);
	const res = await app.request(`/v1/dids/${enc("did:web:epsilon.test")}`, { headers: H });
	const rb = (await res.json()) as { verified: boolean; resolvedFrom: string[]; docHash: string };
	assert.equal(rb.verified, true);
	assert.deepEqual(rb.resolvedFrom, ["local"]);
	assert.ok(rb.docHash.length > 0);
});