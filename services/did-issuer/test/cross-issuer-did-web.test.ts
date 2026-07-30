// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 2 (did-issuer-wallet-phase2): cross-issuer did:web resolution — the
// verifier verifies a credential issued by a FOREIGN did:web issuer (e.g. a
// customer's own), resolving the issuer key via a constrained SSRF-safe fetch.
// The local DID store still serves the did-issuer's own creds (no regression).
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createPublicKey } from "node:crypto";
import { app } from "../src/index";
import { issueSdJwtVc } from "../src/sdjwt";
import { _resetStatusForTests } from "../src/status";
import { _resetRevokedKidsForTests } from "../src/revoked-kids";
import { _resetForTests as resetDidStore } from "../src/store";
import type { KeyMaterial } from "@mneurix/shared";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const FOREIGN_DID = "did:web:other-issuer.example";
const FOREIGN_KID = "foreign-issuer-key";
const VCT = "https://other-issuer.example/vct/competency/v1";
const SUBJECT = "did:web:lattice.mneurix.example/learners/7";

before(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });
afterEach(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });

function foreignKeyMaterial() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		keys: { privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string, publicKeyPem: publicKey.export({ format: "pem", type: "spki" }) as string, kid: FOREIGN_KID } as KeyMaterial,
		jwk: createPublicKey({ key: publicKey.export({ format: "jwk" }) as Record<string, string>, format: "jwk" }).export({ format: "jwk" }) as Record<string, string>,
	};
}

async function verify(presentation: string): Promise<{ verified: boolean; status: string; reason?: string }> {
	const r = await app.request("/v1/presentations:verify", { method: "POST", headers: H, body: JSON.stringify({ presentation }) });
	return (await r.json()) as { verified: boolean; status: string; reason?: string };
}

test("cross-issuer did:web: verifies a foreign did:web issuer's SD-JWT VC via the SSRF-safe fetch", async () => {
	const fk = foreignKeyMaterial();
	// Build the foreign did:web doc the verifier will fetch.
	const doc = { verificationMethod: [{ id: `${FOREIGN_DID}#${FOREIGN_KID}`, publicKeyJwk: fk.jwk }] };
	// Mock globalThis.fetch to serve the foreign did:web doc at the expected URL.
	const realFetch = globalThis.fetch;
	let fetchedUrl = "";
	globalThis.fetch = ((url: string | URL | Request) => {
		fetchedUrl = String(url);
		return Promise.resolve(new Response(JSON.stringify(doc), { status: 200, headers: { "content-type": "application/json" } }));
	}) as typeof globalThis.fetch;
	process.env.MNEURIX_DIDWEB_ALLOW_ORIGINS = "other-issuer.example";
	try {
		// Issue a foreign SD-JWT VC signed by the foreign key (iss = FOREIGN_DID).
		const result = await issueSdJwtVc({ iss: FOREIGN_DID, sub: SUBJECT, vct: VCT, claims: { score: 0.9 }, selectivelyDisclosable: ["score"], verificationMethod: `${FOREIGN_DID}#${FOREIGN_KID}` }, fk.keys);
		const vc = result.credential;
		// The verify endpoint resolves the foreign key via the mock fetch + verifies.
		const v = await verify(vc);
		assert.equal(v.verified, true, "foreign SD-JWT VC verifies via cross-issuer did:web fetch");
		assert.equal(v.status, "valid");
		assert.equal(fetchedUrl, "https://other-issuer.example/.well-known/did.json", "fetched the foreign did:web doc URL");
	} finally {
		globalThis.fetch = realFetch;
		delete process.env.MNEURIX_DIDWEB_ALLOW_ORIGINS;
	}
});

test("cross-issuer did:web: a private-IP origin is blocked (SSRF guard, fail-closed)", async () => {
	const fk = foreignKeyMaterial();
	const realFetch = globalThis.fetch;
	globalThis.fetch = (() => Promise.resolve(new Response("{}", { status: 200 }))) as typeof globalThis.fetch;
	process.env.MNEURIX_DIDWEB_ALLOW_ORIGINS = "*";
	try {
		const result = await issueSdJwtVc({ iss: "did:web:127.0.0.1", sub: SUBJECT, vct: VCT, claims: { score: 0.9 }, selectivelyDisclosable: ["score"], verificationMethod: "did:web:127.0.0.1#k" }, fk.keys);
		const v = await verify(result.credential);
		assert.equal(v.verified, false, "private-IP origin rejected");
		assert.equal(v.status, "unavailable");
	} finally {
		globalThis.fetch = realFetch;
		delete process.env.MNEURIX_DIDWEB_ALLOW_ORIGINS;
	}
});

test("cross-issuer did:web: an unallowed origin is rejected (allow-list gate)", async () => {
	const fk = foreignKeyMaterial();
	const realFetch = globalThis.fetch;
	globalThis.fetch = (() => Promise.resolve(new Response("{}", { status: 200 }))) as typeof globalThis.fetch;
	process.env.MNEURIX_DIDWEB_ALLOW_ORIGINS = "other-issuer.example"; // only other-issuer allowed
	try {
		const result = await issueSdJwtVc({ iss: "did:web:not-allowed.example", sub: SUBJECT, vct: VCT, claims: { score: 0.9 }, selectivelyDisclosable: ["score"], verificationMethod: "did:web:not-allowed.example#k" }, fk.keys);
		const v = await verify(result.credential);
		assert.equal(v.verified, false, "unallowed origin rejected");
		assert.equal(v.status, "unavailable");
	} finally {
		globalThis.fetch = realFetch;
		delete process.env.MNEURIX_DIDWEB_ALLOW_ORIGINS;
	}
});