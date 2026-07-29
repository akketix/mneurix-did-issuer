// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { signAsync } from "@noble/ed25519";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetRevokedKidsForTests } from "../src/revoked-kids";
import { _resetForTests as resetDidStore } from "../src/store";
import type { OpenBadgeCredential } from "@mneurix/shared";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const enc = encodeURIComponent;
const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

const achievement = {
	id: "https://lattice.mneurix.example/achievements/comp-1",
	type: ["Achievement"], name: "Mneurix Competency X",
	description: "A council-verified competency.", criteria: { narrative: "Pass." }, alignment: [],
};
const evidence = {
	kind: "council-formative" as const, id: "https://did-issuer.mneurix.example/evidence/sub-1",
	type: ["Evidence"], narrative: "Council-verified.", score: 0.85, agreement: 0.9, councilSize: 3,
	criterionScores: [{ criterionId: "c1", score: 0.9, reasoning: "strong" }],
	requiresHumanReview: false, isOfficialCertification: false, alignment: [],
};
const subjectId = "did:web:lattice.mneurix.example/learners/42";
const ISSUER_ORIGIN = "did-issuer.mneurix.example";
const issuerDid = "did:web:" + ISSUER_ORIGIN;

before(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });
afterEach(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });

async function mint(): Promise<void> {
	await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: ISSUER_ORIGIN }) });
}

async function issueOb3(): Promise<OpenBadgeCredential> {
	const r = await app.request("/v1/vcs:issue", { method: "POST", headers: H, body: JSON.stringify({ subjectId, secure: "data-integrity", achievement, evidence }) });
	return ((await r.json()) as { credential: OpenBadgeCredential }).credential;
}

async function verify(presentation: unknown, opts?: { requireKeyBinding?: boolean; nonce?: string; aud?: string }): Promise<{ verified: boolean; status: string; reason?: string }> {
	const r = await app.request("/v1/presentations:verify", {
		method: "POST", headers: H,
		body: JSON.stringify({ presentation, ...opts }),
	});
	return (await r.json()) as { verified: boolean; status: string; reason?: string };
}

test("M6: OB3 VC verifies; after rotate the old-key VC is rejected (fail-closed)", async () => {
	await mint();
	const oldVc = await issueOb3();
	const r0 = await verify(oldVc);
	assert.equal(r0.verified, true);
	assert.equal(r0.status, "valid");

	// Rotate → tombstones the old kid.
	const rotate = await app.request(`/v1/dids/${enc(issuerDid)}/keys:rotate`, { method: "POST", headers: H });
	assert.equal(rotate.status, 200);

	// The old VC (signed by the now-revoked kid) is rejected fail-closed.
	const oldResult = await verify(oldVc);
	assert.equal(oldResult.verified, false);
	assert.equal(oldResult.status, "revoked");

	// A freshly-issued VC (new kid) verifies.
	const newVc = await issueOb3();
	const r2 = await verify(newVc);
	assert.equal(r2.verified, true);
	assert.equal(r2.status, "valid");
});

test("M6: SD-JWT VC verifies; KB-JWT key binding enforced", async () => {
	await mint();
	// Holder key (Ed25519) for cnf + KB-JWT signing.
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
	const holderSeed = new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url"));

	const issue = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({
			subjectId, secure: "sd-jwt-vc", vct: "https://lattice.mneurix.example/vct/comp/v1",
			claims: { score: 0.85, given_name: "Alice" }, selectivelyDisclosable: ["score"], holderJwk,
		}),
	});
	const sdJwtWithoutKb = ((await issue.json()) as { credential: string }).credential; // ends with "~"
	assert.ok(sdJwtWithoutKb.endsWith("~"));

	// Build a KB-JWT (RFC 9901 §4.3) signed by the holder key over sd_hash.
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: "n1", aud: "https://verifier.example", iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	const kbJwt = `${kbHeader}.${kbPayload}.${b64url(kbSig)}`;
	const sdJwtWithKb = sdJwtWithoutKb + kbJwt; // ...~<kbJwt>

	// SD-JWT+KB with requireKeyBinding → verified.
	const ok = await verify(sdJwtWithKb, { requireKeyBinding: true, nonce: "n1", aud: "https://verifier.example" });
	assert.equal(ok.verified, true);

	// Bare SD-JWT (no KB) + requireKeyBinding → rejected.
	const noKb = await verify(sdJwtWithoutKb, { requireKeyBinding: true });
	assert.equal(noKb.verified, false);

	// Tampered KB-JWT (wrong nonce) → rejected.
	const badPayload = b64url(JSON.stringify({ nonce: "wrong", aud: "https://verifier.example", iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const badKbSig = await signAsync(Buffer.from(`${kbHeader}.${badPayload}`, "ascii"), holderSeed);
	const badKbJwt = `${kbHeader}.${badPayload}.${b64url(badKbSig)}`;
	const bad = await verify(sdJwtWithoutKb + badKbJwt, { requireKeyBinding: true, nonce: "n1" });
	assert.equal(bad.verified, false);
});

test("M6: GET /credentials/:id/status returns valid for an issued OB3 credential", async () => {
	await mint();
	const vc = await issueOb3();
	const r = await app.request(`/v1/credentials/${enc(vc.id)}/status`, { headers: H });
	assert.equal(r.status, 200);
	const b = (await r.json()) as { state: string; revoked: boolean };
	assert.equal(b.state, "valid");
	assert.equal(b.revoked, false);
});