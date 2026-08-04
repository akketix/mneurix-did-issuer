// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// H-2 (kimi-k3:cloud audit #2): the SD-JWT VC revocation status must be checked
// on verify. A revoked credential → { verified: false, status: "revoked" }.
// A non-revoked credential → { verified: true, status: "valid" } (no regression).
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/index";
import { _resetStatusForTests, revokeStatus } from "../src/status";
import { _resetRevokedKidsForTests } from "../src/revoked-kids";
import { _resetForTests as resetDidStore } from "../src/store";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_ORIGIN = "did-issuer.mneurix.example";
const VCT = "https://did-issuer.mneurix.example/vct/achievement";
const SUBJECT = "did:web:lattice.mneurix.example/learners/2";

before(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });
afterEach(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });

async function mint() {
	await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: ISSUER_ORIGIN }) });
}

async function issueEdDSA(holderJwk?: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9, given_name: "A" }, selectivelyDisclosable: ["score"], ...(holderJwk ? { holderJwk } : {}) }),
	});
	assert.equal(res.status, 201);
	return ((await res.json()) as { credential: string }).credential;
}

async function verify(presentation: string): Promise<{ verified: boolean; status: string; reason?: string }> {
	const r = await app.request("/v1/presentations:verify", { method: "POST", headers: H, body: JSON.stringify({ presentation }) });
	return (await r.json()) as { verified: boolean; status: string; reason?: string };
}

function extractStatusIdx(credential: string): number {
	const payloadB64 = credential.split("~")[0]!.split(".")[1]!;
	const payload = JSON.parse(Buffer.from(payloadB64.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { status: { status_list: { uri: string; idx: number } } };
	return payload.status.status_list.idx;
}

test("H-2: a revoked SD-JWT VC is rejected on verify (status: revoked)", async () => {
	await mint();
	const vc = await issueEdDSA();
	const idx = extractStatusIdx(vc);
	// Revoke the status bit
	revokeStatus("revocation", idx);
	// Verify → should be revoked
	const result = await verify(vc);
	assert.equal(result.verified, false, "revoked credential should not verify");
	assert.equal(result.status, "revoked");
	assert.match(result.reason ?? "", /revoked/);
});

test("H-2: a non-revoked SD-JWT VC verifies as valid (no regression)", async () => {
	await mint();
	const vc = await issueEdDSA();
	// Don't revoke — should verify as valid
	const result = await verify(vc);
	assert.equal(result.verified, true);
	assert.equal(result.status, "valid");
});