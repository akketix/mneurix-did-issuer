// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 3 (did-issuer-wallet-phase2): multi-credential DCQL — the request queries
// >1 credential; the wallet presents a vp_token object keyed by query id
// (OID4VP §8.1); the receiver verifies each presentation. Single-credential (N=1)
// stays a bare-string vp_token (no regression).
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { signAsync } from "@noble/ed25519";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetOpenid4vpForTests } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const ACH = `${ISSUER_URL}/vct/achievement`;
const COMP = `${ISSUER_URL}/vct/competency`;
const SUBJECT = "did:web:lattice.mneurix.example/learners/8";

const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

before(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });
afterEach(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });

async function requestMulti(): Promise<{ nonce: string; state: string; clientId: string }> {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ credentials: [{ vct: ACH, claims: ["score"] }, { vct: COMP, claims: ["score"] }] }),
	});
	assert.equal(res.status, 201);
	const body = (await res.json()) as { dcql_query: { credentials: Array<{ id: string; meta: { vct_values: string[] } }> }; session: { nonce: string; state: string } };
	assert.equal(body.dcql_query.credentials.length, 2, "two credential queries");
	assert.equal(body.dcql_query.credentials[0]!.id, "sd_jwt_vc_1");
	assert.equal(body.dcql_query.credentials[1]!.id, "sd_jwt_vc_2");
	assert.deepEqual(body.dcql_query.credentials[0]!.meta.vct_values, [ACH]);
	assert.deepEqual(body.dcql_query.credentials[1]!.meta.vct_values, [COMP]);
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL };
}

async function issueEs256(vct: string, holderJwk: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct, claims: { score: 0.9, given_name: "Eve" }, selectivelyDisclosable: ["score"], holderJwk, alg: "ES256" }),
	});
	assert.equal(res.status, 201);
	return ((await res.json()) as { credential: string }).credential;
}

function holder() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		jwk: publicKey.export({ format: "jwk" }) as Record<string, string>,
		seed: new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url")),
	};
}

async function withKb(sdJwtWithoutKb: string, sess: { nonce: string; clientId: string }, seed: Uint8Array): Promise<string> {
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), seed);
	return sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`;
}

async function postResponse(vpToken: string, state: string): Promise<{ status: number; body: { verified?: boolean; credentials?: number; message?: string } }> {
	const res = await app.request("/openid4vp/response", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ vp_token: vpToken, state }).toString(),
	});
	return { status: res.status, body: (await res.json()) as { verified?: boolean; credentials?: number; message?: string } };
}

test("multi-credential DCQL: a 2-credential request + object-keyed vp_token verifies both presentations", async () => {
	const { jwk, seed } = holder();
	const sess = await requestMulti();
	const vc1 = await withKb(await issueEs256(ACH, jwk), sess, seed);
	const vc2 = await withKb(await issueEs256(COMP, jwk), sess, seed);
	const vpToken = JSON.stringify({ sd_jwt_vc_1: vc1, sd_jwt_vc_2: vc2 });
	const r = await postResponse(vpToken, sess.state);
	assert.equal(r.status, 200);
	assert.equal(r.body.verified, true);
	assert.equal(r.body.credentials, 2, "both presentations verified");
});

test("multi-credential DCQL: a tampered second presentation -> 401 (fail-closed)", async () => {
	const { jwk, seed } = holder();
	const sess = await requestMulti();
	const vc1 = await withKb(await issueEs256(ACH, jwk), sess, seed);
	const vc2Bad = await withKb(await issueEs256(COMP, jwk), { nonce: "wrong-nonce", clientId: sess.clientId }, seed);
	const r = await postResponse(JSON.stringify({ sd_jwt_vc_1: vc1, sd_jwt_vc_2: vc2Bad }), sess.state);
	assert.equal(r.status, 401);
});

test("multi-credential DCQL: single-credential (N=1) still accepts a bare-string vp_token (no regression)", async () => {
	const { jwk, seed } = holder();
	// single-credential request
	const req = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: ACH, claims: ["score"] }) });
	const sess = (await req.json()) as { session: { nonce: string; state: string; clientId?: string } };
	const session = { nonce: sess.session.nonce, state: sess.session.state, clientId: ISSUER_URL };
	const vc = await withKb(await issueEs256(ACH, jwk), session, seed);
	const r = await postResponse(vc, session.state); // bare-string vp_token
	assert.equal(r.status, 200);
	assert.equal(r.body.verified, true);
	assert.equal(r.body.credentials, 1, "single-credential N=1");
});