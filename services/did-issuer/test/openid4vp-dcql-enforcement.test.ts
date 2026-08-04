// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// H-1 (kimi-k3:cloud audit #2): the OpenID4VP receiver must enforce the DCQL
// query — the presented credential's vct must match the requested type, + the
// count must match (multi-credential). A wrong vct or wrong count → 401.
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
const SUBJECT = "did:web:lattice.mneurix.example/learners/1";

const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

before(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });
afterEach(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });

async function request(vct: string): Promise<{ nonce: string; state: string; clientId: string }> {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct, claims: ["score"] }) });
	const body = (await res.json()) as { session: { nonce: string; state: string } };
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL };
}

async function issueEs256(vct: string, holderJwk: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", { method: "POST", headers: H, body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct, claims: { score: 0.9 }, selectivelyDisclosable: ["score"], holderJwk, alg: "ES256" }) });
	assert.equal(res.status, 201);
	return ((await res.json()) as { credential: string }).credential;
}

function holder() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return { jwk: publicKey.export({ format: "jwk" }) as Record<string, string>, seed: new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url")) };
}

function kbJwt(seed: Uint8Array, sdJwtWithoutKb: string, nonce: string, aud: string): string {
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbH = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbP = b64url(JSON.stringify({ nonce, aud, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	// signAsync is async — this helper returns a Promise; the caller must await.
	// But we can't await in a sync function. Return the parts + let the caller sign.
	// Actually — let's just return the parts + the caller assembles.
	return `${kbH}.${kbP}.`; // placeholder; the caller replaces the sig
}

async function postResponse(vpToken: string, state: string): Promise<number> {
	const res = await app.request("/openid4vp/response", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ vp_token: vpToken, state }).toString() });
	return res.status;
}

test("H-1: a credential with the WRONG vct is rejected (DCQL enforcement)", async () => {
	const { jwk, seed } = holder();
	const sess = await request(ACH); // requests achievement
	const vc = await issueEs256(COMP, jwk); // issues COMPETENCY (wrong vct)
	const sdHash = b64url(createHash("sha256").update(Buffer.from(vc, "ascii")).digest());
	const kbH = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbP = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbH}.${kbP}`, "ascii"), seed);
	const vpToken = `${vc}${kbH}.${kbP}.${b64url(kbSig)}`;
	const status = await postResponse(vpToken, sess.state);
	assert.equal(status, 401, "wrong vct → 401");
});

test("H-1: a credential with the CORRECT vct is accepted (no regression)", async () => {
	const { jwk, seed } = holder();
	const sess = await request(ACH); // requests achievement
	const vc = await issueEs256(ACH, jwk); // issues ACHIEVEMENT (correct vct)
	const sdHash = b64url(createHash("sha256").update(Buffer.from(vc, "ascii")).digest());
	const kbH = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbP = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbH}.${kbP}`, "ascii"), seed);
	const vpToken = `${vc}${kbH}.${kbP}.${b64url(kbSig)}`;
	const status = await postResponse(vpToken, sess.state);
	assert.equal(status, 200, "correct vct → 200");
});

test("H-1: multi-credential with the WRONG count (1 of 2) is rejected", async () => {
	const { jwk, seed } = holder();
	// Request 2 credentials (achievement + competency)
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ credentials: [{ vct: ACH, claims: ["score"] }, { vct: COMP, claims: ["score"] }] }) });
	const sess = (await res.json()) as { session: { nonce: string; state: string } };
	// Present only 1 of the 2 requested
	const vc = await issueEs256(ACH, jwk);
	const sdHash = b64url(createHash("sha256").update(Buffer.from(vc, "ascii")).digest());
	const kbH = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbP = b64url(JSON.stringify({ nonce: sess.session.nonce, aud: ISSUER_URL, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbH}.${kbP}`, "ascii"), seed);
	const vpToken = `${vc}${kbH}.${kbP}.${b64url(kbSig)}`; // bare string = 1 credential
	const status = await postResponse(vpToken, sess.session.state);
	assert.equal(status, 401, "wrong count (1 of 2) → 401");
});