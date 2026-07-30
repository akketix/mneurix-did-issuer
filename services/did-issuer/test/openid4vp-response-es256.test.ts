// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.3 (ES256 verify path): the OpenID4VP response receiver verifies an
// ES256 (P-256) SD-JWT VC presentation — the HAIP/EUDI wallet-path mirror of
// the EdDSA/did:web receiver test. The issuer key is the in-process P-256 key
// (the did-issuer verifying its own ES256 credential, iss = HTTPS issuer); the
// holder binding is an Ed25519 KB-JWT (the wallet's holder key).
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { signAsync } from "@noble/ed25519";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetOpenid4vpForTests } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;
const SUBJECT = "did:web:lattice.mneurix.example/learners/77";

const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

before(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });
afterEach(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });

async function requestPresentation(): Promise<{ nonce: string; state: string; clientId: string }> {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT, claims: ["score"] }) });
	const body = (await res.json()) as { session: { nonce: string; state: string } };
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL };
}

async function issueEs256SdJwt(holderJwk: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9, given_name: "Alice" }, selectivelyDisclosable: ["score"], holderJwk, alg: "ES256" }),
	});
	assert.equal(res.status, 201);
	return ((await res.json()) as { credential: string }).credential;
}

async function postResponse(vpToken: string, state: string): Promise<{ status: number; body: { verified?: boolean; subject?: string; issuer?: string; message?: string } }> {
	const res = await app.request("/openid4vp/response", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ vp_token: vpToken, state }).toString(),
	});
	return { status: res.status, body: (await res.json()) as { verified?: boolean; subject?: string; issuer?: string; message?: string } };
}

function holderKeypair() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
	const holderSeed = new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url"));
	return { holderJwk, holderSeed };
}

test("1.3 ES256: receiver verifies an ES256 SD-JWT VC + Ed25519 KB-JWT holder binding", async () => {
	const { holderJwk, holderSeed } = holderKeypair();
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	assert.ok(sdJwtWithoutKb.endsWith("~"));

	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	const vpToken = sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`;

	const r = await postResponse(vpToken, sess.state);
	assert.equal(r.status, 200);
	assert.equal(r.body.verified, true);
	assert.equal(r.body.subject, SUBJECT);
	assert.equal(r.body.issuer, ISSUER_URL);
});

test("1.3 ES256: wrong KB-JWT nonce -> 401 (fail-closed)", async () => {
	const { holderJwk, holderSeed } = holderKeypair();
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: "wrong-nonce", aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	const r = await postResponse(sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`, sess.state);
	assert.equal(r.status, 401);
});

test("1.3 ES256: no KB-JWT -> 401 (peekKbJwtNonce returns null)", async () => {
	const { holderJwk } = holderKeypair();
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	const r = await postResponse(sdJwtWithoutKb, sess.state);
	assert.equal(r.status, 401);
});