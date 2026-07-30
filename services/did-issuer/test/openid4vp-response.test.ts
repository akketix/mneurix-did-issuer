// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.3 (did-issuer-wallet-expansion): the OpenID4VP response receiver —
// POST /openid4vp/response closes the verifier loop: the wallet POSTs the
// vp_token (SD-JWT VC + KB-JWT) + state; the receiver binds it to the verifier
// session (state + KB-JWT nonce) + verifies the SD-JWT VC + KB-JWT holder
// binding (reuses verifyPresentation).
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { signAsync } from "@noble/ed25519";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetRevokedKidsForTests } from "../src/revoked-kids";
import { _resetForTests as resetDidStore } from "../src/store";
import { _resetOpenid4vpForTests } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const ISSUER_ORIGIN = "did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;
const SUBJECT = "did:web:lattice.mneurix.example/learners/42";

const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

before(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); _resetOpenid4vpForTests(); });
afterEach(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); _resetOpenid4vpForTests(); });

async function mint(): Promise<void> {
	await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: ISSUER_ORIGIN }) });
}

async function requestPresentation(): Promise<{ nonce: string; state: string; clientId: string }> {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT, claims: ["score"] }) });
	const body = (await res.json()) as { session: { nonce: string; state: string; responseUri: string; vct: string; claims: string[] } };
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL };
}

async function issueHolderBoundSdJwt(holderJwk: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.85, given_name: "Alice" }, selectivelyDisclosable: ["score"], holderJwk }),
	});
	assert.equal(res.status, 201);
	return ((await res.json()) as { credential: string }).credential;
}

async function postResponse(vpToken: string, state: string): Promise<{ status: number; body: { verified?: boolean; error?: string; message?: string } }> {
	const res = await app.request("/openid4vp/response", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ vp_token: vpToken, state }).toString(),
	});
	return { status: res.status, body: (await res.json()) as { verified?: boolean; error?: string; message?: string } };
}

test("1.3: receiver verifies a holder-bound SD-JWT VC presented against a verifier session", async () => {
	await mint();
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
	const holderSeed = new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url"));

	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueHolderBoundSdJwt(holderJwk);
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

	const replay = await postResponse(vpToken, sess.state);
	assert.equal(replay.status, 401);
});

test("1.3: wrong KB-JWT nonce -> 401 (session nonce mismatch, fail-closed)", async () => {
	await mint();
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
	const holderSeed = new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url"));
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueHolderBoundSdJwt(holderJwk);
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: "wrong-nonce", aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	const r = await postResponse(sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`, sess.state);
	assert.equal(r.status, 401);
});

test("1.3: no KB-JWT (non-holder-bound) -> 401", async () => {
	await mint();
	const { publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueHolderBoundSdJwt(holderJwk);
	const r = await postResponse(sdJwtWithoutKb, sess.state);
	assert.equal(r.status, 401);
});

test("1.3: wrong state -> 401 (no matching session)", async () => {
	await mint();
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as { kty: string; crv: string; x: string };
	const holderSeed = new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url"));
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueHolderBoundSdJwt(holderJwk);
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	const r = await postResponse(sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`, "wrong-state");
	assert.equal(r.status, 401);
});

test("1.3: missing vp_token/state -> 400", async () => {
	const r = await postResponse("", "");
	assert.equal(r.status, 400);
});