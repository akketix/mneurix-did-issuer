// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task JARM (did-issuer-wallet-expansion): the JWT-Secured Authorization
// Response Mode layer — the encrypted (direct_post.jwt) response wraps a
// wallet-SIGNED JWT (not just a form). The receiver decrypts the JWE, verifies
// the JARM JWT signature (with the header's jwk) + aud, then verifies the
// vp_token (SD-JWT VC + KB-JWT) inside.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash } from "node:crypto";
import { signAsync } from "@noble/ed25519";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetOpenid4vpForTests } from "../src/openid4vp";
import { encryptResponse } from "../src/jwe";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;
const SUBJECT = "did:web:lattice.mneurix.example/learners/33";

const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

before(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });
afterEach(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });

async function requestEncrypted(): Promise<{ nonce: string; state: string; clientId: string; recipientJwk: Record<string, unknown> }> {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT, claims: ["score"], encrypted: true }) });
	const body = (await res.json()) as { session: { nonce: string; state: string }; client_metadata: { jwks: { keys: Array<Record<string, unknown>> } } };
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL, recipientJwk: body.client_metadata.jwks.keys[0]! };
}

async function issueEs256SdJwt(holderJwk: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9, given_name: "Dan" }, selectivelyDisclosable: ["score"], holderJwk, alg: "ES256" }),
	});
	assert.equal(res.status, 201);
	return ((await res.json()) as { credential: string }).credential;
}

async function postEncrypted(state: string, jwe: string): Promise<{ status: number; body: { verified?: boolean; subject?: string; message?: string } }> {
	const res = await app.request(`/openid4vp/response/${state}`, {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ response: jwe }).toString(),
	});
	return { status: res.status, body: (await res.json()) as { verified?: boolean; subject?: string; message?: string } };
}

function holder() {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		holderJwk: publicKey.export({ format: "jwk" }) as Record<string, string>,
		holderSeed: new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url")),
	};
}

async function buildVpToken(sess: { nonce: string; clientId: string }, holderJwk: Record<string, string>, holderSeed: Uint8Array): Promise<string> {
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	return sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`;
}

test("JARM: encrypted response wraps a wallet-signed JWT; receiver verifies JARM sig + aud + the vp_token", async () => {
	const { holderJwk, holderSeed } = holder();
	const sess = await requestEncrypted();
	const vpToken = await buildVpToken(sess, holderJwk, holderSeed);
	// Build the JARM JWT (signed by the holder key; header carries the holder jwk).
	const jarmHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "jwt", jwk: holderJwk }));
	const jarmPayload = b64url(JSON.stringify({ vp_token: vpToken, state: sess.state, aud: sess.clientId, iat: Math.floor(Date.now() / 1000) }));
	const jarmSig = await signAsync(Buffer.from(`${jarmHeader}.${jarmPayload}`, "ascii"), holderSeed);
	const jarm = `${jarmHeader}.${jarmPayload}.${b64url(jarmSig)}`;
	const jwe = await encryptResponse(jarm, sess.recipientJwk);
	const r = await postEncrypted(sess.state, jwe);
	assert.equal(r.status, 200);
	assert.equal(r.body.verified, true);
	assert.equal(r.body.subject, SUBJECT);
	// replay -> 401 (session consumed)
	assert.equal((await postEncrypted(sess.state, jwe)).status, 401);
});

test("JARM: wrong aud -> 401 (verifier client_id mismatch)", async () => {
	const { holderJwk, holderSeed } = holder();
	const sess = await requestEncrypted();
	const vpToken = await buildVpToken(sess, holderJwk, holderSeed);
	const jarmHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "jwt", jwk: holderJwk }));
	const jarmPayload = b64url(JSON.stringify({ vp_token: vpToken, state: sess.state, aud: "https://wrong-verifier.example", iat: Math.floor(Date.now() / 1000) }));
	const jarmSig = await signAsync(Buffer.from(`${jarmHeader}.${jarmPayload}`, "ascii"), holderSeed);
	const r = await postEncrypted(sess.state, await encryptResponse(`${jarmHeader}.${jarmPayload}.${b64url(jarmSig)}`, sess.recipientJwk));
	assert.equal(r.status, 401);
});

test("JARM: tampered JARM signature -> 401 (fail-closed)", async () => {
	const { holderJwk, holderSeed } = holder();
	const sess = await requestEncrypted();
	const vpToken = await buildVpToken(sess, holderJwk, holderSeed);
	const jarmHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "jwt", jwk: holderJwk }));
	const jarmPayload = b64url(JSON.stringify({ vp_token: vpToken, state: sess.state, aud: sess.clientId, iat: Math.floor(Date.now() / 1000) }));
	// sign with a DIFFERENT key (a forgery) -> the JARM sig won't verify against the header jwk.
	const forge = generateKeyPairSync("ed25519");
	const forgedSig = await signAsync(Buffer.from(`${jarmHeader}.${jarmPayload}`, "ascii"), new Uint8Array(Buffer.from((forge.privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url")));
	const r = await postEncrypted(sess.state, await encryptResponse(`${jarmHeader}.${jarmPayload}.${b64url(forgedSig)}`, sess.recipientJwk));
	assert.equal(r.status, 401);
});