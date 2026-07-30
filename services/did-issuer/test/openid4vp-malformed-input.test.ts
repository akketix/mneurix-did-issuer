// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Fresh-eyes review regression tests: malformed attacker-supplied input must
// yield a clean 401/400 (fail-closed), NOT an unhandled-throw 500. Covers the
// unencrypted receiver (a malformed disclosure inside an otherwise-peekable
// SD-JWT+KB) + the encrypted receiver (a malformed JARM JWT header).
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
const SUBJECT = "did:web:lattice.mneurix.example/learners/6";

const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

before(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });
afterEach(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });

async function request(): Promise<{ nonce: string; state: string; clientId: string }> {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT, claims: ["score"] }) });
	const body = (await res.json()) as { session: { nonce: string; state: string } };
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL };
}

async function requestEncrypted(): Promise<{ nonce: string; state: string; clientId: string; recipientJwk: Record<string, unknown> }> {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT, claims: ["score"], encrypted: true }) });
	const body = (await res.json()) as { session: { nonce: string; state: string }; client_metadata: { jwks: { keys: Array<Record<string, unknown>> } } };
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL, recipientJwk: body.client_metadata.jwks.keys[0]! };
}

async function issueEs256(holderJwk: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9, given_name: "M" }, selectivelyDisclosable: ["score"], holderJwk, alg: "ES256" }),
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

async function postUnencrypted(vpToken: string, state: string): Promise<number> {
	const res = await app.request("/openid4vp/response", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ vp_token: vpToken, state }).toString() });
	return res.status;
}

async function postEncrypted(state: string, jwe: string): Promise<number> {
	const res = await app.request(`/openid4vp/response/${state}`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ response: jwe }).toString() });
	return res.status;
}

test("malformed input: a malformed disclosure in an otherwise-peekable SD-JWT+KB -> 401 (not 500)", async () => {
	const { jwk, seed } = holder();
	const sess = await request();
	const vc1 = await issueEs256(jwk); // issuerJwt~disc~  (ends with "~", no KB-JWT)
	const issuerJwt = vc1.split("~")[0]!;
	// Build a valid KB-JWT (holder-bound to the session nonce) so peekKbJwtNonce succeeds;
	// the verify then throws on the GARBAGE disclosure -> caught -> 401, not 500.
	const sdHash = b64url(createHash("sha256").update(Buffer.from(`${issuerJwt}~GARBAGE~`, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), seed);
	const vpToken = `${issuerJwt}~GARBAGE~${kbHeader}.${kbPayload}.${b64url(kbSig)}`;
	const status = await postUnencrypted(vpToken, sess.state);
	assert.equal(status, 401, "malformed disclosure -> 401 (fail-closed), not a 500");
});

test("malformed input: a malformed JARM header (encrypted) -> 401 (not 500)", async () => {
	const sess = await requestEncrypted();
	// A JARM-looking plaintext (3 dot-parts, no "="/"&"/"~") with an invalid header.
	const malformedJarm = "xxxxx.yyy.zzz";
	const jwe = await encryptResponse(malformedJarm, sess.recipientJwk);
	const status = await postEncrypted(sess.state, jwe);
	assert.equal(status, 401, "malformed JARM -> 401 (fail-closed), not a 500");
});

test("malformed input: /v1/presentations:verify with a malformed VC -> 200 { verified: false } (not 500)", async () => {
	const res = await app.request("/v1/presentations:verify", { method: "POST", headers: H, body: JSON.stringify({ presentation: "a.b.c" }) });
	assert.equal(res.status, 200, "malformed VC -> 200 (clean rejection), not 500");
	const body = (await res.json()) as { verified: boolean; status: string; reason?: string };
	assert.equal(body.verified, false);
	assert.equal(body.status, "rejected");
	assert.match(body.reason ?? "", /malformed/);
});
