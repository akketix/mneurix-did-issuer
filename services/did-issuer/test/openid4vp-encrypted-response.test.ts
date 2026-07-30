// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.4 (did-issuer-wallet-expansion): encrypted OpenID4VP responses
// (direct_post.jwt / JWE ECDH-ES + A128GCM). The verifier advertises a per-
// request ephemeral ECDH-ES public key in the request client_metadata; the
// wallet encrypts the vp_token response to it; the receiver decrypts (jose)
// + verifies the SD-JWT VC + KB-JWT.
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
const SUBJECT = "did:web:lattice.mneurix.example/learners/55";

const b64url = (b: Buffer | string) => (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url");

before(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });
afterEach(() => { _resetStatusForTests(); _resetOpenid4vpForTests(); });

async function requestEncrypted(): Promise<{ nonce: string; state: string; clientId: string; recipientJwk: Record<string, unknown> }> {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT, claims: ["score"], encrypted: true }) });
	assert.equal(res.status, 201);
	const body = (await res.json()) as {
		session: { nonce: string; state: string; responseUri: string };
		client_metadata: { jwks: { keys: Array<Record<string, unknown>> }; encrypted_response_alg: string; encrypted_response_enc: string };
	};
	// the response_uri is per-state for encrypted requests
	assert.equal(body.session.responseUri, `${ISSUER_URL}/openid4vp/response/${body.session.state}`);
	assert.equal(body.client_metadata.encrypted_response_alg, "ECDH-ES");
	assert.equal(body.client_metadata.encrypted_response_enc, "A128GCM");
	const recipientJwk = body.client_metadata.jwks.keys[0]!;
	assert.equal(recipientJwk.kty, "EC");
	assert.equal(recipientJwk.crv, "P-256");
	return { nonce: body.session.nonce, state: body.session.state, clientId: ISSUER_URL, recipientJwk };
}

async function issueEs256SdJwt(holderJwk: Record<string, string>): Promise<string> {
	const res = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9, given_name: "Carol" }, selectivelyDisclosable: ["score"], holderJwk, alg: "ES256" }),
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

test("1.4: encrypted direct_post.jwt — wallet encrypts the vp_token response; receiver decrypts + verifies", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
	const holderSeed = new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url"));

	const sess = await requestEncrypted();
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	assert.ok(sdJwtWithoutKb.endsWith("~"));

	// Build the KB-JWT (Ed25519 holder) bound to the session nonce + clientId.
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	const vpToken = sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`;

	// Encrypt the form-encoded response to the verifier's ephemeral ECDH-ES key.
	const plaintext = new URLSearchParams({ vp_token: vpToken, state: sess.state }).toString();
	const jwe = await encryptResponse(plaintext, sess.recipientJwk);

	const r = await postEncrypted(sess.state, jwe);
	assert.equal(r.status, 200);
	assert.equal(r.body.verified, true);
	assert.equal(r.body.subject, SUBJECT);

	// replay -> 401 (session consumed)
	const replay = await postEncrypted(sess.state, jwe);
	assert.equal(replay.status, 401);
});

test("1.4: encrypted response with a wrong path state -> 401 (no matching session)", async () => {
	const sess = await requestEncrypted();
	const jwe = await encryptResponse("vp_token=x&state=wrong", sess.recipientJwk);
	const r = await postEncrypted("not-the-session-state", jwe);
	assert.equal(r.status, 401);
});

test("1.4: tampered/garbage JWE -> 401 (decryption fails, fail-closed)", async () => {
	const { publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
	const sess = await requestEncrypted();
	await issueEs256SdJwt(holderJwk); // not used; just to consume nothing
	const r = await postEncrypted(sess.state, "not.a.valid.jwe");
	assert.equal(r.status, 401);
});