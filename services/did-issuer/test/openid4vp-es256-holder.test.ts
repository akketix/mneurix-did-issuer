// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.5 (ES256 holder binding): the KB-JWT holder binding now accepts a
// P-256 (ES256) holder key, not just Ed25519 — HAIP/EUDI wallets (HAIP §7
// mandates ES256-capable KB-JWTs) can present with their ES256 holder key.
// An ES256 SD-JWT VC + an ES256 KB-JWT presented against a verifier session.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createHash, createSign } from "node:crypto";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetOpenid4vpForTests } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;
const SUBJECT = "did:web:lattice.mneurix.example/learners/66";

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
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9, given_name: "Bob" }, selectivelyDisclosable: ["score"], holderJwk, alg: "ES256" }),
	});
	assert.equal(res.status, 201);
	return ((await res.json()) as { credential: string }).credential;
}

async function postResponse(vpToken: string, state: string): Promise<{ status: number; body: { verified?: boolean; subject?: string; issuer?: string } }> {
	const res = await app.request("/openid4vp/response", {
		method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({ vp_token: vpToken, state }).toString(),
	});
	return { status: res.status, body: (await res.json()) as { verified?: boolean; subject?: string; issuer?: string } };
}

function es256Holder() {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	return {
		holderJwk: publicKey.export({ format: "jwk" }) as Record<string, string>,
		holderPrivateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
	};
}

function es256KbJwt(holderPrivateKeyPem: string, sdJwtWithoutKb: string, nonce: string, aud: string): string {
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "ES256", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce, aud, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = createSign("SHA256").update(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii")).sign({ key: holderPrivateKeyPem, dsaEncoding: "ieee-p1363" });
	return `${kbHeader}.${kbPayload}.${b64url(kbSig)}`;
}

test("1.5: ES256 SD-JWT VC + ES256 (P-256) holder KB-JWT verifies at the receiver", async () => {
	const { holderJwk, holderPrivateKeyPem } = es256Holder();
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	assert.ok(sdJwtWithoutKb.endsWith("~"));
	const vpToken = sdJwtWithoutKb + es256KbJwt(holderPrivateKeyPem, sdJwtWithoutKb, sess.nonce, sess.clientId);
	const r = await postResponse(vpToken, sess.state);
	assert.equal(r.status, 200);
	assert.equal(r.body.verified, true);
	assert.equal(r.body.subject, SUBJECT);
	assert.equal(r.body.issuer, ISSUER_URL);
});

test("1.5: ES256 holder KB-JWT with wrong nonce -> 401 (fail-closed)", async () => {
	const { holderJwk, holderPrivateKeyPem } = es256Holder();
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	const vpToken = sdJwtWithoutKb + es256KbJwt(holderPrivateKeyPem, sdJwtWithoutKb, "wrong-nonce", sess.clientId);
	const r = await postResponse(vpToken, sess.state);
	assert.equal(r.status, 401);
});

test("1.5: an Ed25519-holder ES256 SD-JWT VC still verifies (mixed issuer-ES256/holder-Ed25519, no regression)", async () => {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const holderJwk = publicKey.export({ format: "jwk" }) as Record<string, string>;
	const holderSeed = new Uint8Array(Buffer.from((privateKey.export({ format: "jwk" }) as { d: string }).d, "base64url"));
	const { signAsync } = await import("@noble/ed25519");
	const sess = await requestPresentation();
	const sdJwtWithoutKb = await issueEs256SdJwt(holderJwk);
	const sdHash = b64url(createHash("sha256").update(Buffer.from(sdJwtWithoutKb, "ascii")).digest());
	const kbHeader = b64url(JSON.stringify({ alg: "EdDSA", typ: "kb+jwt" }));
	const kbPayload = b64url(JSON.stringify({ nonce: sess.nonce, aud: sess.clientId, iat: Math.floor(Date.now() / 1000), sd_hash: sdHash }));
	const kbSig = await signAsync(Buffer.from(`${kbHeader}.${kbPayload}`, "ascii"), holderSeed);
	const r = await postResponse(sdJwtWithoutKb + `${kbHeader}.${kbPayload}.${b64url(kbSig)}`, sess.state);
	assert.equal(r.status, 200);
	assert.equal(r.body.verified, true);
});