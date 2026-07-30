// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.1c (did-issuer-wallet-expansion): the ES256 (P-256) issuer key carries
// an `x5c` chain (HAIP §6.1.1) — advertised in /.well-known/jwt-vc-issuer + in
// the ES256 SD-JWT VC header. The dev cert is self-signed (exercises the x5c
// plumbing); prod replaces it with an IACA-issued cert.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { X509Certificate } from "node:crypto";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;
const SUBJECT = "did:web:lattice.mneurix.example/learners/44";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

before(() => _resetStatusForTests());
afterEach(() => _resetStatusForTests());

test("1.1c: /.well-known/jwt-vc-issuer ES256 key carries x5c; the cert parses + its key matches the JWK", async () => {
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as {
		jwks: { keys: Array<Record<string, unknown>> };
	};
	const es = meta.jwks.keys.find((k) => k.alg === "ES256")!;
	assert.ok(Array.isArray(es.x5c) && (es.x5c as string[]).length > 0, "ES256 key advertises x5c");
	const cert = new X509Certificate(Buffer.from((es.x5c as string[])[0]!, "base64"));
	assert.equal(cert.publicKey.asymmetricKeyType, "ec");
	const cpk = cert.publicKey.export({ format: "jwk" }) as { x: string; y: string };
	assert.equal(cpk.x, es.x, "cert public key x matches the ES256 JWK");
	assert.equal(cpk.y, es.y, "cert public key y matches the ES256 JWK");
	assert.ok(cert.verify(cert.publicKey), "self-signed dev cert verifies with its own key");
});

test("1.1c: an ES256 SD-JWT VC header carries x5c (the cert matches the issuer ES256 key)", async () => {
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9 }, selectivelyDisclosable: ["score"], alg: "ES256" }),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: string };
	const header = JSON.parse(b64urlDecode(ib.credential.split("~")[0]!.split(".")[0]!).toString("utf8")) as Record<string, unknown>;
	assert.equal(header.alg, "ES256");
	assert.ok(Array.isArray(header.x5c) && (header.x5c as string[]).length > 0, "ES256 SD-JWT VC header carries x5c");
	// the x5c cert's key matches the advertised ES256 JWK
	const cert = new X509Certificate(Buffer.from((header.x5c as string[])[0]!, "base64"));
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as { jwks: { keys: Array<Record<string, unknown>> } };
	const es = meta.jwks.keys.find((k) => k.alg === "ES256")!;
	const cpk = cert.publicKey.export({ format: "jwk" }) as { x: string; y: string };
	assert.equal(cpk.x, es.x);
	assert.equal(cpk.y, es.y);
});

test("1.1c: an EdDSA SD-JWT VC header does NOT carry x5c (x5c is ES256/HAIP-only)", async () => {
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, secure: "sd-jwt-vc", vct: VCT, claims: { score: 0.9 }, selectivelyDisclosable: ["score"] }),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: string };
	const header = JSON.parse(b64urlDecode(ib.credential.split("~")[0]!.split(".")[0]!).toString("utf8")) as Record<string, unknown>;
	assert.equal(header.alg, "EdDSA");
	assert.equal(header.x5c, undefined, "EdDSA/did:web path does not carry x5c");
});