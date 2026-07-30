// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.1a (did-issuer-wallet-expansion, hybrid key model): the issuer
// advertises BOTH keys (Ed25519/EdDSA OKP + P-256/ES256 EC) in
// /.well-known/jwt-vc-issuer, + signEs256Jwt produces a JOSE-conformant ES256
// JWS (raw r‖s) that verifies against the advertised P-256 JWK.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { tmpdir } from "node:os";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { app } from "../src/index";
import { loadOrCreateP256IssuerKey, signEs256Jwt } from "../src/keys";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

test("1.1a: /.well-known/jwt-vc-issuer advertises BOTH keys (EdDSA OKP + ES256 EC)", async () => {
	const res = await app.request("/.well-known/jwt-vc-issuer");
	assert.equal(res.status, 200);
	const body = (await res.json()) as { jwks: { keys: Array<Record<string, string>> } };
	const keys = body.jwks.keys;
	const ed = keys.find((k) => k.alg === "EdDSA");
	const es = keys.find((k) => k.alg === "ES256");
	assert.ok(ed, "Ed25519/EdDSA key present");
	assert.equal(ed!.kty, "OKP");
	assert.equal(ed!.crv, "Ed25519");
	assert.ok(es, "P-256/ES256 key present");
	assert.equal(es!.kty, "EC");
	assert.equal(es!.crv, "P-256");
	assert.ok(es!.x && es!.y, "P-256 JWK has base64url x + y");
	// the advertised ES256 JWK reconstructs a usable EC public key
	assert.doesNotThrow(() => createPublicKey({ key: es!, format: "jwk" }));
});

test("1.1a: signEs256Jwt produces a JOSE-conformant ES256 JWS (raw r‖s) verifiable against the P-256 JWK", () => {
	const dir = mkdtempSync(join(tmpdir(), "mneurix-did-issuer-"));
	try {
		const key = loadOrCreateP256IssuerKey(dir);
		const payload = {
			sub: "https://did-issuer.mneurix.example/statuslists/revocation/1",
			iat: 1700000000,
			status_list: { bits: 1, vals: "AAAA" },
		};
		const jwt = signEs256Jwt(payload, key, key.kid, "statuslist+jwt");
		const parts = jwt.split(".");
		assert.equal(parts.length, 3, "compact JWS header.payload.signature");
		const [h, p, sig] = parts as [string, string, string];
		const header = JSON.parse(b64urlDecode(h).toString("utf8")) as Record<string, unknown>;
		assert.equal(header.alg, "ES256");
		assert.equal(header.typ, "statuslist+jwt");
		assert.equal(header.kid, key.kid);
		const sigBytes = b64urlDecode(sig);
		assert.equal(sigBytes.length, 64, "ES256 signature is raw r‖s (64 bytes), not DER");
		const pub = createPublicKey({ key: key.jwk, format: "jwk" });
		const signingInput = Buffer.from(h + "." + p, "ascii");
		const valid = verify("SHA256", signingInput, { key: pub, dsaEncoding: "ieee-p1363" }, sigBytes);
		assert.equal(valid, true, "ES256 JWS verifies against the P-256 JWK");
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});