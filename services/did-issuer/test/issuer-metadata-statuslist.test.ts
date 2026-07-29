// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.3 (did-issuer-wallet-expansion): jwt-vc-issuer metadata (vct_values),
// the vct type-definition endpoint, + the IETF Token Status List JWT endpoint
// (signed, verifiable against the issuer JWKS).
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyAsync } from "@noble/ed25519";
import { app } from "../src/index";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

test("1.3: /.well-known/jwt-vc-issuer metadata advertises the Ed25519 JWK + vct_values", async () => {
	const res = await app.request("/.well-known/jwt-vc-issuer");
	assert.equal(res.status, 200);
	const body = (await res.json()) as {
		issuer: string;
		jwks: { keys: Array<Record<string, string>> };
		vct_values?: string[];
	};
	assert.ok(body.issuer, "issuer present");
	assert.ok(Array.isArray(body.jwks?.keys) && body.jwks.keys.length > 0, "jwks present");
	const key = body.jwks.keys[0]!;
	assert.equal(key.alg, "EdDSA");
	assert.equal(key.kty, "OKP");
	assert.equal(key.crv, "Ed25519");
	assert.ok(Array.isArray(body.vct_values) && body.vct_values.length > 0, "vct_values advertised");
	assert.match(body.vct_values[0]!, /\/vct\/achievement$/);
});

test("1.3: GET /vct/achievement returns the vct definition; unknown vct -> 404", async () => {
	const ok = await app.request("/vct/achievement");
	assert.equal(ok.status, 200);
	const def = (await ok.json()) as { vct: string; name: string; description: string };
	assert.match(def.vct, /\/vct\/achievement$/);
	assert.ok(def.name);
	assert.ok(def.description);

	// cross-check: the vct definition matches the metadata's advertised vct
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as {
		vct_values?: string[];
	};
	assert.equal(def.vct, meta.vct_values?.[0]);

	const notFound = await app.request("/vct/unknown");
	assert.equal(notFound.status, 404);
});

test("1.3: GET /statuslists/revocation/1 returns a signed IETF status-list JWT (verifiable against the issuer JWKS)", async () => {
	// Fetch the issuer public key (JWK) from the metadata.
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as {
		jwks: { keys: Array<Record<string, string>> };
	};
	const x = meta.jwks.keys[0]!.x!;
	const pub = b64urlDecode(x); // 32-byte raw Ed25519 public key

	const res = await app.request("/statuslists/revocation/1");
	assert.equal(res.status, 200);
	assert.match(res.headers.get("content-type") ?? "", /statuslist\+jwt/);
	const jwt = await res.text();
	const parts = jwt.split(".");
	assert.equal(parts.length, 3, "compact JWS header.payload.signature");

	const [h, p, sig] = parts as [string, string, string];
	const header = JSON.parse(b64urlDecode(h).toString("utf8")) as Record<string, unknown>;
	assert.equal(header.typ, "statuslist+jwt");
	assert.equal(header.alg, "EdDSA");

	const payload = JSON.parse(b64urlDecode(p).toString("utf8")) as {
		sub: string;
		iat: number;
		status_list: { bits: number; vals: string };
	};
	assert.match(payload.sub, /\/statuslists\/revocation\/1$/);
	assert.equal(payload.status_list.bits, 1);
	assert.equal(typeof payload.status_list.vals, "string");
	assert.ok(payload.status_list.vals.length > 0, "vals is a non-empty base64url bitstring");
	assert.ok(typeof payload.iat === "number");

	// Verify the Ed25519 signature against the issuer JWK.
	const signingInput = Buffer.from(h + "." + p, "ascii");
	const valid = await verifyAsync(
		new Uint8Array(b64urlDecode(sig)),
		signingInput,
		new Uint8Array(pub),
	);
	assert.equal(valid, true, "status-list JWT signature verifies against the issuer JWK");
});

test("1.3: GET /statuslists/<invalid-purpose>/1 -> 400", async () => {
	const res = await app.request("/statuslists/bogus/1");
	assert.equal(res.status, 400);
});