// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

import { test } from "node:test";
import assert from "node:assert/strict";
import { buildDidDocument, didFor, publicKeyJwkFromPem } from "../src/did";
import { loadOrCreateIssuerKey } from "../src/keys";
import { _resetForTests } from "../src/store";
import { app } from "../src/index";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };

test("did:web document is DID-Core-shaped", () => {
	const key = loadOrCreateIssuerKey(undefined);
	const jwk = publicKeyJwkFromPem(key.publicKeyPem);
	const doc = buildDidDocument("example.com", key.kid, jwk);
	assert.equal(doc.id, "did:web:example.com");
	assert.equal(doc["@context"][0], "https://www.w3.org/ns/did/v1");
	assert.equal(doc.verificationMethod[0].type, "JsonWebKey");
	assert.equal(doc.verificationMethod[0].controller, "did:web:example.com");
	assert.equal(doc.verificationMethod[0].id, "did:web:example.com#" + key.kid);
	assert.equal(doc.assertionMethod[0], "did:web:example.com#" + key.kid);
	assert.equal(jwk.kty, "OKP");
	assert.equal(jwk.crv, "Ed25519");
	assert.ok(jwk.x.length > 0);
});

test("mint -> resolve round-trip via the API", async () => {
	_resetForTests();
	const mint = await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: "acme.test" }) });
	assert.equal(mint.status, 201);
	const mb = (await mint.json()) as { did: string; document: { id: string } };
	assert.equal(mb.did, "did:web:acme.test");
	const res = await app.request("/v1/dids/" + encodeURIComponent("did:web:acme.test"), { headers: H });
	assert.equal(res.status, 200);
	const rb = (await res.json()) as { did: string; document: { id: string } };
	assert.equal(rb.document.id, "did:web:acme.test");
});

test("well-known serves the canonical-origin DID document", async () => {
	const r = await app.request("/.well-known/did.json");
	assert.equal(r.status, 200);
	const b = (await r.json()) as { id: string; verificationMethod: unknown[] };
	assert.equal(b.id, didFor("did-issuer.mneurix.example"));
	assert.ok(Array.isArray(b.verificationMethod), "DID doc has verificationMethod");
});

test("mint rejects a bad origin + no-token is 401", async () => {
	const bad = await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: "bad origin!" }) });
	assert.equal(bad.status, 400);
	const noTok = await app.request("/v1/dids", { method: "POST", body: JSON.stringify({ origin: "x.test" }) });
	assert.equal(noTok.status, 401);
});
