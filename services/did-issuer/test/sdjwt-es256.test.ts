// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.1b (did-issuer-wallet-expansion, hybrid key model): SD-JWT VC issuance
// supports ES256 (P-256, HAIP/EUDI wallet path) alongside the default EdDSA
// (Ed25519, did:web). The ES256 issuer-JWT header carries alg=ES256; the
// signature verifies against the P-256 JWK advertised in jwt-vc-issuer.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify } from "node:crypto";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const SUBJECT = "did:web:lattice.mneurix.example/learners/88";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

before(() => _resetStatusForTests());

test("1.1b: SD-JWT VC issued with alg ES256; header alg=ES256; signature verifies against the advertised P-256 JWK", async () => {
	_resetStatusForTests();
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: H,
		body: JSON.stringify({
			subjectId: SUBJECT,
			secure: "sd-jwt-vc",
			vct: `${ISSUER_URL}/vct/achievement`,
			claims: { score: 0.9 },
			selectivelyDisclosable: ["score"],
			alg: "ES256",
		}),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: string; format: string };
	assert.equal(ib.format, "dc+sd-jwt");
	const jwtPart = ib.credential.split("~")[0]!;
	const [h, p, sig] = jwtPart.split(".") as [string, string, string];
	const header = JSON.parse(b64urlDecode(h).toString("utf8")) as Record<string, unknown>;
	assert.equal(header.alg, "ES256");
	assert.equal(header.typ, "dc+sd-jwt");
	// x5c is absent in dev (no issuer cert generated yet); HAIP prod adds it.

	// Verify the issuer-JWT signature against the advertised P-256 JWK.
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as {
		jwks: { keys: Array<Record<string, unknown>> };
	};
	const es = meta.jwks.keys.find((k) => k.alg === "ES256")!;
	const pub = createPublicKey({ key: es, format: "jwk" });
	const signingInput = Buffer.from(h + "." + p, "ascii");
	const valid = verify("SHA256", signingInput, { key: pub, dsaEncoding: "ieee-p1363" }, b64urlDecode(sig));
	assert.equal(valid, true, "ES256 SD-JWT VC issuer-JWT verifies against the P-256 JWK");
});

test("1.1b: SD-JWT VC default (no alg) still issues EdDSA (no regression)", async () => {
	_resetStatusForTests();
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: H,
		body: JSON.stringify({
			subjectId: SUBJECT,
			secure: "sd-jwt-vc",
			vct: `${ISSUER_URL}/vct/achievement`,
			claims: { score: 0.9 },
			selectivelyDisclosable: ["score"],
		}),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: string };
	const jwtPart = ib.credential.split("~")[0]!;
	const header = JSON.parse(b64urlDecode(jwtPart.split(".")[0]!).toString("utf8")) as Record<string, unknown>;
	assert.equal(header.alg, "EdDSA");
});