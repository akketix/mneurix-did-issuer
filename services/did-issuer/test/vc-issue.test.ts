// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

import { test, before } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey } from "node:crypto";
import { app } from "../src/index";
import { verifyOb3 } from "../src/vc-issue";
import { verifySdJwtVc } from "../src/sdjwt";
import { _resetStatusForTests } from "../src/status";
import type { KeyMaterial, OpenBadgeCredential } from "@mneurix/shared";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };

before(() => _resetStatusForTests());

/** Fetch the issuer's public KeyMaterial from the public well-known DID document
 * (the did:web doc carries the Ed25519 publicKeyJwk). Public-only material is
 * fine for verification. */
async function issuerPublicKeyMaterial(): Promise<KeyMaterial> {
	const res = await app.request("/.well-known/did.json");
	const doc = (await res.json()) as { verificationMethod: { publicKeyJwk: Record<string, string> }[] };
	const jwk = doc.verificationMethod[0]!.publicKeyJwk;
	const publicKeyPem = createPublicKey({ key: jwk, format: "jwk" }).export({ format: "pem", type: "spki" }) as string;
	return { privateKeyPem: "", publicKeyPem, kid: "issuer" };
}

const achievement = {
	id: "https://lattice.mneurix.example/achievements/comp-1",
	type: ["Achievement"],
	name: "Mneurix Competency X",
	description: "A council-verified competency.",
	criteria: { narrative: "Pass the proctored summative assessment." },
	alignment: [],
};

const evidence = {
	kind: "council-formative" as const,
	id: "https://did-issuer.mneurix.example/evidence/sub-1",
	type: ["Evidence"],
	narrative: "Competence verified by a 3-model Mneurix council.",
	score: 0.85,
	agreement: 0.9,
	councilSize: 3,
	criterionScores: [{ criterionId: "c1", score: 0.9, reasoning: "strong" }],
	requiresHumanReview: false,
	isOfficialCertification: false,
	alignment: [],
};

const learnerDid = "did:web:lattice.mneurix.example/learners/42";

test("M5: /.well-known/jwt-vc-issuer serves issuer metadata + Ed25519 jwks", async () => {
	const res = await app.request("/.well-known/jwt-vc-issuer");
	assert.equal(res.status, 200);
	const body = (await res.json()) as { issuer: string; jwks: { keys: { kty: string; crv: string; kid: string; alg: string }[] } };
	assert.equal(body.issuer, "https://did-issuer.mneurix.example");
	const key = body.jwks.keys[0]!;
	assert.equal(key.kty, "OKP");
	assert.equal(key.crv, "Ed25519");
	assert.equal(key.alg, "EdDSA");
	assert.ok(key.kid.length > 0);
});

test("M5: OB3 Data-Integrity — issue + round-trip verify against the did:web key", async () => {
	_resetStatusForTests();
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: H,
		body: JSON.stringify({ subjectId: learnerDid, secure: "data-integrity", achievement, evidence }),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: OpenBadgeCredential; format: string; statusIndex: number };
	assert.equal(ib.format, "ob3");
	assert.equal(typeof ib.statusIndex, "number");
	assert.ok(ib.statusIndex >= 0);

	// Issuer + verificationMethod are did:web-anchored.
	const issuerDid = "did:web:did-issuer.mneurix.example";
	assert.equal(ib.credential.issuer.id, issuerDid);
	assert.equal(ib.credential.proof.verificationMethod.startsWith(issuerDid + "#"), true);
	assert.equal(ib.credential.credentialSubject.id, learnerDid);
	assert.equal(ib.credential.proof.cryptosuite, "ed25519-jcs-2020");
	assert.equal(ib.credential.credentialStatus?.type, "BitstringStatusListEntry");

	// Signature verifies against the published did:web public key.
	const keys = await issuerPublicKeyMaterial();
	assert.equal(await verifyOb3(ib.credential, keys), true);

	// Tamper-rejection: modifying the signed content (keeping the proof) breaks verification.
	const tampered: OpenBadgeCredential = {
		...ib.credential,
		credentialSubject: {
			...ib.credential.credentialSubject,
			achievement: { ...ib.credential.credentialSubject.achievement, name: "FORGED Competency" },
		},
	};
	assert.equal(await verifyOb3(tampered, keys), false);
});

test("M5: SD-JWT VC — issue, decode, selective disclosure, holder binding", async () => {
	_resetStatusForTests();
	const holderJwk = { kty: "OKP", crv: "Ed25519", x: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij" };
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: H,
		body: JSON.stringify({
			subjectId: learnerDid,
			secure: "sd-jwt-vc",
			vct: "https://lattice.mneurix.example/vct/mneurix-competency/v1",
			claims: { score: 0.85, agreement: 0.9, given_name: "Alice" },
			selectivelyDisclosable: ["score", "agreement"],
			holderJwk,
		}),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: string; format: string; statusIndex: number };
	assert.equal(ib.format, "dc+sd-jwt");
	assert.ok(ib.credential.includes("~"));
	assert.ok(ib.credential.endsWith("~")); // trailing tilde (no KB-JWT at issuance)
	assert.equal(typeof ib.statusIndex, "number");

	const keys = await issuerPublicKeyMaterial();

	// Full presentation (all disclosures) — signature valid + both SD claims disclosed.
	const full = await verifySdJwtVc(ib.credential, keys);
	assert.equal(full.signatureValid, true);
	assert.equal(full.allDisclosuresReferenced, true);
	assert.equal(full.processedPayload?.given_name, "Alice"); // plaintext
	assert.equal(full.processedPayload?.score, 0.85); // disclosed
	assert.equal(full.processedPayload?.agreement, 0.9); // disclosed
	assert.equal(full.processedPayload?.vct, "https://lattice.mneurix.example/vct/mneurix-competency/v1");
	assert.deepEqual(full.processedPayload?.cnf, { jwk: holderJwk }); // holder binding
	assert.equal(full.header?.alg, "EdDSA");
	assert.equal(full.header?.typ, "dc+sd-jwt");
	assert.equal(full.disclosures.length, 2);

	// Selective disclosure: present only the "score" disclosure (drop "agreement").
	const parts = ib.credential.split("~");
	const issuerJwt = parts[0]!;
	const disclosures = parts.slice(1, -1); // drop trailing empty
	const scoreDisclosure = disclosures.find((d) => {
		const [, name] = JSON.parse(Buffer.from(d, "base64url").toString("utf8")) as [string, string, unknown];
		return name === "score";
	})!;
	const presentation = `${issuerJwt}~${scoreDisclosure}~`;
	const partial = await verifySdJwtVc(presentation, keys);
	assert.equal(partial.signatureValid, true);
	assert.equal(partial.processedPayload?.score, 0.85); // the disclosed claim
	assert.equal("agreement" in (partial.processedPayload ?? {}), false); // NOT disclosed
	assert.equal(partial.processedPayload?.given_name, "Alice"); // plaintext still visible
	assert.equal(partial.disclosures.length, 1);

	// Tamper-rejection: flipping a byte of the signature invalidates it.
	const jwtParts = issuerJwt.split(".");
	const tamperedSig = jwtParts[2]!.slice(0, -2) + (jwtParts[2]!.slice(-2) === "AA" ? "BB" : "AA");
	const tamperedJwt = `${jwtParts[0]}.${jwtParts[1]}.${tamperedSig}`;
	const tampered = await verifySdJwtVc(`${tamperedJwt}~${disclosures.join("~")}~`, keys);
	assert.equal(tampered.signatureValid, false);
});

test("M5: /v1/vcs:issue rejects a bad secure value + missing fields", async () => {
	const bad = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: H,
		body: JSON.stringify({ subjectId: learnerDid, secure: "bogus" }),
	});
	assert.equal(bad.status, 400);

	const missing = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: H,
		body: JSON.stringify({ subjectId: learnerDid, secure: "data-integrity" }),
	});
	assert.equal(missing.status, 400); // achievement + evidence required

	const noTok = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ subjectId: learnerDid, secure: "data-integrity", achievement, evidence }),
	});
	assert.equal(noTok.status, 401);
});