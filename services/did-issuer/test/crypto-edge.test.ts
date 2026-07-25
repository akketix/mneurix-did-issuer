// services/did-issuer/test/crypto-edge.test.ts — Angle 1 crypto edge cases.
// Tests the RFC 9901 §7.1 unreferenced-disclosure rejection + other crypto edges.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetRevokedKidsForTests } from "../src/revoked-kids";
import { _resetForTests as resetDidStore } from "../src/store";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const enc = encodeURIComponent;
const ISSUER_ORIGIN = "did-issuer.mneurix.example";
const issuerDid = "did:web:" + ISSUER_ORIGIN;
const subjectId = "did:web:lattice.mneurix.example/learners/42";

before(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });
afterEach(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });

async function mint(): Promise<void> {
	await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: ISSUER_ORIGIN }) });
}

async function issueSdJwt(): Promise<string> {
	const r = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({
			subjectId, secure: "sd-jwt-vc",
			vct: "https://lattice.mneurix.example/vct/comp/v1",
			claims: { score: 0.85, given_name: "Alice" },
			selectivelyDisclosable: ["score"],
		}),
	});
	return ((await r.json()) as { credential: string }).credential;
}

async function verify(presentation: string, opts?: Record<string, unknown>): Promise<{ verified: boolean; status: string; reason?: string }> {
	const r = await app.request("/v1/presentations:verify", {
		method: "POST", headers: H,
		body: JSON.stringify({ presentation, ...opts }),
	});
	return (await r.json()) as { verified: boolean; status: string; reason?: string };
}

test("Angle1: SD-JWT with an unreferenced (forged) disclosure is rejected (RFC 9901 §7.1)", async () => {
	await mint();
	const credential = await issueSdJwt();
	// The credential is `issuerJwt~disc~` (one disclosure for "score").
	// Append a FORGED disclosure (not in _sd) to the presentation.
	const forgedDisclosure = Buffer.from(JSON.stringify(["fake-salt", "fakeClaim", "fakeValue"])).toString("base64url");
	const parts = credential.split("~"); // [issuerJwt, disc, ""]
	const issuerJwt = parts[0]!;
	const realDisclosure = parts[1]!;
	// Presentation with the real disclosure + the forged one: `issuerJwt~real~forged~`
	const tamperedPresentation = `${issuerJwt}~${realDisclosure}~${forgedDisclosure}~`;
	const result = await verify(tamperedPresentation);
	assert.equal(result.verified, false);
	assert.match(result.reason ?? "", /unreferenced disclosure/i);
});

test("Angle1: SD-JWT with only the real disclosure (no forgery) verifies", async () => {
	await mint();
	const credential = await issueSdJwt();
	const result = await verify(credential);
	assert.equal(result.verified, true);
});

test("Angle1: SD-JWT with a tampered issuer JWT signature is rejected", async () => {
	await mint();
	const credential = await issueSdJwt();
	const parts = credential.split("~");
	const issuerJwt = parts[0]!;
	const jwtParts = issuerJwt.split(".");
	// Flip the last 2 chars of the signature.
	const tamperedSig = jwtParts[2]!.slice(0, -2) + (jwtParts[2]!.slice(-2) === "AA" ? "BB" : "AA");
	const tamperedJwt = `${jwtParts[0]}.${jwtParts[1]}.${tamperedSig}`;
	const tamperedPresentation = `${tamperedJwt}~${parts.slice(1).join("~")}`;
	const result = await verify(tamperedPresentation);
	assert.equal(result.verified, false);
	assert.match(result.reason ?? "", /signature invalid/i);
});

test("Angle1: SD-JWT with a tampered payload (changed claim) is rejected", async () => {
	await mint();
	const credential = await issueSdJwt();
	const parts = credential.split("~");
	const issuerJwt = parts[0]!;
	const jwtParts = issuerJwt.split(".");
	// Decode the payload, change a claim, re-encode (signature won't match).
	const payload = JSON.parse(Buffer.from(jwtParts[1]!, "base64url").toString("utf8")) as Record<string, unknown>;
	payload.vct = "https://forged.example/vct";
	const tamperedPayload = Buffer.from(JSON.stringify(payload)).toString("base64url");
	const tamperedJwt = `${jwtParts[0]}.${tamperedPayload}.${jwtParts[2]}`;
	const tamperedPresentation = `${tamperedJwt}~${parts.slice(1).join("~")}`;
	const result = await verify(tamperedPresentation);
	assert.equal(result.verified, false);
	assert.match(result.reason ?? "", /signature invalid/i);
});