// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.1 (did-issuer-wallet-expansion): OID4VCI pre-authorized-code flow —
// mint offer -> redeem token -> fetch the SD-JWT VC (both EdDSA + ES256);
// single-use replay protection; + the metadata endpoints.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify, generateKeyPairSync, createSign } from "node:crypto";
import { signAsync } from "@noble/ed25519";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetOid4vciForTests } from "../src/oid4vci";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const SUBJECT = "did:web:lattice.mneurix.example/learners/99";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

function holderKeypairES256() {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	return {
		jwk: publicKey.export({ format: "jwk" }) as Record<string, string>,
		signProof: (nonce: string) => {
			const header = b64url(JSON.stringify({ alg: "ES256", typ: "openid4vci-proof+jwt", jwk: publicKey.export({ format: "jwk" }) }));
			const payload = b64url(JSON.stringify({ nonce, iss: "did:web:wallet.example", aud: ISSUER_URL }));
			const signingInput = Buffer.from(header + "." + payload, "ascii");
			const sig = createSign("SHA256").update(signingInput).sign({ key: privateKey.export({ format: "pem", type: "pkcs8" }), dsaEncoding: "ieee-p1363" });
			return header + "." + payload + "." + b64url(sig);
		},
	};
}

function b64url(b: Buffer | string) { return (typeof b === "string" ? Buffer.from(b, "utf8") : Buffer.from(b)).toString("base64url"); }


async function mintOffer(alg?: "EdDSA" | "ES256") {
	const res = await app.request("/v1/credential-offers", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: SUBJECT, vct: `${ISSUER_URL}/vct/achievement`, claims: { score: 0.9 }, selectivelyDisclosable: ["score"], ...(alg ? { alg } : {}) }),
	});
	assert.equal(res.status, 201);
	return (await res.json()) as {
		credential_issuer: string; credential_configuration_ids: string[];
		grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { pre_authorized_code: string; user_pin_required: boolean } };
	};
}
async function redeemToken(code: string) {
	const res = await app.request("/oauth/token", {
		method: "POST", headers: { "content-type": "application/json" },
		body: JSON.stringify({ grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code", pre_authorized_code: code }),
	});
	return { status: res.status, body: (await res.json()) as { access_token?: string; c_nonce?: string; error?: string } };
}
async function fetchCredential(accessToken: string, proofJwt?: string) {
	const body = proofJwt ? { proof: { jwt: proofJwt, proof_type: "jwt" } } : {};
	const res = await app.request("/credentials", { method: "POST", headers: { authorization: `Bearer ${accessToken}`, "content-type": "application/json" }, body: JSON.stringify(body) });
	return { status: res.status, body: (await res.json()) as { format?: string; credential?: string; error?: string } };
}

beforeEach(() => { _resetStatusForTests(); _resetOid4vciForTests(); });

test("1.1 OID4VCI: mint offer -> redeem token -> fetch credential (EdDSA, default)", async () => {
	const offer = await mintOffer();
	assert.equal(offer.credential_issuer, ISSUER_URL);
	assert.deepEqual(offer.credential_configuration_ids, [`${ISSUER_URL}/vct/achievement`]);
	const code = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].pre_authorized_code;
	assert.ok(code);
	assert.equal(offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].user_pin_required, false);

	const tok = await redeemToken(code);
	assert.equal(tok.status, 200);
	assert.equal(tok.body.access_token ? "bearer" : null, "bearer");
	assert.ok(tok.body.c_nonce, "c_nonce issued at the token endpoint");

	// M-2: wallet proves possession of its holder key via a proof JWT.
	const holder = holderKeypairES256();
	const proof = holder.signProof(tok.body.c_nonce!);
	const cred = await fetchCredential(tok.body.access_token!, proof);
	assert.equal(cred.status, 200);
	assert.equal(cred.body.format, "vc+sd-jwt");
	const header = JSON.parse(b64urlDecode(cred.body.credential!.split("~")[0]!.split(".")[0]!).toString("utf8")) as Record<string, unknown>;
	assert.equal(header.alg, "EdDSA");
});

test("1.1 OID4VCI: ES256 flow — header alg=ES256, iss=HTTPS issuer, signature verifies against the P-256 JWK", async () => {
	const offer = await mintOffer("ES256");
	const code = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].pre_authorized_code;
	const tok = await redeemToken(code);
	assert.equal(tok.status, 200);
	assert.ok(tok.body.c_nonce, "c_nonce issued");
	const holder = holderKeypairES256();
	const proof = holder.signProof(tok.body.c_nonce!);
	const cred = await fetchCredential(tok.body.access_token!, proof);
	assert.equal(cred.status, 200);
	const [h, p, sig] = cred.body.credential!.split("~")[0]!.split(".") as [string, string, string];
	const header = JSON.parse(b64urlDecode(h).toString("utf8")) as Record<string, unknown>;
	assert.equal(header.alg, "ES256");
	const payload = JSON.parse(b64urlDecode(p).toString("utf8")) as { iss: string; vct: string };
	assert.equal(payload.iss, ISSUER_URL, "ES256 path uses the HTTPS issuer (HAIP-style), not did:web");
	assert.equal(payload.vct, `${ISSUER_URL}/vct/achievement`);
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as { jwks: { keys: Array<Record<string, unknown>> } };
	const es = meta.jwks.keys.find((k) => k.alg === "ES256")!;
	const pub = createPublicKey({ key: es, format: "jwk" });
	const valid = verify("SHA256", Buffer.from(h + "." + p, "ascii"), { key: pub, dsaEncoding: "ieee-p1363" }, b64urlDecode(sig));
	assert.equal(valid, true, "ES256 SD-JWT VC from the credential endpoint verifies against the P-256 JWK");
});

test("1.1 OID4VCI: single-use replay protection (access token + code + c_nonce)", async () => {
	const offer = await mintOffer();
	const code = offer.grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].pre_authorized_code;
	const tok = await redeemToken(code);
	assert.equal(tok.status, 200);
	assert.ok(tok.body.c_nonce, "c_nonce issued");
	const holder = holderKeypairES256();
	const proof = holder.signProof(tok.body.c_nonce!);
	const cred = await fetchCredential(tok.body.access_token!, proof);
	assert.equal(cred.status, 200);
	// Replay the access token + same proof — the access token is consumed (single-use).
	const replayCred = await fetchCredential(tok.body.access_token!, proof);
	assert.equal(replayCred.status, 401, "access token is single-use (replay -> 401)");
	const replayTok = await redeemToken(code);
	assert.equal(replayTok.status, 400, "pre-authorized code is single-use (replay -> 400)");
});

test("1.1 OID4VCI: missing/invalid access token -> 401", async () => {
	const noTok = await app.request("/credentials", { method: "POST", headers: {}, body: JSON.stringify({}) });
	assert.equal(noTok.status, 401);
	const badTok = await fetchCredential("not-a-real-token");
	assert.equal(badTok.status, 401);
});

test("1.1 OID4VCI: metadata endpoints advertise the flow", async () => {
	const as = (await (await app.request("/.well-known/oauth-authorization-server")).json()) as Record<string, unknown>;
	assert.equal(as.issuer, ISSUER_URL);
	assert.equal(as.token_endpoint, `${ISSUER_URL}/oauth/token`);
	assert.ok((as.grant_types_supported as string[]).includes("urn:ietf:params:oauth:grant-type:pre-authorized_code"));
	const ci = (await (await app.request("/.well-known/oauth-credential-issuer")).json()) as Record<string, unknown>;
	assert.equal(ci.credential_issuer, ISSUER_URL);
	assert.equal(ci.credential_endpoint, `${ISSUER_URL}/credentials`);
	const cfg = (ci.credential_configurations_supported as Record<string, Record<string, unknown>>)[`${ISSUER_URL}/vct/achievement`]!;
	assert.equal(cfg.format, "vc+sd-jwt");
	assert.ok((cfg.credential_signing_alg_values_supported as string[]).includes("ES256"));
});