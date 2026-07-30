// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task (did-issuer-wallet-expansion): the status-list token for the ES256/HAIP
// path is ES256-signed + carries x5c (HAIP §6.1). GET /statuslists/:purpose/:id?alg=ES256
// returns an ES256 statuslist+jwt (x5c header, verifiable against the P-256 JWK);
// the default serves the Ed25519 token; an ES256 SD-JWT VC's status uri carries
// ?alg=ES256.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, verify, X509Certificate } from "node:crypto";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

before(() => _resetStatusForTests());
afterEach(() => _resetStatusForTests());

test("status-list ES256: ?alg=ES256 returns an ES256 statuslist+jwt with x5c, verifiable against the P-256 JWK", async () => {
	const res = await app.request("/statuslists/revocation/1?alg=ES256");
	assert.equal(res.status, 200);
	assert.match(res.headers.get("content-type") ?? "", /statuslist\+jwt/);
	const jwt = await res.text();
	const [h, p, sig] = jwt.split(".") as [string, string, string];
	const header = JSON.parse(b64urlDecode(h).toString("utf8")) as { alg: string; typ: string; x5c?: string[] };
	assert.equal(header.alg, "ES256");
	assert.equal(header.typ, "statuslist+jwt");
	assert.ok(Array.isArray(header.x5c) && header.x5c.length > 0, "x5c in the ES256 status-list token header");
	// the x5c cert parses + matches the advertised ES256 JWK
	const cert = new X509Certificate(Buffer.from(header.x5c![0]!, "base64"));
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as { jwks: { keys: Array<Record<string, unknown>> } };
	const es = meta.jwks.keys.find((k) => k.alg === "ES256")!;
	const cpk = cert.publicKey.export({ format: "jwk" }) as { x: string; y: string };
	assert.equal(cpk.x, es.x);
	assert.equal(cpk.y, es.y);
	// verify the ES256 signature against the P-256 JWK
	const pub = createPublicKey({ key: es, format: "jwk" });
	const valid = verify("SHA256", Buffer.from(h + "." + p, "ascii"), { key: pub, dsaEncoding: "ieee-p1363" }, b64urlDecode(sig));
	assert.equal(valid, true, "ES256 status-list JWT verifies against the P-256 JWK");
	// payload.sub carries ?alg=ES256 + the status_list
	const payload = JSON.parse(b64urlDecode(p).toString("utf8")) as { sub: string; status_list: { bits: number; vals: string } };
	assert.equal(payload.sub, `${ISSUER_URL}/statuslists/revocation/1?alg=ES256`);
	assert.equal(payload.status_list.bits, 1);
	assert.ok(typeof payload.status_list.vals === "string");
});

test("status-list ES256: default (no alg) still returns the Ed25519 token (no x5c)", async () => {
	const res = await app.request("/statuslists/revocation/1");
	const jwt = await res.text();
	const header = JSON.parse(b64urlDecode(jwt.split(".")[0]!).toString("utf8")) as { alg: string; x5c?: unknown };
	assert.equal(header.alg, "EdDSA");
	assert.equal(header.x5c, undefined, "Ed25519 status-list token has no x5c");
});

test("status-list ES256: an ES256 SD-JWT VC's status uri carries ?alg=ES256", async () => {
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId: "did:web:lattice.mneurix.example/learners/9", secure: "sd-jwt-vc", vct: `${ISSUER_URL}/vct/achievement`, claims: { score: 0.9 }, selectivelyDisclosable: ["score"], alg: "ES256" }),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: string };
	const payload = JSON.parse(b64urlDecode(ib.credential.split("~")[0]!.split(".")[1]!).toString("utf8")) as { status: { status_list: { uri: string; idx: number; bits: number } } };
	assert.equal(payload.status.status_list.uri, `${ISSUER_URL}/statuslists/revocation/1?alg=ES256`, "ES256 VC points at the ES256 status-list token");
	assert.equal(payload.status.status_list.bits, 1);
});