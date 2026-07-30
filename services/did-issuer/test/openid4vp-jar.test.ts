// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task JAR (did-issuer-wallet-expansion): the signed Request Object (JWT-
// Secured Authorization Request) + the x509_hash client-id scheme (HAIP §5).
// POST /v1/presentations/request with signed:true returns an openid4vp:// URI
// carrying client_id=x509_hash:<cert hash> + request_uri (by reference); the
// signed request JWT (ES256+x5c) is hosted at GET /openid4vp/request/:id.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { verify, X509Certificate } from "node:crypto";
import { app } from "../src/index";
import { _resetOpenid4vpForTests } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

before(() => _resetOpenid4vpForTests());
afterEach(() => _resetOpenid4vpForTests());

test("JAR: signed request (x509_hash) — URI carries client_id + request_uri; the request object is hosted + ES256+x5c-verifiable", async () => {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct: VCT, claims: ["score"], signed: true }),
	});
	assert.equal(res.status, 201);
	const body = (await res.json()) as {
		uri: string; request_object: string; request_uri: string;
		session: { state: string };
	};
	// the URI carries client_id (x509_hash) + request_uri + request_uri_method=get; NO by-value params
	const sp = new URLSearchParams(body.uri.split("?")[1] ?? "");
	assert.match(sp.get("client_id") ?? "", /^x509_hash:/);
	assert.ok(sp.get("request_uri"));
	assert.equal(sp.get("request_uri_method"), "get");
	assert.equal(sp.get("response_type"), null, "by-value params are NOT in the URI (they are in the request object)");

	// GET the request object from request_uri
	const reqPath = body.request_uri.slice(ISSUER_URL.length);
	const r = await app.request(reqPath);
	assert.equal(r.status, 200);
	assert.match(r.headers.get("content-type") ?? "", /oauth-authz-req\+jwt/);
	const jwt = await r.text();
	assert.equal(jwt, body.request_object, "the hosted request object matches the returned request_object");

	// verify the JAR JWT: header alg=ES256 + x5c; payload has the params; sig verifies via the x5c cert
	const [h, p, sig] = jwt.split(".") as [string, string, string];
	const header = JSON.parse(b64urlDecode(h).toString("utf8")) as { alg: string; typ: string; x5c: string[] };
	assert.equal(header.alg, "ES256");
	assert.equal(header.typ, "oauth-authz-req+jwt");
	assert.ok(header.x5c.length > 0, "JAR carries x5c");
	const payload = JSON.parse(b64urlDecode(p).toString("utf8")) as {
		response_type: string; response_mode: string; client_id: string; nonce: string; state: string;
		dcql_query: { credentials: Array<{ meta: { vct_values: string[] } }> }; response_uri: string;
	};
	assert.equal(payload.response_type, "vp_token");
	assert.equal(payload.response_mode, "direct_post");
	assert.match(payload.client_id, /^x509_hash:/);
	assert.equal(payload.client_id, sp.get("client_id"), "the request object's client_id matches the URI's");
	assert.ok(payload.nonce && payload.state);
	assert.deepEqual(payload.dcql_query.credentials[0]!.meta.vct_values, [VCT]);
	assert.equal(payload.response_uri, `${ISSUER_URL}/openid4vp/response`);
	// the signature verifies against the x5c cert's public key
	const cert = new X509Certificate(Buffer.from(header.x5c[0]!, "base64"));
	const valid = verify("SHA256", Buffer.from(h + "." + p, "ascii"), { key: cert.publicKey, dsaEncoding: "ieee-p1363" }, b64urlDecode(sig));
	assert.equal(valid, true, "JAR signature verifies against the x5c cert's key");
});

test("JAR: the request object id is the session state (the request_uri path)", async () => {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT, signed: true }) });
	const body = (await res.json()) as { request_uri: string; session: { state: string } };
	assert.equal(body.request_uri, `${ISSUER_URL}/openid4vp/request/${body.session.state}`);
});

test("JAR: GET /openid4vp/request/:id for an unknown id -> 404", async () => {
	const r = await app.request("/openid4vp/request/no-such-id");
	assert.equal(r.status, 404);
});