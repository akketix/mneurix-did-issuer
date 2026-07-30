// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.2 (did-issuer-wallet-expansion): the OpenID4VP verifier request
// generator — POST /v1/presentations/request produces an openid4vp://
// authorization request (a DCQL query for an SD-JWT VC by vct) + a verifier
// session (nonce/state), defaulting response_mode=direct_post.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/index";
import { _resetOpenid4vpForTests, resolveSession } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;

beforeEach(() => _resetOpenid4vpForTests());

test("1.2: POST /v1/presentations/request generates an openid4vp:// request with a DCQL query for the vct", async () => {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct: VCT, claims: ["score", "given_name"] }),
	});
	assert.equal(res.status, 201);
	const body = (await res.json()) as {
		uri: string;
		dcql_query: { credentials: Array<{ id: string; format: string; meta: { vct_values: string[] }; claims: Array<{ path: string[] }> }> };
		session: { nonce: string; state: string; responseUri: string; vct: string; claims: string[] };
	};
	// uri is openid4vp:// with the required params
	assert.ok(body.uri.startsWith("openid4vp://?"));
	const sp = new URLSearchParams(body.uri.split("?")[1] ?? "");
	assert.equal(sp.get("response_type"), "vp_token");
	assert.equal(sp.get("response_mode"), "direct_post");
	assert.equal(sp.get("client_id"), ISSUER_URL);
	assert.equal(sp.get("response_uri"), `${ISSUER_URL}/openid4vp/response`);
	assert.ok(sp.get("nonce"), "nonce present");
	assert.ok(sp.get("state"), "state present");
	// the dcql_query in the uri matches the returned dcql_query
	assert.deepEqual(JSON.parse(sp.get("dcql_query")!), body.dcql_query);
	// the DCQL query targets the SD-JWT VC vct + the requested claims
	const q = body.dcql_query.credentials[0]!;
	assert.equal(q.id, "sd_jwt_vc");
	assert.equal(q.format, "dc+sd-jwt");
	assert.deepEqual(q.meta.vct_values, [VCT]);
	assert.deepEqual(q.claims, [{ path: ["score"] }, { path: ["given_name"] }]);
	// session reflects the request
	assert.equal(body.session.vct, VCT);
	assert.equal(body.session.responseUri, `${ISSUER_URL}/openid4vp/response`);
	assert.equal(body.session.nonce, sp.get("nonce"));
	assert.equal(body.session.state, sp.get("state"));
});

test("1.2: each request mints a fresh nonce/state (no reuse)", async () => {
	const a = await (await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT }) })).json() as { session: { nonce: string; state: string } };
	const b = await (await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT }) })).json() as { session: { nonce: string; state: string } };
	assert.notEqual(a.session.nonce, b.session.nonce, "nonce is fresh per request");
	assert.notEqual(a.session.state, b.session.state, "state is fresh per request");
});

test("1.2: custom clientId + responseUri override the defaults", async () => {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct: VCT, clientId: "https://verifier.example.com", responseUri: "https://verifier.example.com/cb" }),
	});
	assert.equal(res.status, 201);
	const sp = new URLSearchParams((((await res.json()) as { uri: string }).uri).split("?")[1] ?? "");
	assert.equal(sp.get("client_id"), "https://verifier.example.com");
	assert.equal(sp.get("response_uri"), "https://verifier.example.com/cb");
});

test("1.2: missing vct -> 400", async () => {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ claims: ["score"] }) });
	assert.equal(res.status, 400);
});

test("1.2: resolveSession matches nonce/state + rejects mismatch (fail-closed)", async () => {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT }) });
	const s = (await res.json()) as { session: { nonce: string; state: string } };
	assert.ok(resolveSession(s.session.state, s.session.nonce), "matching state+nonce resolves the session");
	assert.equal(resolveSession(s.session.state, "wrong-nonce"), null, "wrong nonce -> fail-closed");
	assert.equal(resolveSession("wrong-state", s.session.nonce), null, "wrong state -> fail-closed");
});