// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.6 (did-issuer-wallet-expansion): the W3C Digital Credentials API
// transport — POST /v1/presentations/request with transport "dc_api" returns a
// dc_api_request JSON object (for navigator.credentials.get), the modern
// web-based wallet invocation, alongside the openid4vp:// URI.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/index";
import { _resetOpenid4vpForTests } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;

before(() => _resetOpenid4vpForTests());
afterEach(() => _resetOpenid4vpForTests());

test("1.6: transport dc_api returns a dc_api_request object for navigator.credentials.get", async () => {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct: VCT, claims: ["score"], transport: "dc_api" }),
	});
	assert.equal(res.status, 201);
	const body = (await res.json()) as {
		uri: string;
		dc_api_request?: { response_type: string; response_mode: string; client_id: string; nonce: string; state: string; dcql_query: { credentials: Array<{ meta: { vct_values: string[] } }> }; response_uri: string };
	};
	assert.ok(body.dc_api_request, "dc_api_request present");
	const r = body.dc_api_request!;
	assert.equal(r.response_type, "vp_token");
	assert.equal(r.response_mode, "dc_api");
	assert.equal(r.client_id, ISSUER_URL);
	assert.ok(r.nonce && r.state);
	assert.deepEqual(r.dcql_query.credentials[0]!.meta.vct_values, [VCT]);
	assert.equal(r.response_uri, `${ISSUER_URL}/openid4vp/response`);
	// the openid4vp:// URI is also present (with response_mode=dc_api) for reference
	assert.match(body.uri, /openid4vp:\/\/\?/);
	assert.match(body.uri, /response_mode=dc_api/);
});

test("1.6: transport dc_api + encrypted -> response_mode dc_api.jwt + client_metadata (per-state response_uri)", async () => {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct: VCT, transport: "dc_api", encrypted: true }),
	});
	assert.equal(res.status, 201);
	const body = (await res.json()) as {
		dc_api_request?: { response_mode: string; response_uri: string; state: string; client_metadata: { encrypted_response_alg: string; jwks: { keys: unknown[] } } };
	};
	const r = body.dc_api_request!;
	assert.equal(r.response_mode, "dc_api.jwt");
	assert.equal(r.client_metadata.encrypted_response_alg, "ECDH-ES");
	assert.ok(r.client_metadata.jwks.keys.length > 0);
	assert.equal(r.response_uri, `${ISSUER_URL}/openid4vp/response/${r.state}`, "per-state response_uri for encrypted dc_api.jwt");
});

test("1.6: default transport (openid4vp) -> no dc_api_request; URI uses direct_post", async () => {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT }) });
	assert.equal(res.status, 201);
	const body = (await res.json()) as { uri: string; dc_api_request?: unknown };
	assert.equal(body.dc_api_request, undefined, "no dc_api_request for the default transport");
	assert.match(body.uri, /response_mode=direct_post/);
});