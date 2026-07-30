// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task (did-issuer-wallet-expansion): the openid4vp-redirect (claimed https)
// transport — the third delivery variant. POST /v1/presentations/request with
// transport "openid4vp-redirect" returns a claimed-https redirect URL (the
// request params in an https URL for universal-links/app-links wallet
// invocation), alongside the openid4vp:// URI.
import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/index";
import { _resetOpenid4vpForTests } from "../src/openid4vp";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const VCT = `${ISSUER_URL}/vct/achievement`;

before(() => _resetOpenid4vpForTests());
afterEach(() => _resetOpenid4vpForTests());

test("openid4vp-redirect: returns a claimed-https redirect URL with the request params", async () => {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct: VCT, claims: ["score"], transport: "openid4vp-redirect" }),
	});
	assert.equal(res.status, 201);
	const body = (await res.json()) as { uri: string; redirect_url?: string };
	assert.ok(body.redirect_url, "redirect_url present");
	const u = new URL(body.redirect_url!);
	assert.equal(u.origin + u.pathname, `${ISSUER_URL}/openid4vp`, "claimed-https base at <issuer>/openid4vp");
	assert.equal(u.searchParams.get("response_type"), "vp_token");
	assert.equal(u.searchParams.get("response_mode"), "direct_post");
	assert.equal(u.searchParams.get("client_id"), ISSUER_URL, "client_id is the claimed-https origin");
	assert.ok(u.searchParams.get("nonce"));
	assert.ok(u.searchParams.get("state"));
	assert.deepEqual(JSON.parse(u.searchParams.get("dcql_query")!).credentials[0].meta.vct_values, [VCT]);
	// the openid4vp:// URI is also present (for fallback)
	assert.match(body.uri, /openid4vp:\/\/\?/);
});

test("openid4vp-redirect + encrypted -> redirect_url uses direct_post.jwt + carries client_metadata", async () => {
	const res = await app.request("/v1/presentations/request", {
		method: "POST", headers: H,
		body: JSON.stringify({ vct: VCT, transport: "openid4vp-redirect", encrypted: true }),
	});
	assert.equal(res.status, 201);
	const body = (await res.json()) as { redirect_url?: string };
	const u = new URL(body.redirect_url!);
	assert.equal(u.searchParams.get("response_mode"), "direct_post.jwt");
	assert.ok(u.searchParams.get("client_metadata"), "encrypted client_metadata carried in the redirect URL");
	const cm = JSON.parse(u.searchParams.get("client_metadata")!);
	assert.equal(cm.encrypted_response_alg, "ECDH-ES");
	// per-state response_uri for encrypted
	assert.equal(u.searchParams.get("response_uri"), `${ISSUER_URL}/openid4vp/response/${u.searchParams.get("state")}`);
});

test("openid4vp-redirect: default transport -> no redirect_url", async () => {
	const res = await app.request("/v1/presentations/request", { method: "POST", headers: H, body: JSON.stringify({ vct: VCT }) });
	assert.equal(res.status, 201);
	const body = (await res.json()) as { redirect_url?: unknown };
	assert.equal(body.redirect_url, undefined, "no redirect_url for the default transport");
});