// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task (did-issuer-wallet-expansion): the vct taxonomy — the issuer advertises
// its supported credential types (vct_values) + serves each type's definition
// (claim schema) at GET /vct/:name, for wallet/verifier credential-type discovery.
import { test } from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/index";

const ISSUER_URL = "https://did-issuer.mneurix.example";

test("vct taxonomy: /.well-known/jwt-vc-issuer advertises all registered vct_values", async () => {
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as { vct_values: string[] };
	assert.ok(meta.vct_values.length >= 3, "multiple vct_values advertised");
	for (const name of ["achievement", "competency", "mastery"]) {
		assert.ok(meta.vct_values.includes(`${ISSUER_URL}/vct/${name}`), `${name} vct advertised`);
	}
});

test("vct taxonomy: GET /vct/:name serves each registered vct definition (vct + name + description + claims)", async () => {
	for (const name of ["achievement", "competency", "mastery"]) {
		const res = await app.request(`/vct/${name}`);
		assert.equal(res.status, 200, `${name} -> 200`);
		const def = (await res.json()) as { vct: string; name: string; description: string; claims: Record<string, string> };
		assert.equal(def.vct, `${ISSUER_URL}/vct/${name}`);
		assert.ok(def.name);
		assert.ok(def.description);
		assert.ok(Object.keys(def.claims).length > 0, `${name} has a claim schema`);
	}
});

test("vct taxonomy: GET /vct/unknown -> 404", async () => {
	const res = await app.request("/vct/unknown");
	assert.equal(res.status, 404);
});

test("vct taxonomy: the default achievement vct is the first advertised (no regression)", async () => {
	const meta = (await (await app.request("/.well-known/jwt-vc-issuer")).json()) as { vct_values: string[] };
	assert.match(meta.vct_values[0]!, /\/vct\/achievement$/);
});