// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

import { test } from "node:test";
import assert from "node:assert/strict";

test("smoke: did-issuer boots + /health responds 200", async () => {
	const url = new URL("../services/did-issuer/src/index.ts", import.meta.url);
	const mod = await import(url.href);
	const res = await mod.app.request("/health");
	assert.equal(res.status, 200);
	const body = (await res.json()) as { status: string; service: string };
	assert.equal(body.status, "ok");
	assert.equal(body.service, "did-issuer");
});
