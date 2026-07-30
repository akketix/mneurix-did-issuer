// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

// Task 1.3b (did-issuer-wallet-expansion): the SD-JWT VC `status` claim is the
// IETF Token Status List shape (status.status_list.{uri,idx,bits}), pointing at
// the /statuslists/:purpose/:id JWT endpoint, + the bit at idx round-trips
// (0 = valid -> 1 = revoked) through the signed status-list JWT.
import { test, before } from "node:test";
import assert from "node:assert/strict";
import { app } from "../src/index";
import { _resetStatusForTests, revokeStatus } from "../src/status";
import { getBit } from "@mneurix/shared";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const ISSUER_URL = "https://did-issuer.mneurix.example";
const SUBJECT = "did:web:lattice.mneurix.example/learners/77";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
}

async function statusListPayload(path: string): Promise<{ status_list: { bits: number; vals: string } }> {
	const res = await app.request(path);
	assert.equal(res.status, 200);
	const jwt = await res.text();
	return JSON.parse(b64urlDecode(jwt.split(".")[1]!).toString("utf8"));
}

before(() => _resetStatusForTests());

test("1.3b: SD-JWT VC status claim is the IETF status_list shape; the bit at idx round-trips valid->revoked", async () => {
	_resetStatusForTests();
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST",
		headers: H,
		body: JSON.stringify({
			subjectId: SUBJECT,
			secure: "sd-jwt-vc",
			vct: `${ISSUER_URL}/vct/achievement`,
			claims: { score: 0.9 },
			selectivelyDisclosable: ["score"],
		}),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: string; statusIndex: number };

	// Decode the SD-JWT payload (the JWT part before the first "~").
	const jwtPart = ib.credential.split("~")[0]!;
	const payload = JSON.parse(b64urlDecode(jwtPart.split(".")[1]!).toString("utf8")) as {
		status?: { status_list?: { uri?: string; idx?: number; bits?: number } };
	};
	assert.ok(payload.status?.status_list, "status.status_list present in the SD-JWT VC payload");
	const sl = payload.status!.status_list!;
	assert.equal(sl.uri, `${ISSUER_URL}/statuslists/revocation/1`);
	assert.equal(sl.idx, ib.statusIndex);
	assert.equal(sl.bits, 1);

	// Fetch the status-list JWT at the uri + read the bit at idx (0 = valid).
	const uriPath = sl.uri!.slice(ISSUER_URL.length); // "/statuslists/revocation/1"
	const sl1 = await statusListPayload(uriPath);
	assert.equal(sl1.status_list.bits, 1);
	const bytes1 = new Uint8Array(Buffer.from(sl1.status_list.vals, "base64url"));
	assert.equal(getBit(bytes1, sl.idx!), 0, "bit at idx is 0 (valid) before revocation");

	// Revoke the index + re-fetch: bit should now be 1 (revoked, fail-closed).
	revokeStatus("revocation", sl.idx!);
	const sl2 = await statusListPayload(uriPath);
	const bytes2 = new Uint8Array(Buffer.from(sl2.status_list.vals, "base64url"));
	assert.equal(getBit(bytes2, sl.idx!), 1, "bit at idx is 1 (revoked) after revokeStatus");
});