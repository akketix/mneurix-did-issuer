import { test, before, afterEach } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { app } from "../src/index";
import { _resetStatusForTests } from "../src/status";
import { _resetRevokedKidsForTests } from "../src/revoked-kids";
import { _resetForTests as resetDidStore } from "../src/store";
import type { OpenBadgeCredential } from "@mneurix/shared";

const H = { "x-mneurix-service-token": "dev-did-issuer-token", "content-type": "application/json" };
const enc = encodeURIComponent;

const achievement = {
	id: "https://lattice.mneurix.example/achievements/comp-1",
	type: ["Achievement"],
	name: "Mneurix Competency X",
	description: "A council-verified competency.",
	criteria: { narrative: "Pass the proctored summative assessment." },
	alignment: [],
};
const evidence = {
	kind: "council-formative" as const,
	id: "https://did-issuer.mneurix.example/evidence/sub-1",
	type: ["Evidence"],
	narrative: "Competence verified by a 3-model Mneurix council.",
	score: 0.85, agreement: 0.9, councilSize: 3,
	criterionScores: [{ criterionId: "c1", score: 0.9, reasoning: "strong" }],
	requiresHumanReview: false, isOfficialCertification: false, alignment: [],
};
const subjectId = "did:web:lattice.mneurix.example/learners/42";
const ISSUER_ORIGIN = "did-issuer.mneurix.example";
const issuerDid = "did:web:" + ISSUER_ORIGIN;

before(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });
afterEach(() => { resetDidStore(); _resetStatusForTests(); _resetRevokedKidsForTests(); });

async function mintAndIssue(): Promise<{ credential: OpenBadgeCredential; oldKid: string }> {
	await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: ISSUER_ORIGIN }) });
	const wellKnown = await app.request("/.well-known/did.json");
	const doc = (await wellKnown.json()) as { verificationMethod: { id: string }[] };
	const oldKid = doc.verificationMethod[0]!.id.split("#")[1]!;
	const issue = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId, secure: "data-integrity", achievement, evidence }),
	});
	assert.equal(issue.status, 201);
	const ib = (await issue.json()) as { credential: OpenBadgeCredential };
	return { credential: ib.credential, oldKid };
}

function kidOf(vm: string): string {
	return vm.slice(vm.lastIndexOf("#") + 1);
}

test("M6: rotate keeps the DID stable, tombstones the old kid, new key signs", async () => {
	const { credential: oldVc, oldKid } = await mintAndIssue();
	assert.equal(kidOf(oldVc.proof.verificationMethod), oldKid);

	const rotate = await app.request(`/v1/dids/${enc(issuerDid)}/keys:rotate`, { method: "POST", headers: H });
	assert.equal(rotate.status, 200);
	const rb = (await rotate.json()) as { did: string; newKid: string; tombstonedKid: string; publishedTo: string[] };
	assert.equal(rb.did, issuerDid); // DID stable
	assert.notEqual(rb.newKid, oldKid);
	assert.equal(rb.tombstonedKid, oldKid);
	assert.deepEqual(rb.publishedTo, []); // no origins configured → no publish

	// The DID doc now carries BOTH verification methods; assertionMethod = new only.
	const res = await app.request(`/v1/dids/${enc(issuerDid)}`, { headers: H });
	const db = (await res.json()) as { document: { verificationMethod: { id: string }[]; assertionMethod: string[] } };
	assert.equal(db.document.verificationMethod.length, 2);
	assert.deepEqual(db.document.assertionMethod, [`${issuerDid}#${rb.newKid}`]);
	const vmKids = db.document.verificationMethod.map((m) => kidOf(m.id)).sort();
	assert.deepEqual(vmKids, [oldKid, rb.newKid].sort());

	// A freshly-issued VC is now signed by the NEW kid.
	const issue2 = await app.request("/v1/vcs:issue", {
		method: "POST", headers: H,
		body: JSON.stringify({ subjectId, secure: "data-integrity", achievement, evidence }),
	});
	const ib2 = (await issue2.json()) as { credential: OpenBadgeCredential };
	assert.equal(kidOf(ib2.credential.proof.verificationMethod), rb.newKid);
});

test("M6: revoke tombstones a kid + removes it from the DID doc", async () => {
	const { oldKid } = await mintAndIssue();
	const revoke = await app.request(`/v1/dids/${enc(issuerDid)}/keys:revoke`, {
		method: "POST", headers: H, body: JSON.stringify({ kid: oldKid }),
	});
	assert.equal(revoke.status, 200);
	const rb = (await revoke.json()) as { revokedKid: string };
	assert.equal(rb.revokedKid, oldKid);

	// The doc no longer carries the revoked verificationMethod.
	const res = await app.request(`/v1/dids/${enc(issuerDid)}`, { headers: H });
	const db = (await res.json()) as { document: { verificationMethod: { id: string }[] } };
	assert.equal(db.document.verificationMethod.find((m) => kidOf(m.id) === oldKid), undefined);
});

// --- mock HTTP origin (for the atomic multi-origin republish test) ---
interface MockOrigin { url: string; doc: () => unknown; stop: () => Promise<void>; }
function mockOrigin(): Promise<MockOrigin> {
	let served: unknown = null;
	return new Promise((resolve) => {
		const server: Server = createServer((req, res) => {
			if (req.url !== "/.well-known/did.json") { res.writeHead(404); res.end(); return; }
			if (req.method === "GET") {
				if (!served) { res.writeHead(404); res.end(); return; }
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify(served));
				return;
			}
			if (req.method === "PUT") {
				let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => { served = JSON.parse(body); res.writeHead(204); res.end(); });
				return;
			}
			res.writeHead(405); res.end();
		});
		server.listen(0, "127.0.0.1", () => {
			const addr = server.address() as { port: number };
			resolve({ url: `http://127.0.0.1:${addr.port}`, doc: () => served, stop: () => new Promise<void>((r) => server.close(() => r())) });
		});
	});
}

test("M6: rotate republishes the rotated doc atomically to all origins", async () => {
	const o = await mockOrigin();
	process.env.MNEURIX_DID_ORIGINS = o.url;
	try {
		await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: ISSUER_ORIGIN }) });
		// publish the initial doc so the store records the origin list
		await app.request(`/v1/dids/${enc(issuerDid)}/publish`, { method: "POST", headers: H, body: JSON.stringify({ origins: [o.url] }) });

		const rotate = await app.request(`/v1/dids/${enc(issuerDid)}/keys:rotate`, { method: "POST", headers: H });
		assert.equal(rotate.status, 200);
		const rb = (await rotate.json()) as { publishedTo: string[]; newKid: string };
		assert.equal(rb.publishedTo.length, 1);

		// The origin now serves the rotated doc: two verificationMethods.
		const served = o.doc() as { verificationMethod: { id: string }[]; assertionMethod: string[] };
		assert.equal(served.verificationMethod.length, 2);
		assert.deepEqual(served.assertionMethod, [`${issuerDid}#${rb.newKid}`]);
	} finally {
		delete process.env.MNEURIX_DID_ORIGINS;
		await o.stop();
	}
});

test("M6: rotate/revoke enforce operator roles when MNEURIX_OPERATORS is set", async () => {
	await app.request("/v1/dids", { method: "POST", headers: H, body: JSON.stringify({ origin: ISSUER_ORIGIN }) });
	const prev = process.env.MNEURIX_OPERATORS;
	process.env.MNEURIX_OPERATORS = "alice:revoker+issuer:tok-alice,bob:publisher:tok-bob";
	try {
		// bob (role publisher) is NOT allowed to rotate → 403.
		const forbidden = await app.request(`/v1/dids/${enc(issuerDid)}/keys:rotate`, {
			method: "POST", headers: { ...H, authorization: "Bearer tok-bob" },
		});
		assert.equal(forbidden.status, 403);

		// alice (role issuer) may rotate → 200.
		const allowed = await app.request(`/v1/dids/${enc(issuerDid)}/keys:rotate`, {
			method: "POST", headers: { ...H, authorization: "Bearer tok-alice" },
		});
		assert.equal(allowed.status, 200);

		// no bearer at all → 401.
		const noBearer = await app.request(`/v1/dids/${enc(issuerDid)}/keys:rotate`, { method: "POST", headers: H });
		assert.equal(noBearer.status, 401);
	} finally {
		if (prev === undefined) delete process.env.MNEURIX_OPERATORS; else process.env.MNEURIX_OPERATORS = prev;
	}
});