// T10.1: FileDidStore persistence test.
// Run: npx tsx services/did-issuer/test/store-persistence.test.ts
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FileDidStore, InMemoryDidStore } from "../src/store";

const dir = mkdtempSync(join(tmpdir(), "did-store-"));
after(() => rmSync(dir, { recursive: true, force: true }));

const SAMPLE_DOC = {
	id: "did:web:example.com:learner:alice",
	"@context": ["https://www.w3.org/ns/did/v1"],
	verificationMethod: [],
	authentication: [],
} as never;

test("T10.1: FileDidStore persists a DID to disk + reads it back", () => {
	const store = new FileDidStore(dir);
	store.putDid("did:web:example.com:learner:alice", SAMPLE_DOC, "kid-1");
	const got = store.getDid("did:web:example.com:learner:alice");
	assert.ok(got, "DID must be retrievable");
	assert.equal(got!.kid, "kid-1");
	assert.equal(got!.document.id, "did:web:example.com:learner:alice");
	// The file exists on disk.
	assert.equal(existsSync(join(dir, "abc")) || readdirMatches(dir), true);
});

test("T10.1: FileDidStore setPublished updates the origins + docHash", () => {
	const store = new FileDidStore(dir);
	store.putDid("did:web:example.com:learner:bob", SAMPLE_DOC, "kid-2");
	store.setPublished("did:web:example.com:learner:bob", ["https://origin-1", "https://origin-2"], "hash-abc");
	const got = store.getDid("did:web:example.com:learner:bob");
	assert.ok(got);
	assert.deepEqual(got!.origins, ["https://origin-1", "https://origin-2"]);
	assert.equal(got!.docHash, "hash-abc");
});

test("T10.1: FileDidStore getDid returns undefined for an unknown DID", () => {
	const store = new FileDidStore(dir);
	assert.equal(store.getDid("did:web:example.com:unknown"), undefined);
});

test("T10.1: FileDidStore survives a new instance (durable on disk)", () => {
	const store1 = new FileDidStore(dir);
	store1.putDid("did:web:example.com:learner:carol", SAMPLE_DOC, "kid-3");
	// A new instance pointing at the same dir reads the persisted DID.
	const store2 = new FileDidStore(dir);
	const got = store2.getDid("did:web:example.com:learner:carol");
	assert.ok(got, "DID must survive across instances (durable on disk)");
	assert.equal(got!.kid, "kid-3");
});

test("T10.1: InMemoryDidStore is not durable (clears on new instance)", () => {
	const store1 = new InMemoryDidStore();
	store1.putDid("did:web:example.com:learner:dave", SAMPLE_DOC, "kid-4");
	const store2 = new InMemoryDidStore();
	assert.equal(store2.getDid("did:web:example.com:learner:dave"), undefined, "in-memory is not durable");
});

// Helper: check that at least one .json file exists in the dir.
import { readdirSync } from "node:fs";
function readdirMatches(d: string): boolean {
	return readdirSync(d).some((f) => f.endsWith(".json"));
}