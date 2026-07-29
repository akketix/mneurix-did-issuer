// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/**
 * DID-document store — env-driven persistence swap (M10 / T10.1).
 *
 * Mirrors the lattice's `createLrs()` env-swap pattern:
 *   - MNEURIX_DB_BACKEND=postgres → Postgres (requires `pg`; stubbed until added)
 *   - otherwise                    → FileDidStore (one JSON file per DID, no native dep)
 *
 * The hot read path stays the same module-level API (putDid/getDid/setPublished)
 * so callers don't change. The backend is selected at module load.
 *
 * Purity: none (fs). */
import type { DidDocument } from "./did";
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, rmSync } from "node:fs";
import { join, resolve } from "node:path";
import { createHash } from "node:crypto";
import { loadDataEncryptionKey, encryptAtRest, decryptAtRest } from "@mneurix/shared";

export interface Stored {
	document: DidDocument;
	kid: string;
	createdAt: string;
	/** Origin base URLs the doc was published to (empty/absent = minted, not published). */
	origins?: string[];
	/** Pinned hash of the *published* (origin-embedded) document, set at publish time. */
	docHash?: string;
}

/** The DID store interface (swappable backend). */
export interface DidStore {
	putDid(did: string, document: DidDocument, kid: string): void;
	getDid(did: string): Stored | undefined;
	setPublished(did: string, origins: string[], docHash: string): void;
}

/** In-memory store (tests / dev). */
export class InMemoryDidStore implements DidStore {
	private docs = new Map<string, Stored>();
	putDid(did: string, document: DidDocument, kid: string): void {
		this.docs.set(did, { document, kid, createdAt: new Date().toISOString() });
	}
	getDid(did: string): Stored | undefined {
		return this.docs.get(did);
	}
	setPublished(did: string, origins: string[], docHash: string): void {
		const s = this.docs.get(did);
		if (!s) return;
		this.docs.set(did, { ...s, origins, docHash });
	}
	clear(): void {
		this.docs.clear();
	}
}

/** File-backed store — one JSON file per DID (local default, no native dep). */
export class FileDidStore implements DidStore {
	private readonly dir: string;
	constructor(dir?: string) {
		this.dir = resolve(dir ?? process.env.MNEURIX_DID_DATA_DIR ?? join(process.cwd(), "data", "dids"));
		mkdirSync(this.dir, { recursive: true });
	}
	/** Sanitize the DID into a safe filename (DIDs have colons). */
	private pathFor(did: string): string {
		const safe = createHash("sha256").update(did).digest("hex").slice(0, 32);
		return join(this.dir, `${safe}.json`);
	}
	putDid(did: string, document: DidDocument, kid: string): void {
		const stored: Stored = { document, kid, createdAt: new Date().toISOString() };
		this.write(did, JSON.stringify(stored));
	}
	getDid(did: string): Stored | undefined {
		const raw = this.read(did);
		if (raw === undefined) return undefined;
		try {
			return JSON.parse(raw) as Stored;
		} catch {
			return undefined;
		}
	}
	setPublished(did: string, origins: string[], docHash: string): void {
		const s = this.getDid(did);
		if (!s) return;
		this.write(did, JSON.stringify({ ...s, origins, docHash }));
	}
	/** Write with app-level encryption when a DEK is loaded (MNEURIX_REST_ENCRYPTION=app-dek). */
	private write(did: string, json: string): void {
		const dek = loadDataEncryptionKey();
		const data = dek ? encryptAtRest(json, dek) : json;
		writeFileSync(this.pathFor(did), data, "utf8");
	}
	/** Read + decrypt when a DEK is loaded. */
	private read(did: string): string | undefined {
		const p = this.pathFor(did);
		if (!existsSync(p)) return undefined;
		try {
			const raw = readFileSync(p, "utf8");
			const dek = loadDataEncryptionKey();
			return dek ? decryptAtRest(raw, dek).toString("utf8") : raw;
		} catch {
			return undefined;
		}
	}
}

/** Env-driven factory: postgres → Postgres (stub), prod → FileDidStore, dev → InMemory. */
export function createDidStore(): DidStore {
	if (process.env.MNEURIX_DB_BACKEND === "postgres") {
		// Postgres backend requires the `pg` dep (not yet added). Fail-closed
		// with a clear message rather than silently falling back to files.
		throw new Error(
			"MNEURIX_DB_BACKEND=postgres requires the `pg` dependency — not yet installed. Use the file backend (unset MNEURIX_DB_BACKEND) or add `pg`.",
		);
	}
	// Prod-like hosts use the durable file backend; dev/tests use in-memory
	// (mirrors the lattice's dev-default pattern so _resetForTests works).
	const isProdLike =
		process.env.MNEURIX_ENV === "production" ||
		process.env.MNEURIX_ON_PREM === "1";
	if (isProdLike || process.env.MNEURIX_DID_STORE === "file") {
		return new FileDidStore();
	}
	return new InMemoryDidStore();
}

// Module-level store (selected at load) + the existing API delegates to it.
const store: DidStore = createDidStore();

export function putDid(did: string, document: DidDocument, kid: string): void {
	store.putDid(did, document, kid);
}

export function getDid(did: string): Stored | undefined {
	return store.getDid(did);
}

/** Record a successful multi-origin publish on the stored DID record. */
export function setPublished(did: string, origins: string[], docHash: string): void {
	store.setPublished(did, origins, docHash);
}

/** Test helper — clears the in-memory store (no-op for file store). */
export function _resetForTests(): void {
	if (store instanceof InMemoryDidStore) {
		store.clear();
	}
}