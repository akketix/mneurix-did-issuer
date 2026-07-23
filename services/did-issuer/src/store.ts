/** DID-document store (M3 MVP — in-memory; M4 adds multi-origin persistence).
 *
 * M4 stores the origin list + pinned doc hash alongside the document so the
 * issuer's own resolver can pin against the publish-time hash. The hot read
 * path is the in-memory Map; the durable record lands with the M10
 * SQLite/Postgres backend (env-driven swap). Purity: none. */
import type { DidDocument } from "./did";

interface Stored {
	document: DidDocument;
	kid: string;
	createdAt: string;
	/** Origin base URLs the doc was published to (empty/absent = minted, not published). */
	origins?: string[];
	/** Pinned hash of the *published* (origin-embedded) document, set at publish time. */
	docHash?: string;
}

const docs = new Map<string, Stored>();

export function putDid(did: string, document: DidDocument, kid: string): void {
	docs.set(did, { document, kid, createdAt: new Date().toISOString() });
}

export function getDid(did: string): Stored | undefined {
	return docs.get(did);
}

/** Record a successful multi-origin publish on the stored DID record. */
export function setPublished(did: string, origins: string[], docHash: string): void {
	const s = docs.get(did);
	if (!s) return;
	docs.set(did, { ...s, origins, docHash });
}

export function _resetForTests(): void {
	docs.clear();
}