/** DID-document store (M3 MVP — in-memory).
 *
 * M4 adds the multi-origin publisher + fan-out/quorum resolver. Purity: none. */
import type { DidDocument } from "./did";

interface Stored {
	document: DidDocument;
	kid: string;
	createdAt: string;
}

const docs = new Map<string, Stored>();

export function putDid(did: string, document: DidDocument, kid: string): void {
	docs.set(did, { document, kid, createdAt: new Date().toISOString() });
}

export function getDid(did: string): Stored | undefined {
	return docs.get(did);
}

export function _resetForTests(): void {
	docs.clear();
}
