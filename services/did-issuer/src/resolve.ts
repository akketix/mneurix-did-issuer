/** Fan-out + quorum resolver (M4).
 *
 * Resolves a did:web identifier by fetching `/.well-known/did.json` from every
 * configured origin in parallel, keeping only documents whose `id` matches the
 * requested DID, then quoruming on the majority document hash. `verified`
 * requires M-of-N (quorum) agreement AND — when a pinned hash is supplied
 * (the issuer's own stored publish hash) — that the majority hash equals the
 * pinned hash, so a tampered majority is still rejected. On disagreement the
 * resolver falls back to the majority document with `verified:false`.
 *
 * Purity: node fetch via the injected `OriginPublisher`. */
import type { DidDocument } from "./did";
import { didHash } from "./did";
import { didDocUrl, type Origin, type OriginList } from "./origins";
import type { OriginPublisher } from "./publish";
import { LocalHttpPublisher } from "./publish";

export interface OriginHashMatch {
	origin: string;
	doc: DidDocument;
	hash: string;
}

export interface QuorumMismatch {
	origin: string;
	docHash: string;
}

export interface QuorumResult {
	did: string;
	document: DidDocument | null;
	/** Origins that returned the majority doc (in origin-list order). */
	resolvedFrom: string[];
	/** The majority document hash ("" if nothing resolved). */
	docHash: string;
	verified: boolean;
	/** Origins that returned a different doc (diagnostics). */
	mismatches: QuorumMismatch[];
}

/**
 * Fan out + quorum-resolve `did`. `pinnedHash` is optional: when provided by
 * the issuer (stored at publish time), `verified` additionally requires the
 * majority hash to equal it. A third-party verifier calls without a pinned
 * hash and relies on majority quorum alone.
 */
export async function resolveDid(
	did: string,
	originList: OriginList,
	pinnedHash?: string,
	publisher: OriginPublisher = new LocalHttpPublisher(),
): Promise<QuorumResult> {
	const fetched = await Promise.all(
		originList.origins.map(async (o: Origin) => {
			try {
				const doc = await publisher.get(didDocUrl(o));
				if (!doc || doc.id !== did) return null;
				return { origin: o.url, doc, hash: didHash(doc) } satisfies OriginHashMatch;
			} catch {
				return null;
			}
		}),
	);
	const ok = fetched.filter((f): f is OriginHashMatch => f !== null);

	const byHash = new Map<string, { count: number; first: OriginHashMatch }>();
	for (const f of ok) {
		const existing = byHash.get(f.hash);
		if (existing) {
			existing.count++;
		} else {
			byHash.set(f.hash, { count: 1, first: f });
		}
	}

	let best: { hash: string; count: number; first: OriginHashMatch } | null = null;
	for (const [hash, entry] of byHash) {
		if (best === null || entry.count > best.count) {
			best = { hash, count: entry.count, first: entry.first };
		}
	}

	if (best === null) {
		return { did, document: null, resolvedFrom: [], docHash: "", verified: false, mismatches: [] };
	}

	const resolvedFrom = ok.filter((f) => f.hash === best!.hash).map((f) => f.origin);
	const mismatches = ok
		.filter((f) => f.hash !== best!.hash)
		.map((f) => ({ origin: f.origin, docHash: f.hash }));
	const quorumMet = best.count >= originList.quorum;
	const pinnedOk = pinnedHash === undefined || best.hash === pinnedHash;

	return {
		did,
		document: best.first.doc,
		resolvedFrom,
		docHash: best.hash,
		verified: quorumMet && pinnedOk,
		mismatches,
	};
}