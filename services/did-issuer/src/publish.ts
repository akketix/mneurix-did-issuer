// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Atomic 2-phase multi-origin publisher (M4).
 *
 * Publishes the *identical* DID document to every configured origin in
 * parallel. Stage = PUT + round-trip verify (GET back, id match, hash match).
 * Commit = the staged writes stand. Rollback = DELETE the staged doc from every
 * origin that accepted it, so a failed quorum leaves NO half-published
 * document on any origin.
 *
 * v1 models stage/commit as idempotent PUT + DELETE-on-rollback over plain
 * HTTP (the local/mock origin contract). Real cloud publishers (M10 runbook)
 * implement true stage-then-rename (e.g. write `did.json.staged` then atomic
 * rename) behind the same `OriginPublisher` interface.
 *
 * Purity: node fetch (global `fetch`, Node >=20). */
import type { DidDocument } from "./did";
import { didHash } from "./did";
import { didDocUrl, embedOriginsInDoc, type OriginList } from "./origins";

/** Transport seam: how a DID document is written/read/removed at one origin.
 * Swappable so cloud publishers (S3-website PUT, Cloudflare Pages, DO Spaces,
 * GitHub Pages) plug in without touching the publish algorithm. */
export interface OriginPublisher {
	put(url: string, doc: DidDocument): Promise<boolean>;
	get(url: string): Promise<DidDocument | null>;
	delete(url: string): Promise<boolean>;
}

/** Default publisher over plain HTTP(S) using the global fetch. */
export class LocalHttpPublisher implements OriginPublisher {
	async put(url: string, doc: DidDocument): Promise<boolean> {
		const res = await fetch(url, {
			method: "PUT",
			headers: { "content-type": "application/json" },
			body: JSON.stringify(doc),
		});
		return res.ok;
	}
	async get(url: string): Promise<DidDocument | null> {
		const res = await fetch(url);
		if (!res.ok) return null;
		return (await res.json()) as DidDocument;
	}
	async delete(url: string): Promise<boolean> {
		const res = await fetch(url, { method: "DELETE" });
		return res.ok;
	}
}

export interface PublishResult {
	/** Origin base URLs that staged + round-trip verified. */
	publishedTo: string[];
	/** Required M-of-N. */
	quorum: number;
	/** Origins that actually confirmed. */
	confirmed: number;
	/** Hash of the published (origin-embedded) document. */
	docHash: string;
	/** true iff confirmed >= quorum (committed); false = rolled back. */
	staged: boolean;
}

/**
 * Stage the origin-embedded DID document to all origins; commit on quorum,
 * otherwise rollback. Returns the publish result (never throws — failures are
 * reflected as `staged:false`).
 */
export async function publishDid(
	originList: OriginList,
	did: string,
	document: DidDocument,
	publisher: OriginPublisher = new LocalHttpPublisher(),
): Promise<PublishResult> {
	const publishedDoc = embedOriginsInDoc(document, originList.origins);
	const docHash = didHash(publishedDoc);

	const staged = await Promise.all(
		originList.origins.map(async (o) => {
			const url = didDocUrl(o);
			try {
				const putOk = await publisher.put(url, publishedDoc);
				if (!putOk) return null;
				const got = await publisher.get(url);
				if (!got || got.id !== did) return null;
				return didHash(got) === docHash ? { origin: o.url, docUrl: url } : null;
			} catch {
				return null;
			}
		}),
	);
	const stagedTo = staged.filter((s): s is { origin: string; docUrl: string } => s !== null);

	if (stagedTo.length >= originList.quorum) {
		return { publishedTo: stagedTo.map((s) => s.origin), quorum: originList.quorum, confirmed: stagedTo.length, docHash, staged: true };
	}

	// Rollback: no half-published doc. Delete the *full* did.json URL on each
	// origin that staged (not the origin base URL).
	await Promise.all(stagedTo.map((s) => publisher.delete(s.docUrl).catch(() => false)));
	return { publishedTo: [], quorum: originList.quorum, confirmed: stagedTo.length, docHash, staged: false };
}