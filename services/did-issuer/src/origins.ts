/** Multi-cloud DID-document origin config (M4).
 *
 * did:web anchors a DID to ONE canonical HTTPS origin (resolvable at
 * `/.well-known/did.json`). For resilience we publish the *same* DID document
 * to N independent origins on different clouds and resolve by fan-out + quorum
 * (M-of-N byte-identical match). The origin list is a TRANSPORT concern — it
 * is embedded in the DID document (`alsoKnownAs` + the custom
 * `x-mneurix-did-origins` array) but is NOT part of the DID string, so the DID
 * stays stable as origins are added or removed.
 *
 * v1 scope (locked decision 2026-07-23): mechanism first, LOCAL/MOCK origins
 * only. `MNEURIX_DID_ORIGINS` is a comma list of origin base URLs
 * (e.g. `http://127.0.0.1:9001,http://127.0.0.1:9002`). Real cloud publishers
 * (DO Space + GitHub Pages) are deferred to a deploy milestone.
 *
 * Purity: none (reads env; fetch lives in publish.ts/resolve.ts). */
import type { DidDocument } from "./did";

export interface Origin {
	/** Base URL of the origin, e.g. "http://127.0.0.1:9001" (no trailing slash). */
	url: string;
	/** Optional path prefix under the origin, e.g. "" or "/path". Default "". */
	path: string;
}

export interface OriginList {
	origins: Origin[];
	strategy: "fanout-quorum";
	/** M-of-N: how many origins must return a byte-identical doc for `verified`. */
	quorum: number;
}

/** Where a did:web document is served on an origin (did:web method spec). */
export function didDocUrl(origin: Origin): string {
	const base = origin.url.replace(/\/+$/, "");
	const path = origin.path === "" ? "" : origin.path.replace(/\/+$/, "");
	return `${base}${path}/.well-known/did.json`;
}

/** Parse one `MNEURIX_DID_ORIGINS` entry ("url" or "url|path") into an Origin. */
export function parseOrigin(entry: string): Origin {
	const [url, path] = entry.split("|");
	return { url: (url ?? "").trim(), path: (path ?? "").trim() };
}

/**
 * Build the origin list from `MNEURIX_DID_ORIGINS` (comma-separated
 * `url[|path]` entries). Quorum defaults to a strict majority (floor(N/2)+1),
 * minimum 1; an empty config yields an empty list (resolver then falls back to
 * the local store — the M3 behaviour).
 */
export function loadOriginsFromEnv(env: string | undefined = process.env.MNEURIX_DID_ORIGINS): OriginList {
	const origins = (env ?? "")
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean)
		.map(parseOrigin)
		.filter((o) => o.url.length > 0);
	const quorum = origins.length === 0 ? 0 : Math.max(1, Math.floor(origins.length / 2) + 1);
	return { origins, strategy: "fanout-quorum", quorum };
}

/** Build an OriginList from raw origin URLs (used by the publish endpoint when
 * the caller supplies origins in the body). Quorum = strict majority. */
export function originListFromUrls(urls: string[]): OriginList {
	const origins = urls.map((u) => parseOrigin(u)).filter((o) => o.url.length > 0);
	const quorum = origins.length === 0 ? 0 : Math.max(1, Math.floor(origins.length / 2) + 1);
	return { origins, strategy: "fanout-quorum", quorum };
}

/**
 * Embed the origin list into a DID document for publication: mirror URLs go in
 * `alsoKnownAs` (URIs identifying the same subject) and the full transport list
 * goes in the custom `x-mneurix-did-origins` array. The DID string is untouched.
 */
export function embedOriginsInDoc(doc: DidDocument, origins: Origin[]): DidDocument {
	const mirrorUrls = origins.map((o) => o.url);
	const alsoKnownAs = [...(doc.alsoKnownAs ?? []), ...mirrorUrls];
	return {
		...doc,
		alsoKnownAs,
		"x-mneurix-did-origins": mirrorUrls,
	};
}