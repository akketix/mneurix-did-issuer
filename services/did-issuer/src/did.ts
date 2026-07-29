// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** did:web DID document builder (M3) — W3C DID Core v1.0 + did:web method.
 *
 * The DID string is `did:web:<origin>` (origin without scheme; colons allowed).
 * The verification method is a JsonWebKey carrying an Ed25519 public key
 * (vc-jose-cose §4.2). Multi-origin resolution + atomic publish land in M4;
 * M3 resolves from the local store.
 *
 * Purity: node:crypto (createPublicKey for PEM->JWK). */
import { createHash, createPublicKey } from "node:crypto";

export interface DidDocument {
	"@context": string[];
	id: string;
	verificationMethod: {
		id: string;
		type: "JsonWebKey";
		controller: string;
		publicKeyJwk: Record<string, string>;
	}[];
	assertionMethod: string[];
	/** URIs identifying the same subject (DID Core §4.1). M4 lists mirror origins here. */
	alsoKnownAs?: string[];
	/** Transport-only list of origin URLs that serve this document (M4 resilience). */
	"x-mneurix-did-origins"?: string[];
}

export function didFor(origin: string): string {
	return "did:web:" + origin;
}

export function publicKeyJwkFromPem(publicKeyPem: string): Record<string, string> {
	return createPublicKey(publicKeyPem).export({ format: "jwk" }) as Record<string, string>;
}

export function buildDidDocument(origin: string, kid: string, publicKeyJwk: Record<string, string>): DidDocument {
	const did = didFor(origin);
	const vmId = did + "#" + kid;
	return {
		"@context": ["https://www.w3.org/ns/did/v1"],
		id: did,
		verificationMethod: [{ id: vmId, type: "JsonWebKey", controller: did, publicKeyJwk }],
		assertionMethod: [vmId],
	};
}

/** A DID document carrying multiple verification methods (M6 rotation): the
 * old key is retained (so pre-rotation VCs stay verifiable) while
 * `assertionMethod` lists only the keys authorised to sign NEW credentials. */
export interface DidMethod {
	kid: string;
	publicKeyJwk: Record<string, string>;
}

export function buildDidDocumentMulti(
	origin: string,
	methods: DidMethod[],
	assertionKids: string[],
): DidDocument {
	const did = didFor(origin);
	return {
		"@context": ["https://www.w3.org/ns/did/v1"],
		id: did,
		verificationMethod: methods.map((m) => ({ id: `${did}#${m.kid}`, type: "JsonWebKey", controller: did, publicKeyJwk: m.publicKeyJwk })),
		assertionMethod: assertionKids.map((k) => `${did}#${k}`),
	};
}

/** Inverse of `didFor`: the origin segment of a `did:web:<origin>` string. */
export function originFromDid(did: string): string {
	return did.startsWith("did:web:") ? did.slice("did:web:".length) : did;
}

/** JCS-inspired deterministic canonicalization (RFC 8785-shaped): recursively
 * sort object keys, preserve array order, no insignificant whitespace. Full
 * RFC 8785 number/unicode edge cases are a future hardening; DID documents are
 * strings + arrays + nested objects, so this is byte-stable for hash pinning. */
export function canonicalDocBytes(value: unknown): string {
	if (value === null) return "null";
	if (Array.isArray(value)) return "[" + value.map(canonicalDocBytes).join(",") + "]";
	if (typeof value === "object") {
		const obj = value as Record<string, unknown>;
		return "{" + Object.keys(obj).sort().map((k) => JSON.stringify(k) + ":" + canonicalDocBytes(obj[k])).join(",") + "}";
	}
	return JSON.stringify(value);
}

/** SHA-256 over the canonical document bytes — the pinned doc hash used by the
 * M4 fan-out/quorum resolver to detect byte-level disagreement between origins. */
export function didHash(document: DidDocument): string {
	return createHash("sha256").update(canonicalDocBytes(document)).digest("hex");
}
