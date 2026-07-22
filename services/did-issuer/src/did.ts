/** did:web DID document builder (M3) — W3C DID Core v1.0 + did:web method.
 *
 * The DID string is `did:web:<origin>` (origin without scheme; colons allowed).
 * The verification method is a JsonWebKey carrying an Ed25519 public key
 * (vc-jose-cose §4.2). Multi-origin resolution + atomic publish land in M4;
 * M3 resolves from the local store.
 *
 * Purity: node:crypto (createPublicKey for PEM->JWK). */
import { createPublicKey } from "node:crypto";

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
