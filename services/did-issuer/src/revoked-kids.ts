/** F15 signed revoked-kids tombstone (M6) — mirrors the lattice's
 * `RevokedIssuerKeys` (CISO F15): the current issuance key signs the list of
 * revoked signing-key ids, so a verifier can reject a VC signed by a revoked
 * kid (fail-closed). The tombstone is a W3C Data-Integrity-signed doc.
 *
 * v1 is in-memory (the durable `revoked-kids.json` + TTL cache land in M10).
 * The list is signed on every mutation with the current issuer key.
 *
 * Purity: node:crypto-free; signing delegated to vc-issue.signDataIntegrity. */
import { signDataIntegrity, verifyDataIntegrity, type SignedDoc } from "./vc-issue";
import { getKeyByKid } from "./keys";
import type { KeyMaterial } from "@mneurix/shared";

export interface RevokedKidsDoc extends SignedDoc {
	type: "RevokedIssuerKeys";
	revokedKids: string[];
	updated: string;
	signedByKid: string;
}

let revokedKids: string[] = [];
let tombstone: RevokedKidsDoc | null = null;

/** Append `kid` to the revoked list + re-sign the tombstone with `keys` (the
 * current issuance key). Idempotent. `verificationMethod` = did:web#currentKid. */
export async function revokeKid(
	kid: string,
	keys: KeyMaterial,
	verificationMethod: string,
): Promise<RevokedKidsDoc> {
	if (!revokedKids.includes(kid)) revokedKids = [...revokedKids, kid];
	const doc: Omit<RevokedKidsDoc, "proof"> = {
		type: "RevokedIssuerKeys",
		revokedKids: [...revokedKids],
		updated: new Date().toISOString(),
		signedByKid: keys.kid,
	};
	tombstone = (await signDataIntegrity(doc, keys, verificationMethod)) as RevokedKidsDoc;
	return tombstone;
}

/** Is `kid` revoked? Fail-closed: the tombstone signature MUST verify against
 * the signing kid's public key (resolved from the key store) before the list
 * is trusted. Returns false when there is no tombstone or it doesn't verify. */
export async function isKidRevoked(kid: string): Promise<boolean> {
	if (!tombstone) return false;
	const signer = getKeyByKid(tombstone.signedByKid);
	if (!signer) return false; // can't verify the tombstone → no positive record
	const ok = await verifyDataIntegrity(tombstone, signer);
	if (!ok) return false;
	return tombstone.revokedKids.includes(kid);
}

/** The current signed tombstone (or null). */
export function getRevokedKidsDoc(): RevokedKidsDoc | null {
	return tombstone;
}

/** The raw revoked-kids list (no signature check — for diagnostics). */
export function revokedKidsList(): string[] {
	return [...revokedKids];
}

export function _resetRevokedKidsForTests(): void {
	revokedKids = [];
	tombstone = null;
}