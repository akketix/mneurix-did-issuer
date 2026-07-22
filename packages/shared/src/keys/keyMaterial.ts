/**
 * @mneurix/shared/keys/keyMaterial — the canonical issuer key shape.
 *
 * Single source of truth for `KeyMaterial` so the credential service, the
 * sealed-key provider, and `ob3.ts` all agree on what a custodied Ed25519
 * issuer key looks like. Moved here from `services/credential/src/keys.ts`
 * (which re-exports it for backward compatibility).
 *
 * `privateKeyPem` is the PKCS#8 PEM of the Ed25519 private key. For
 * **public-only** material (verification, key docs) it is the empty string
 * `""` by convention; `expandKey()` tolerates this and derives only the
 * public half. Callers that sign MUST go through a `KeyProvider` that
 * actually unsealed the private seed.
 */
export interface KeyMaterial {
	/** PKCS#8 PEM, base64 — the private key. Empty string `""` = public-only. */
	privateKeyPem: string;
	/** SPKI PEM, base64 — safe to publish for peer verification. */
	publicKeyPem: string;
	/** Stable key id (hash of the public key) — used as `issuerKeyId`. */
	kid: string;
}
