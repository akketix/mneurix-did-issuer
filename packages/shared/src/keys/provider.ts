/**
 * @mneurix/shared/keys/provider — pluggable issuer key custody (G-CRYPTO-1).
 *
 * The credential service never touches key material directly; it goes through
 * a `KeyProvider`. Two implementations ship:
 *
 *  - **`PemKeyProvider`** (dev only) — plaintext PEM on disk under
 *    `data/keys/`. Backward-compatible with the original `keys.ts` path. The
 *    prod boot guard (`boot-guard.ts`) refuses to start the credential service
 *    with this provider when `MNEURIX_ENV=production`.
 *
 *  - **`LocalSealedKeyProvider`** (prod) — Ed25519 private seeds sealed at
 *    rest with AES-256-GCM under a master key that is itself sealed by a
 *    scrypt-derived key-encryption-key (KEK) from a passphrase. No external
 *    KMS SDK, no age/softhsm — `node:crypto` only (purity gate).
 *
 * Verification is a *public* operation: `publicById(kid)` returns the public
 * PEM without unsealing the private seed, so the `/verify` and `/issuer/:kid`
 * endpoints never need the passphrase. Only issuance (`getCurrent`/`rotate`)
 * unseals, which happens in the single credential-service process that holds
 * the passphrase in env.
 *
 * **Open risk (CISO security, §4):** a single sealed `master.key` is a
 * total-loss cliff — no Shamir M-of-N escrow is in scope for this slice. An
 * offline backup + operator runbook are required before prod. The interface is
 * shaped so a future `ShamirEscrowKeyProvider` can slot in without touching
 * callers.
 */
import type { KeyMaterial } from "./keyMaterial";

/**
 * Public-only key material — sufficient for signature verification and key-doc
 * publishing. `privateKeyPem` is the empty string by convention so it can be
 * passed to `expandKey()` which tolerates its absence.
 */
export interface PublicKeyMaterial {
	readonly publicKeyPem: string;
	readonly kid: string;
}

/**
 * Key custody plug-in. Implementations MUST be deterministic for a given
 * `kid` (repeated `getById`/`publicById` for the same kid return equivalent
 * material) and MUST NOT persist plaintext private keys outside dev.
 */
export interface KeyProvider {
	/** Human-readable provider id, e.g. "pem" | "local-sealed". */
	readonly name: string;

	/** Current issuance key (unseals the private seed). */
	getCurrent(): KeyMaterial;

	/** Full key material for `kid` (unseals). `null` if unknown. */
	getById(kid: string): KeyMaterial | null;

	/** Get the key for `kid`, creating it if absent. Does NOT change the
	 * current issuance kid (use for side keys like statusKid). */
	ensureKey(kid: string): KeyMaterial;

	/** Public-only material for `kid` — no unseal, no passphrase needed. */
	publicById(kid: string): PublicKeyMaterial | null;

	/** The current issuance kid. */
	readonly currentKid: string;

	/** Rotate: generate a fresh keypair, persist + set it current, return it. */
	rotate(): KeyMaterial;
}

export * from "./keyMaterial";
