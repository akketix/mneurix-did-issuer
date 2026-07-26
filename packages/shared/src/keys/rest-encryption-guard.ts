/**
 * @mneurix/shared/keys/rest-encryption-guard — encryption-at-rest enforcement
 * (the "attest + enforce, don't prescribe" model).
 *
 * Layer 2 (boot attestation) + Layer 3 (app-level envelope encryption):
 *
 *   - `MNEURIX_REST_ENCRYPTION=attested` — the operator confirms disk/volume
 *     encryption is configured (LUKS, cloud volumes, etc.). Required in prod
 *     (fail-closed without it). The product trusts the attestation.
 *   - `MNEURIX_REST_ENCRYPTION=app-dek`  — the product uses app-level AES-256-GCM
 *     with a customer-supplied DEK (`MNEURIX_DATA_ENCRYPTION_KEY`, >=32 chars).
 *     The DEK is derived via scrypt (same proven pattern as key custody). The
 *     customer holds the secret; the product enforces the encryption.
 *   - unset in prod                  → THROW (refuse to boot unencrypted).
 *
 * The encrypt/decrypt pair (AES-256-GCM) is used by the file stores when
 * `app-dek` is active. When `attested`, the file stores pass through (the disk
 * encryption handles at-rest confidentiality).
 *
 * Purity: node:crypto only (scrypt, AES-GCM). */
import {
	scryptSync,
	randomBytes,
	createCipheriv,
	createDecipheriv,
} from "node:crypto";

export type RestEncryptionMode = "attested" | "app-dek" | "none";

// Scrypt params — mirror the key custody (local-sealed.ts) for consistency.
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 32;
const SCRYPT_MAXMEM = 128 * 1024 * 1024; // 128 MiB
const GCM_IV_LEN = 12;
/** Fixed salt for the DEK derivation (the customer's secret is the variable). */
const REST_DEK_SALT = "mneurix-rest-encryption-dek-v1";

/** Minimum length for the customer-supplied DEK secret. */
export const MIN_DEK_SECRET_LEN = 32;

/**
 * Layer 2: assert that encryption-at-rest is configured in production. Returns
 * the active mode. Throws (refuses to boot) in prod-like hosts when
 * MNEURIX_REST_ENCRYPTION is unset — the product enforces, the customer attests.
 */
export function assertRestEncryptionInProd(opts: {
	env?: string;
	onPrem?: boolean;
} = {}): RestEncryptionMode {
	const env = opts.env ?? process.env.MNEURIX_ENV;
	const onPrem = opts.onPrem ?? process.env.MNEURIX_ON_PREM === "1";
	const isProdLike = env === "production" || onPrem;
	const raw = (process.env.MNEURIX_REST_ENCRYPTION ?? "none").trim().toLowerCase();
	const mode: RestEncryptionMode =
		raw === "attested" ? "attested" : raw === "app-dek" ? "app-dek" : "none";

	if (isProdLike && mode === "none") {
		throw new Error(
			"MNEURIX_ENV=production requires MNEURIX_REST_ENCRYPTION=attested (disk/volume encryption) or =app-dek (app-level AES-GCM with MNEURIX_DATA_ENCRYPTION_KEY) — refusing to boot unencrypted (encryption-at-rest enforcement).",
		);
	}
	if (mode === "app-dek") {
		const secret = process.env.MNEURIX_DATA_ENCRYPTION_KEY;
		if (!secret || secret.length < MIN_DEK_SECRET_LEN) {
			throw new Error(
				`MNEURIX_REST_ENCRYPTION=app-dek requires MNEURIX_DATA_ENCRYPTION_KEY (>=${MIN_DEK_SECRET_LEN} chars) — the customer-supplied data encryption key. The key stays in the customer's hands; the product derives the AES key via scrypt.`,
			);
		}
	}
	return mode;
}

let cachedDek: Buffer | null = null;

/**
 * Layer 3: load the data encryption key (DEK) derived from the customer's
 * `MNEURIX_DATA_ENCRYPTION_KEY` secret via scrypt. Returns null when the secret
 * is not set (the `attested` mode — no app-level encryption, disk encryption
 * handles it). The DEK is cached after the first derivation (scrypt is expensive).
 */
export function loadDataEncryptionKey(): Buffer | null {
	if (cachedDek) return cachedDek;
	const secret = process.env.MNEURIX_DATA_ENCRYPTION_KEY;
	if (!secret || secret.length < MIN_DEK_SECRET_LEN) return null;
	cachedDek = scryptSync(secret, REST_DEK_SALT, SCRYPT_DKLEN, {
		N: SCRYPT_N,
		r: SCRYPT_R,
		p: SCRYPT_P,
		maxmem: SCRYPT_MAXMEM,
	});
	return cachedDek;
}

/** Reset the cached DEK (test helper). */
export function _resetDekCache(): void {
	cachedDek = null;
}

/**
 * Encrypt a plaintext (string or Buffer) with AES-256-GCM. Returns
 * `base64url(iv).base64url(ciphertext + authTag)`. The GCM tag provides
 * tamper-evidence (a tampered ciphertext fails on decrypt).
 */
export function encryptAtRest(plaintext: string | Buffer, key: Buffer): string {
	const iv = randomBytes(GCM_IV_LEN);
	const cipher = createCipheriv("aes-256-gcm", key, iv);
	const buf =
		typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : plaintext;
	const ciphertext = Buffer.concat([cipher.update(buf), cipher.final()]);
	const tag = cipher.getAuthTag();
	return `${iv.toString("base64url")}.${Buffer.concat([ciphertext, tag]).toString("base64url")}`;
}

/**
 * Decrypt an `encryptAtRest`-encoded ciphertext. Returns the plaintext Buffer.
 * Throws on a malformed ciphertext or a failed GCM auth-tag verification
 * (tamper-evidence).
 */
export function decryptAtRest(encoded: string, key: Buffer): Buffer {
	const sep = encoded.indexOf(".");
	if (sep < 0) throw new Error("decryptAtRest: malformed ciphertext (no separator)");
	const iv = Buffer.from(encoded.slice(0, sep), "base64url");
	const ctTag = Buffer.from(encoded.slice(sep + 1), "base64url");
	if (iv.length !== GCM_IV_LEN || ctTag.length < 16) {
		throw new Error("decryptAtRest: malformed ciphertext (bad IV or missing tag)");
	}
	const tag = ctTag.subarray(ctTag.length - 16);
	const ciphertext = ctTag.subarray(0, ctTag.length - 16);
	const decipher = createDecipheriv("aes-256-gcm", key, iv);
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}