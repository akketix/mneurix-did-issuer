// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/**
 * @mneurix/shared/keys/local-sealed — self-built KMS custody (G-CRYPTO-1).
 *
 * Two-layer sealing, `node:crypto` only (purity gate: no KMS SDK, no age/softhsm):
 *
 *  1. **Master key** — a random 32-byte secret, sealed at rest by a
 *     key-encryption-key (KEK) derived from `MNEURIX_KEY_PASSPHRASE` via
 *     **scrypt** (params pinned, see `SCRYPT_*`). Stored as `master.key`.
 *  2. **Issuer private seeds** — each Ed25519 seed sealed by the master key
 *     with **AES-256-GCM** (authenticated). Stored as `<kid>.sealed`.
 *
 * Public keys remain plaintext PEM (`<kid>.public.pem`) — they are public.
 * `current.kid` names the issuance key. The passphrase never touches disk.
 *
 * **Verification needs no passphrase:** `publicById(kid)` reads only the
 * public PEM. Only `getCurrent`/`getById`/`rotate` unseal, and only the
 * credential-service process holds the passphrase (in env).
 *
 * **Open risk (CISO security §4, concern #2):** a single sealed `master.key`
 * is a total-loss cliff; Shamir M-of-N escrow is out of scope for this slice.
 * Offline backup + operator runbook required before prod. The
 * `KeyProvider` interface is shaped for a future `ShamirEscrowKeyProvider`.
 */
import {
	scryptSync,
	randomBytes,
	createCipheriv,
	createDecipheriv,
	generateKeyPairSync,
	createPrivateKey,
	createPublicKey,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { KeyMaterial, KeyProvider, PublicKeyMaterial } from "./provider";

/** Pinned scrypt cost (CISO: benchmark + pin, not default). ~0.1–0.4s on dev HW. */
const SCRYPT_N = 16384;
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_DKLEN = 32;
const SCRYPT_MAXMEM = 128 * 1024 * 1024; // 128 MiB — must exceed N*r*p*(128)
const MASTER_SALT_LEN = 16;
const GCM_IV_LEN = 12;
const KEY_SEED_LEN = 32;

const MASTER_FILENAME = "master.key";

interface SealedMaster {
	version: 1;
	kdf: { name: "scrypt"; N: number; r: number; p: number; dkLen: number };
	salt: string; // base64url
	nonce: string; // base64url — AES-256-GCM IV
	ciphertext: string; // base64url — encrypted master key (32 bytes) + GCM tag
}

interface SealedKey {
	version: 1;
	kid: string;
	publicKeyPem: string;
	nonce: string; // base64url
	ciphertext: string; // base64url — encrypted Ed25519 seed (32 bytes) + GCM tag
}

const b64u = (b: Buffer | Uint8Array): string =>
	Buffer.from(b).toString("base64url");
const fromB64u = (s: string): Buffer => Buffer.from(s, "base64url");

/** AES-256-GCM seal: returns base64url(nonce || ciphertext || tag) is NOT used;
 * nonce + (ciphertext||tag) stored separately for clarity. */
function gcmSeal(
	key: Buffer,
	plaintext: Buffer,
): { nonce: string; ciphertext: string } {
	const nonce = randomBytes(GCM_IV_LEN);
	const cipher = createCipheriv("aes-256-gcm", key, nonce);
	const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
	const tag = cipher.getAuthTag();
	return { nonce: b64u(nonce), ciphertext: b64u(Buffer.concat([ct, tag])) };
}

function gcmUnseal(key: Buffer, nonceB64: string, ctB64: string): Buffer {
	const nonce = fromB64u(nonceB64);
	const bundle = fromB64u(ctB64);
	if (bundle.length < 16) throw new Error("local-sealed: ciphertext truncated");
	const ct = bundle.subarray(0, bundle.length - 16);
	const tag = bundle.subarray(bundle.length - 16);
	const decipher = createDecipheriv("aes-256-gcm", key, nonce);
	decipher.setAuthTag(tag);
	return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/** Derive the KEK from the passphrase + salt using the pinned scrypt params. */
function deriveKek(passphrase: string, salt: Buffer): Buffer {
	return scryptSync(passphrase, salt, SCRYPT_DKLEN, {
		N: SCRYPT_N,
		r: SCRYPT_R,
		p: SCRYPT_P,
		maxmem: SCRYPT_MAXMEM,
	});
}

export interface LocalSealedKeyProviderOptions {
	/** Directory for sealed key material. Defaults to ./data/keys. */
	dir?: string;
	/** Passphrase protecting the master key. Required (non-empty). */
	passphrase: string;
	/** Default kid when none exists yet (dev compatibility). */
	defaultKid?: string;
}

/**
 * Sealed-key custody provider. Construct once at boot (after the prod boot
 * guard has validated the passphrase) and reuse for every issuance/rotation.
 */
export class LocalSealedKeyProvider implements KeyProvider {
	public readonly name = "local-sealed";
	private readonly dir: string;
	private readonly passphrase: string;
	private readonly defaultKid: string;
	private masterKey: Buffer | null = null;
	private _currentKid: string | null = null;

	constructor(opts: LocalSealedKeyProviderOptions) {
		if (!opts.passphrase || opts.passphrase.length === 0) {
			throw new Error("local-sealed: MNEURIX_KEY_PASSPHRASE is required");
		}
		this.dir = resolve(opts.dir ?? join(process.cwd(), "data", "keys"));
		this.passphrase = opts.passphrase;
		this.defaultKid = opts.defaultKid ?? "mneurix-issuer-001";
		mkdirSync(this.dir, { recursive: true });
	}

	get currentKid(): string {
		if (this._currentKid === null) {
			const kidPath = join(this.dir, "current.kid");
			try {
				this._currentKid = readFileSync(kidPath, "utf8").trim();
			} catch {
				this._currentKid = this.defaultKid;
			}
		}
		return this._currentKid;
	}

	private setCurrentKid(kid: string): void {
		this._currentKid = kid;
		writeFileSync(join(this.dir, "current.kid"), kid);
	}

	/** Load (or create) the sealed master key, returning the raw 32 bytes. */
	private getMaster(): Buffer {
		if (this.masterKey) return this.masterKey;
		const masterPath = join(this.dir, MASTER_FILENAME);
		if (existsSync(masterPath)) {
			const sealed = JSON.parse(
				readFileSync(masterPath, "utf8"),
			) as SealedMaster;
			const kek = deriveKek(this.passphrase, fromB64u(sealed.salt));
			let master: Buffer;
			try {
				master = gcmUnseal(kek, sealed.nonce, sealed.ciphertext);
			} catch {
				throw new Error(
					"local-sealed: master key unseal failed — wrong MNEURIX_KEY_PASSPHRASE or tampered master.key (G-CRYPTO-1)",
				);
			}
			this.masterKey = master; // exactly 32 bytes
			return this.masterKey;
		}
		// First run: generate + seal a fresh master key.
		const master = randomBytes(KEY_SEED_LEN);
		const salt = randomBytes(MASTER_SALT_LEN);
		const kek = deriveKek(this.passphrase, salt);
		const { nonce, ciphertext } = gcmSeal(kek, master);
		const sealed: SealedMaster = {
			version: 1,
			kdf: {
				name: "scrypt",
				N: SCRYPT_N,
				r: SCRYPT_R,
				p: SCRYPT_P,
				dkLen: SCRYPT_DKLEN,
			},
			salt: b64u(salt),
			nonce,
			ciphertext,
		};
		writeFileSync(masterPath, JSON.stringify(sealed), { mode: 0o600 });
		this.masterKey = master;
		return this.masterKey;
	}

	/** Seal `master` with the passphrase-derived KEK and write master.key. */
	private sealAndWriteMaster(master: Buffer): void {
		const salt = randomBytes(MASTER_SALT_LEN);
		const kek = deriveKek(this.passphrase, salt);
		const { nonce, ciphertext } = gcmSeal(kek, master);
		const sealed: SealedMaster = {
			version: 1,
			kdf: { name: "scrypt", N: SCRYPT_N, r: SCRYPT_R, p: SCRYPT_P, dkLen: SCRYPT_DKLEN },
			salt: b64u(salt),
			nonce,
			ciphertext,
		};
		writeFileSync(join(this.dir, MASTER_FILENAME), JSON.stringify(sealed), { mode: 0o600 });
		this.masterKey = master;
	}

	/**
	 * Export the raw 32-byte master key (unsealed) for the key-escrow ceremony
	 * (Shamir split). The master is created on first run if it does not yet
	 * exist. NEVER write the exported bytes to the credential-service host disk;
	 * the caller splits them into offline shares immediately.
	 */
	public exportMasterKey(): Buffer {
		return this.getMaster();
	}

	/**
	 * Replace the sealed master key with `master` (re-seal + overwrite master.key).
	 * Used by key-escrow RECOVERY: the combined Shamir shares reconstruct the
	 * original master bytes, which are re-sealed so previously-sealed issuer
	 * keys remain unsealable. Clears the in-memory key cache.
	 */
	public replaceMasterKey(master: Buffer): void {
		if (master.length !== KEY_SEED_LEN) {
			throw new Error(`local-sealed: master key must be ${KEY_SEED_LEN} bytes (got ${master.length})`);
		}
		this.sealAndWriteMaster(master);
	}

	private sealSeed(
		master: Buffer,
		seed: Buffer,
		kid: string,
		publicKeyPem: string,
	): void {
		const { nonce, ciphertext } = gcmSeal(master, seed);
		const sealed: SealedKey = {
			version: 1,
			kid,
			publicKeyPem,
			nonce,
			ciphertext,
		};
		writeFileSync(join(this.dir, `${kid}.sealed`), JSON.stringify(sealed), {
			mode: 0o600,
		});
	}

	private unsealSeed(master: Buffer, kid: string): Buffer {
		const sealedPath = join(this.dir, `${kid}.sealed`);
		const sealed = JSON.parse(readFileSync(sealedPath, "utf8")) as SealedKey;
		return gcmUnseal(master, sealed.nonce, sealed.ciphertext);
	}

	private publicKeyPemFor(kid: string): string | null {
		const pubPath = join(this.dir, `${kid}.public.pem`);
		if (!existsSync(pubPath)) return null;
		return readFileSync(pubPath, "utf8");
	}

	/** Reconstruct the PKCS#8 private PEM from a raw seed + the public PEM. */
	private seedToPrivateKeyPem(seed: Buffer, publicKeyPem: string): string {
		const pub = createPublicKey(publicKeyPem);
		const pubJwk = pub.export({ format: "jwk" }) as { x: string };
		const privJwk = {
			kty: "OKP" as const,
			crv: "Ed25519" as const,
			d: b64u(seed),
			x: pubJwk.x,
		};
		const priv = createPrivateKey({ key: privJwk, format: "jwk" });
		return priv.export({ format: "pem", type: "pkcs8" }).toString();
	}

	public getById(kid: string): KeyMaterial | null {
		const publicKeyPem = this.publicKeyPemFor(kid);
		if (!publicKeyPem) return null;
		if (!existsSync(join(this.dir, `${kid}.sealed`))) return null;
		const master = this.getMaster();
		const seed = this.unsealSeed(master, kid);
		const privateKeyPem = this.seedToPrivateKeyPem(seed, publicKeyPem);
		return { privateKeyPem, publicKeyPem, kid };
	}

	public publicById(kid: string): PublicKeyMaterial | null {
		const publicKeyPem = this.publicKeyPemFor(kid);
		if (!publicKeyPem) return null;
		return { publicKeyPem, kid };
	}

	public getCurrent(): KeyMaterial {
		const kid = this.currentKid;
		const existing = this.getById(kid);
		if (existing) return existing;
		// First run for this kid: generate + seal + set current.
		return this.generate(kid, true);
	}

	public ensureKey(kid: string): KeyMaterial {
		const existing = this.getById(kid);
		if (existing) return existing;
		return this.generate(kid, false);
	}

	/** Generate a keypair for `kid`, seal it, write public PEM. When
	 * `makeCurrent` is true, set it as the issuance kid. */
	private generate(kid: string, makeCurrent: boolean): KeyMaterial {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const privateKeyPem = privateKey
			.export({ format: "pem", type: "pkcs8" })
			.toString();
		const publicKeyPem = publicKey
			.export({ format: "pem", type: "spki" })
			.toString();
		const privJwk = privateKey.export({ format: "jwk" }) as { d: string };
		const seed = fromB64u(privJwk.d);
		const master = this.getMaster();
		this.sealSeed(master, seed, kid, publicKeyPem);
		writeFileSync(join(this.dir, `${kid}.public.pem`), publicKeyPem);
		if (makeCurrent) this.setCurrentKid(kid);
		return { privateKeyPem, publicKeyPem, kid };
	}

	public rotate(): KeyMaterial {
		const kid = `mneurix-issuer-${Date.now().toString(36)}`;
		return this.generate(kid, true);
	}
}
