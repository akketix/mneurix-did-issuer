// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Issuer assertion key (M3). File-backed Ed25519 (plaintext PEM, dev).
 *
 * The full KeyProvider interface + LocalSealedKeyProvider + Shamir escrow are
 * PORTED into @mneurix/shared/keys (available); the prod sealed-custody boot
 * wiring lands in M9. M3 uses a single file-backed issuer key, sufficient for
 * did:web minting + the API. Purity: node:crypto + node:fs. */
import { generateKeyPairSync, createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface IssuerKey {
	kid: string;
	publicKeyPem: string;
	privateKeyPem: string;
}

export function loadOrCreateIssuerKey(dir: string | undefined): IssuerKey {
	const k = (() => {
		if (dir) {
			const file = join(dir, "issuer.json");
			if (existsSync(file)) return JSON.parse(readFileSync(file, "utf8")) as IssuerKey;
			const gen = generate();
			mkdirSync(dir, { recursive: true });
			writeFileSync(file, JSON.stringify(gen), { mode: 0o600 });
			return gen;
		}
		return generate();
	})();
	keyStore.set(k.kid, k);
	return k;
}

// --- M6: key rotation + key store -------------------------------------------
// In-memory store of every issuer key the service has held, keyed by `kid`, so
// that VCs signed by a pre-rotation key stay verifiable after rotation (the old
// key material is retained). Durable multi-key persistence is M10.
const keyStore = new Map<string, IssuerKey>();

/** Look up a previously-held issuer key by `kid` (for verifying old VCs). */
export function getKeyByKid(kid: string): IssuerKey | undefined {
	return keyStore.get(kid);
}

/** Rotate the issuer assertion key: mint a new Ed25519 keypair, register both
 * the old and new keys in the store, and return the new key. The DID stays
 * stable (`did:web:<origin>`); only the doc's verificationMethod changes. The
 * caller republishes the rotated DID doc + tombstones the old kid. */
export function rotateIssuerKey(current: IssuerKey): IssuerKey {
	keyStore.set(current.kid, current); // keep old key verifiable
	const next = generate();
	keyStore.set(next.kid, next);
	return next;
}

/** All known issuer kids (boot + rotated). */
export function knownKids(): string[] {
	return [...keyStore.keys()];
}

function generate(): IssuerKey {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }) as string;
	const kid = "issuer-" + createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 12);
	return {
		kid,
		publicKeyPem,
		privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
	};
}
