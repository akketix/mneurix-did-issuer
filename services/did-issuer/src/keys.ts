// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Issuer assertion keys. File-backed Ed25519 (plaintext PEM, dev) for the
 * did:web / self-sovereign path, + a P-256 (ECDSA) key for the HAIP/EUDI
 * ES256+x5c wallet path (did-issuer-wallet-expansion, hybrid key model).
 *
 * The full KeyProvider interface + LocalSealedKeyProvider + Shamir escrow are
 * PORTED into @mneurix/shared/keys (available); the prod sealed-custody boot
 * wiring lands in M9. Purity: node:crypto + node:fs. */
import { generateKeyPairSync, createSign, createHash, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface IssuerKey {
	kid: string;
	publicKeyPem: string;
	privateKeyPem: string;
}

/** P-256 (ECDSA) issuer key for the ES256+x5c (HAIP/EUDI) wallet path.
 * `jwk` is the public EC JWK (kty EC, crv P-256, base64url x/y) advertised in
 * /.well-known/jwt-vc-issuer; `x5c` is the optional X.509 chain (DER base64,
 * leaf first) per HAIP §6.1.1 — present in prod (IACA), absent in dev. */
export interface IssuerP256Key {
	kid: string;
	publicKeyPem: string;
	privateKeyPem: string;
	jwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
	x5c?: string[];
}

function b64url(buf: Buffer): string {
	return buf.toString("base64url");
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

export function loadOrCreateP256IssuerKey(dir: string | undefined): IssuerP256Key {
	const k = (() => {
		if (dir) {
			const file = join(dir, "issuer-p256.json");
			if (existsSync(file)) return JSON.parse(readFileSync(file, "utf8")) as IssuerP256Key;
			const gen = generateP256();
			mkdirSync(dir, { recursive: true });
			writeFileSync(file, JSON.stringify(gen), { mode: 0o600 });
			return gen;
		}
		return generateP256();
	})();
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

function generateP256(): IssuerP256Key {
	const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	const publicKeyPem = publicKey.export({ format: "pem", type: "spki" }) as string;
	const jwk = createPublicKey(publicKeyPem).export({ format: "jwk" }) as {
		kty: "EC";
		crv: "P-256";
		x: string;
		y: string;
	};
	const kid = "issuer-p256-" + createHash("sha256").update(publicKeyPem).digest("hex").slice(0, 12);
	return {
		kid,
		publicKeyPem,
		privateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }) as string,
		jwk,
	};
}

/** Sign a compact JWT (JWS) with ES256 (ECDSA P-256 + SHA-256, raw r‖s per
 * RFC 7518 / JOSE). `typ` is the JWT type (e.g. "statuslist+jwt"). Used for the
 * HAIP/EUDI wallet path (the status-list token, + future ES256 artifacts). */
export function signEs256Jwt(
	payload: Record<string, unknown>,
	key: IssuerP256Key,
	kid: string,
	typ: string,
	x5c?: string[],
): string {
	const header: Record<string, unknown> = { alg: "ES256", typ, kid, ...(x5c ? { x5c } : {}) };
	const headerB64 = b64url(Buffer.from(JSON.stringify(header)));
	const payloadB64 = b64url(Buffer.from(JSON.stringify(payload)));
	const signingInput = Buffer.from(headerB64 + "." + payloadB64, "ascii");
	const signature = createSign("SHA256")
		.update(signingInput)
		.sign({ key: key.privateKeyPem, dsaEncoding: "ieee-p1363" });
	return headerB64 + "." + payloadB64 + "." + b64url(signature);
}