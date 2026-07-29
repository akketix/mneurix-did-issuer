// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** SD-JWT VC issuer — RFC 9901 + draft-ietf-oauth-sd-jwt-vc (M5).
 *
 * Ed25519-only (locked decision 2026-07-23): the Issuer-signed JWT uses
 * alg "EdDSA"; the holder key (cnf.jwk) is whatever the caller supplies.
 *
 * Serialization (RFC 9901 §4, verified against the spec — not from memory):
 *   SD-JWT = <Issuer-JWT>~<D.1>~<D.2>~...~<D.N>~
 * (each disclosure followed by a tilde; trailing tilde when no KB-JWT, which
 * is the issuance form — KB-JWT is the M6 verify-side holder proof).
 *
 * Disclosure (object property, §4.2.1): base64url(JSON[salt, claimName, value]).
 * Digest (§4.2.3): base64url(sha256(US-ASCII(disclosure))).
 * Payload: plaintext claims + `_sd` (sorted digest array) + `_sd_alg:"sha-256"`.
 * typ: "dc+sd-jwt" emitted (accept "vc+sd-jwt" on verify per the transition note).
 *
 * v1 supports flat top-level `_sd` selective disclosure (the plan's
 * selectively-disclosable claims — score/agreement/identityAssurance).
 * Recursive + array-element disclosures are a future hardening (RFC 9901 §4.2.6).
 *
 * Purity: node:crypto + @noble/ed25519. */
import { createHash, randomBytes } from "node:crypto";
import { signAsync, verifyAsync } from "@noble/ed25519";
import { expandKey } from "./vc-issue";
import type { KeyMaterial } from "@mneurix/shared";

export type HolderJwk = Record<string, string>;

export interface SdJwtIssueInput {
	/** Issuer identifier — the did:web issuer DID or HTTPS origin. */
	iss: string;
	/** Learner subject DID (did:web). */
	sub: string;
	/** Credential type URI (collision-resistant, e.g. a vct). */
	vct: string;
	/** Plaintext claims (always visible). Keys in `selectivelyDisclosable` are
	 * removed from here and moved into Disclosures + `_sd`. */
	claims: Record<string, unknown>;
	/** Claim names to make selectively disclosable (must exist in `claims`). */
	selectivelyDisclosable: string[];
	/** Holder binding key (cnf.jwk); required to enable key binding (M6). */
	holderJwk?: HolderJwk;
	/** Token Status List reference (status claim), if allocated. */
	status?: { id: string; type: string; statusPurpose: string; statusListIndex: number };
	/** Issuer verification method (kid header), e.g. did:web:<origin>#<kid>. */
	verificationMethod: string;
	/** Issued-at (seconds). Defaults to now. */
	iat?: number;
}

export interface SdJwtIssueResult {
	/** `dc+sd-jwt` credential string. */
	credential: string;
	/** The Issuer-signed JWT (header.payload.signature). */
	issuerJwt: string;
	/** Disclosure strings (base64url), in issuance order. */
	disclosures: string[];
	/** SHA-256 over the published (origin-embedded) SD-JWT — for KB-JWT sd_hash (M6). */
	sdHash: string;
}

// --- base64url helpers (no padding, RFC 7515 §2) ---

function b64url(bytes: Uint8Array | Buffer | string): string {
	const buf = typeof bytes === "string" ? Buffer.from(bytes, "utf8") : Buffer.from(bytes);
	return buf.toString("base64url");
}

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s, "base64url");
}

function sha256B64url(input: string | Uint8Array): string {
	const buf = typeof input === "string" ? Buffer.from(input, "utf8") : Buffer.from(input);
	return b64url(createHash("sha256").update(buf).digest());
}

function randomSalt(): string {
	return b64url(randomBytes(16)); // 128-bit salt (RFC 9901 §9.3 recommended minimum)
}

// --- Disclosure + digest (RFC 9901 §4.2) ---

function makeDisclosure(salt: string, claimName: string, value: unknown): string {
	return b64url(JSON.stringify([salt, claimName, value]));
}

function disclosureHash(disclosure: string): string {
	// §4.2.3: digest over the US-ASCII bytes of the base64url-encoded Disclosure.
	return sha256B64url(Buffer.from(disclosure, "ascii"));
}

// --- Issuance ---

export async function issueSdJwtVc(input: SdJwtIssueInput, keys: KeyMaterial): Promise<SdJwtIssueResult> {
	const { seed } = expandKey(keys);
	if (!seed) throw new Error("issueSdJwtVc: private key required for signing");

	const iat = input.iat ?? Math.floor(Date.now() / 1000);
	const sdSet = new Set(input.selectivelyDisclosable);

	// Build disclosures for the selectively-disclosable claims.
	const disclosures: string[] = [];
	const sdHashes: string[] = [];
	for (const name of input.selectivelyDisclosable) {
		if (!(name in input.claims)) {
			throw new Error(`issueSdJwtVc: selectivelyDisclosable claim "${name}" not present in claims`);
		}
		const salt = randomSalt();
		const value = input.claims[name];
		const disclosure = makeDisclosure(salt, name, value);
		disclosures.push(disclosure);
		sdHashes.push(disclosureHash(disclosure));
	}
	sdHashes.sort(); // RFC 9901 §4.2.4.1: hide original order (alphanumeric sort).

	// Plaintext (always-disclosed) payload claims.
	const payload: Record<string, unknown> = {
		iss: input.iss,
		iat,
		sub: input.sub,
		vct: input.vct,
		_sd_alg: "sha-256",
	};
	for (const [k, v] of Object.entries(input.claims)) {
		if (!sdSet.has(k)) payload[k] = v;
	}
	if (sdHashes.length > 0) payload._sd = sdHashes;
	if (input.holderJwk) payload.cnf = { jwk: input.holderJwk };
	if (input.status) payload.status = input.status;

	const headerKid = input.verificationMethod.includes("#") ? input.verificationMethod.slice(input.verificationMethod.lastIndexOf("#") + 1) : input.verificationMethod;
	const header = { alg: "EdDSA", typ: "dc+sd-jwt", kid: headerKid };
	const headerB64 = b64url(JSON.stringify(header));
	const payloadB64 = b64url(JSON.stringify(payload));
	const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
	const signature = await signAsync(signingInput, seed);
	const issuerJwt = `${headerB64}.${payloadB64}.${b64url(signature)}`;

	// RFC 9901 §4: <Issuer-JWT>~<D.1>~...~<D.N>~ (trailing tilde, no KB-JWT at issuance).
	const credential = `${issuerJwt}~${disclosures.join("~")}${disclosures.length > 0 ? "~" : "~"}`;
	const sdHash = sha256B64url(credential);
	return { credential, issuerJwt, disclosures, sdHash };
}

// --- Verification (issuer-signature check + disclosure processing) ---

export interface SdJwtVerifyResult {
	/** True iff the Ed25519 signature over the Issuer-signed JWT is valid. */
	signatureValid: boolean;
	/** The parsed JWT header. */
	header: Record<string, unknown> | null;
	/** The processed payload: plaintext claims + disclosed claims applied. */
	processedPayload: Record<string, unknown> | null;
	/** The disclosures parsed back to [salt, name, value] arrays. */
	disclosures: Array<[string, string, unknown]>;
	/** Whether every supplied disclosure was referenced by `_sd` (integrity). */
	allDisclosuresReferenced: boolean;
}

export async function verifySdJwtVc(credential: string, keys: KeyMaterial): Promise<SdJwtVerifyResult> {
	const { publicKey } = expandKey(keys);
	// SD-JWT = <Issuer-JWT>~<D.1>~...~<D.N>~  → split on "~".
	const parts = credential.split("~");
	const issuerJwt = parts[0]!;
	const disclosureStrings = parts.slice(1, -1); // drop the trailing empty element

	const jwtParts = issuerJwt.split(".");
	if (jwtParts.length !== 3) {
		return { signatureValid: false, header: null, processedPayload: null, disclosures: [], allDisclosuresReferenced: false };
	}
	const [headerB64, payloadB64, sigB64] = jwtParts as [string, string, string];
	const header = JSON.parse(b64urlDecode(headerB64).toString("utf8")) as Record<string, unknown>;
	const payload = JSON.parse(b64urlDecode(payloadB64).toString("utf8")) as Record<string, unknown>;
	const signature = new Uint8Array(b64urlDecode(sigB64));

	const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "ascii");
	const signatureValid = await verifyAsync(signature, signingInput, publicKey);

	// Process disclosures: compute hash, match against _sd, insert claim.
	const sdArray = Array.isArray(payload._sd) ? (payload._sd as string[]) : [];
	const sdSet = new Set(sdArray);
	const disclosures: Array<[string, string, unknown]> = [];
	const processed: Record<string, unknown> = { ...payload };
	let allReferenced = true;
	for (const d of disclosureStrings) {
		const parsed = JSON.parse(b64urlDecode(d).toString("utf8")) as [string, string, unknown];
		disclosures.push(parsed);
		const hash = disclosureHash(d);
		if (sdSet.has(hash)) {
			// §4.2.4.1 object-property disclosure: [salt, claimName, value]
			const [, claimName, value] = parsed;
			processed[claimName] = value;
		} else {
			allReferenced = false;
		}
	}
	delete processed._sd;
	delete processed._sd_alg;

	return { signatureValid, header, processedPayload: processed, disclosures, allDisclosuresReferenced: allReferenced };
}