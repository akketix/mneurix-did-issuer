// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** VC issuance — OB3 Data-Integrity envelope (M5).
 *
 * Ports `expandKey` / `buildOpenBadgeCredential` / `signOb3` / `verifyOb3`
 * verbatim from the lattice's `services/credential/src/ob3.ts` (plan: "reused
 * verbatim"; M0 wholesale-copy precedent). The issuer key + DID are did:web:
 * `issuer.id` and `proof.verificationMethod` point at the did:web issuer key
 * (`did:web:<origin>#<kid>`), closing the lattice TODO at
 * `web/public/research/oauth-options.md:187`.
 *
 * ed25519-jcs-2020 cryptosuite (W3C VC Data Integrity):
 *   verifyData = bytes(JCS(proofOptions)) || bytes(JCS(documentWithoutProof))
 *   proofValue = multibase-base58btc( Ed25519.sign(verifyData, privateKeySeed) )
 *
 * Purity: node:crypto + canonicalize + @noble/ed25519 + multiformats. */
import { createPrivateKey, createPublicKey } from "node:crypto";
import canonicalize from "canonicalize";
import { signAsync, verifyAsync } from "@noble/ed25519";
import { base58btc } from "multiformats/bases/base58";
import type { KeyMaterial } from "@mneurix/shared";
import {
	OpenBadgeCredentialSchema,
	type OpenBadgeCredential,
	type Achievement,
	type BadgeEvidence,
	type IssuerProfile,
} from "@mneurix/shared";

// ---------------------------------------------------------------------------
// Key conversion: PEM -> raw bytes -> Multikey multibase
// ---------------------------------------------------------------------------

function b64urlToBytes(s: string): Uint8Array {
	return new Uint8Array(Buffer.from(s, "base64url"));
}

export interface ExpandedKey {
	seed?: Uint8Array; // 32-byte Ed25519 private seed; absent when keys are public-only
	publicKey: Uint8Array; // 32-byte public key
	publicKeyMultibase: string; // Multikey: base58btc(0xed01 || publicKey)
}

export function expandKey(keys: KeyMaterial): ExpandedKey {
	const pub = createPublicKey(keys.publicKeyPem);
	const pubJwk = pub.export({ format: "jwk" }) as { x: string };
	const publicKey = b64urlToBytes(pubJwk.x);
	const publicKeyMultibase = base58btc.encode(new Uint8Array([0xed, 0x01, ...publicKey]));
	let seed: Uint8Array | undefined;
	if (keys.privateKeyPem && keys.privateKeyPem.length > 0) {
		const priv = createPrivateKey(keys.privateKeyPem);
		const privJwk = priv.export({ format: "jwk" }) as { d: string };
		seed = b64urlToBytes(privJwk.d);
	}
	return { ...(seed ? { seed } : {}), publicKey, publicKeyMultibase };
}

// ---------------------------------------------------------------------------
// Build the unsigned Open Badge 3.0 credential
// ---------------------------------------------------------------------------

export interface BuildOb3Input {
	/** Credential id, e.g. "https://did-issuer.mneurix.example/credentials/<uuid>". */
	id: string;
	issuer: IssuerProfile;
	/** ISO timestamp for validFrom. */
	issuedAt: string;
	/** Learner subject id, e.g. a did:web learner DID. */
	subjectId: string;
	achievement: Achievement;
	evidence: BadgeEvidence;
	/** Optional Bitstring Status List entry (allocated in status.ts). */
	credentialStatus?: OpenBadgeCredential["credentialStatus"];
}

export type UnsignedOpenBadge = Omit<OpenBadgeCredential, "proof">;

export function buildOpenBadgeCredential(input: BuildOb3Input): UnsignedOpenBadge {
	const doc: UnsignedOpenBadge = {
		"@context": [
			"https://www.w3.org/ns/credentials/v2",
			"https://purl.imsglobal.org/spec/ob/v3p0/context.json",
		],
		id: input.id,
		type: ["VerifiableCredential", "OpenBadgeCredential"],
		issuer: input.issuer,
		validFrom: input.issuedAt,
		credentialSubject: {
			id: input.subjectId,
			type: ["AchievementSubject"],
			achievement: input.achievement,
		},
		evidence: [input.evidence],
	};
	if (input.credentialStatus) {
		doc.credentialStatus = input.credentialStatus;
	}
	return doc;
}

// ---------------------------------------------------------------------------
// Sign + verify with ed25519-jcs-2020 Data Integrity proof
// ---------------------------------------------------------------------------

export interface SignOb3Input {
	unsigned: UnsignedOpenBadge;
	keys: KeyMaterial;
	/** verificationMethod URL, e.g. "did:web:<origin>#<kid>". */
	verificationMethod: string;
}

export async function signOb3(input: SignOb3Input): Promise<OpenBadgeCredential> {
	const { unsigned, keys, verificationMethod } = input;
	const { seed } = expandKey(keys);
	if (!seed) {
		throw new Error(
			"signOb3: private key required for signing — public-only key material was provided",
		);
	}

	const proofOptions = {
		type: "DataIntegrityProof",
		cryptosuite: "ed25519-jcs-2020",
		created: new Date().toISOString(),
		verificationMethod,
		proofPurpose: "assertionMethod",
	};

	const canonProof = canonicalize(proofOptions);
	const canonDoc = canonicalize(unsigned);
	if (!canonProof || !canonDoc) {
		throw new Error("JCS canonicalization failed");
	}
	const verifyData = Buffer.concat([
		Buffer.from(canonProof, "utf8"),
		Buffer.from(canonDoc, "utf8"),
	]);

	const sig = await signAsync(verifyData, seed);
	const proofValue = base58btc.encode(sig);

	const credential: OpenBadgeCredential = {
		...unsigned,
		proof: {
			type: "DataIntegrityProof",
			cryptosuite: "ed25519-jcs-2020",
			created: proofOptions.created,
			verificationMethod,
			proofPurpose: "assertionMethod",
			proofValue,
		},
	};
	return OpenBadgeCredentialSchema.parse(credential);
}

export async function verifyOb3(
	credential: OpenBadgeCredential,
	keys: KeyMaterial,
): Promise<boolean> {
	const { proof } = credential;
	if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "ed25519-jcs-2020") {
		return false;
	}
	const { publicKey } = expandKey(keys);

	const { proof: _dropProof, ...docWithoutProof } = credential;
	const proofOptions = {
		type: proof.type,
		cryptosuite: proof.cryptosuite,
		created: proof.created,
		verificationMethod: proof.verificationMethod,
		proofPurpose: proof.proofPurpose,
	};
	const canonProof = canonicalize(proofOptions);
	const canonDoc = canonicalize(docWithoutProof);
	if (!canonProof || !canonDoc) return false;

	const verifyData = Buffer.concat([
		Buffer.from(canonProof, "utf8"),
		Buffer.from(canonDoc, "utf8"),
	]);
	const sig = base58btc.decode(proof.proofValue);
	return verifyAsync(sig, verifyData, publicKey);
}

/** Convenience: build + sign an OB3 credential in one call (used by the
 * `/v1/vcs:issue` data-integrity path). */
export async function issueOb3(
	subjectId: string,
	achievement: Achievement,
	evidence: BadgeEvidence,
	issuer: IssuerProfile,
	keys: KeyMaterial,
	verificationMethod: string,
	credentialId: string,
	credentialStatus?: OpenBadgeCredential["credentialStatus"],
): Promise<OpenBadgeCredential> {
	const unsigned = buildOpenBadgeCredential({
		id: credentialId,
		issuer,
		issuedAt: new Date().toISOString(),
		subjectId,
		achievement,
		evidence,
		...(credentialStatus ? { credentialStatus } : {}),
	});
	return signOb3({ unsigned, keys, verificationMethod });
}

// ---------------------------------------------------------------------------
// Generic ed25519-jcs-2020 Data Integrity sign/verify (M6: revoked-kids tombstone)
// Same algorithm as signOb3/verifyOb3 but schema-agnostic (no OB3 parse), so the
// F15 RevokedIssuerKeys tombstone + future signed docs can reuse it.
// ---------------------------------------------------------------------------

export interface DataIntegrityProof {
	type: "DataIntegrityProof";
	cryptosuite: "ed25519-jcs-2020";
	created: string;
	verificationMethod: string;
	proofPurpose: "assertionMethod";
	proofValue: string;
}

export interface SignedDoc {
	proof: DataIntegrityProof;
}

export async function signDataIntegrity<T extends Record<string, unknown>>(
	doc: T,
	keys: KeyMaterial,
	verificationMethod: string,
): Promise<T & SignedDoc> {
	const { seed } = expandKey(keys);
	if (!seed) throw new Error("signDataIntegrity: private key required for signing");
	const proofOptions: Omit<DataIntegrityProof, "proofValue"> = {
		type: "DataIntegrityProof",
		cryptosuite: "ed25519-jcs-2020",
		created: new Date().toISOString(),
		verificationMethod,
		proofPurpose: "assertionMethod",
	};
	const canonProof = canonicalize(proofOptions);
	const canonDoc = canonicalize(doc);
	if (!canonProof || !canonDoc) throw new Error("JCS canonicalization failed");
	const verifyData = Buffer.concat([Buffer.from(canonProof, "utf8"), Buffer.from(canonDoc, "utf8")]);
	const sig = await signAsync(verifyData, seed);
	return { ...doc, proof: { ...proofOptions, proofValue: base58btc.encode(sig) } };
}

export async function verifyDataIntegrity<T extends SignedDoc>(signed: T, keys: KeyMaterial): Promise<boolean> {
	const { proof } = signed;
	if (proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "ed25519-jcs-2020") return false;
	const { publicKey } = expandKey(keys);
	const { proof: _drop, ...docWithoutProof } = signed as Record<string, unknown>;
	const proofOptions: Omit<DataIntegrityProof, "proofValue"> = {
		type: proof.type,
		cryptosuite: proof.cryptosuite,
		created: proof.created,
		verificationMethod: proof.verificationMethod,
		proofPurpose: proof.proofPurpose,
	};
	const canonProof = canonicalize(proofOptions);
	const canonDoc = canonicalize(docWithoutProof);
	if (!canonProof || !canonDoc) return false;
	const verifyData = Buffer.concat([Buffer.from(canonProof, "utf8"), Buffer.from(canonDoc, "utf8")]);
	const sig = base58btc.decode(proof.proofValue);
	return verifyAsync(sig, verifyData, publicKey);
}