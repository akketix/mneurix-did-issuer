// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Verifier (M6) — POST /v1/presentations:verify for OB3 Data-Integrity VCs,
 * SD-JWT VCs, and SD-JWT+KB (Key Binding JWT per RFC 9901 §7.3).
 *
 * Fail-closed: a VC signed by a revoked issuer kid (F15 tombstone) is rejected;
 * a credential whose status bit is revoked is rejected. The issuer signing key
 * is resolved from the LOCAL DID store (the verificationMethod publicKeyJwk
 * matching the VC's `kid`) — v1 verifies credentials this issuer published
 * (its own stored DID docs). Cross-issuer did:web fetch resolution (constrained,
 * no SSRF) is tracked as future hardening. The holder cnf.jwk is pinned to
 * Ed25519 (OKP/Ed25519) on KB-JWT verify (no algorithm confusion).
 *
 * Purity: node:crypto + vc-issue + sdjwt + store + revoked-kids + status. */
import { createHash, createPublicKey, verify } from "node:crypto";
import { expandKey, verifyOb3 } from "./vc-issue";
import { verifySdJwtVc, verifySdJwtVcEs256 } from "./sdjwt";
import type { IssuerP256Key } from "./keys";
import { getDid } from "./store";
import { isKidRevoked } from "./revoked-kids";
import { getCredentialStatus } from "./status";
import type { KeyMaterial, OpenBadgeCredential } from "@mneurix/shared";

function b64urlDecode(s: string): Buffer {
	return Buffer.from(s, "base64url");
}

function sha256B64url(input: string): string {
	return Buffer.from(createHash("sha256").update(Buffer.from(input, "ascii")).digest()).toString("base64url");
}

/** Resolve the issuer's public KeyMaterial for `kid` from the did:web DID doc. */
function resolveIssuerKey(issuerDid: string, kid: string): KeyMaterial | null {
	const stored = getDid(issuerDid);
	if (!stored) return null;
	const vm = stored.document.verificationMethod.find((m) => m.id === `${issuerDid}#${kid}`);
	if (!vm) return null;
	const publicKeyPem = createPublicKey({ key: vm.publicKeyJwk, format: "jwk" }).export({ format: "pem", type: "spki" }) as string;
	return { privateKeyPem: "", publicKeyPem, kid };
}

export interface VerifyInput {
	presentation: string | OpenBadgeCredential;
	/** Require a valid Key Binding JWT (SD-JWT+KB). Default false. */
	requireKeyBinding?: boolean;
	/** Expected KB-JWT nonce (replay detection). */
	nonce?: string;
	/** Expected KB-JWT audience. */
	aud?: string;
}

export interface VerifyResult {
	verified: boolean;
	subject?: string;
	issuer?: string;
	status: "valid" | "revoked" | "unavailable" | "stale" | "rejected";
	kid?: string;
	reason?: string;
}

function kidFromVerificationMethod(vm: string): string | null {
	const idx = vm.lastIndexOf("#");
	return idx >= 0 ? vm.slice(idx + 1) : null;
}

/** Verify a Key Binding JWT (RFC 9901 §4.3) against the holder cnf.jwk. */
async function verifyKbJwt(
	kbJwt: string,
	holderJwk: Record<string, string>,
	expectedSdHash: string,
	expectedNonce?: string,
	expectedAud?: string,
): Promise<boolean> {
	const parts = kbJwt.split(".");
	if (parts.length !== 3) return false;
	const [h, p, s] = parts as [string, string, string];
	const header = JSON.parse(b64urlDecode(h).toString("utf8")) as { typ?: string; alg?: string };
	if (header.typ !== "kb+jwt") return false;
	if (header.alg === "none" || !header.alg) return false;
	const payload = JSON.parse(b64urlDecode(p).toString("utf8")) as { nonce?: string; aud?: string; iat?: number; sd_hash?: string };
	if (typeof payload.sd_hash !== "string" || payload.sd_hash !== expectedSdHash) return false;
	if (expectedNonce !== undefined && payload.nonce !== expectedNonce) return false;
	if (expectedAud !== undefined && payload.aud !== expectedAud) return false;
	// Verify the KB-JWT holder signature with the cnf.jwk public key. The holder
	// key is pinned to Ed25519 (OKP/Ed25519, alg EdDSA) or P-256 (EC/P-256, alg
	// ES256) -- fail-closed on any other kty/crv/alg (no algorithm confusion).
	const signingInput = Buffer.from(`${h}.${p}`, "ascii");
	const sig = b64urlDecode(s);
	if (holderJwk.kty === "OKP" && holderJwk.crv === "Ed25519") {
		if (header.alg !== "EdDSA") return false;
		const publicKeyPem = createPublicKey({ key: holderJwk, format: "jwk" }).export({ format: "pem", type: "spki" }) as string;
		const { publicKey } = expandKey({ privateKeyPem: "", publicKeyPem, kid: "holder" });
		const { verifyAsync } = await import("@noble/ed25519");
		return verifyAsync(new Uint8Array(sig), signingInput, publicKey);
	}
	if (holderJwk.kty === "EC" && holderJwk.crv === "P-256") {
		if (header.alg !== "ES256") return false;
		const pub = createPublicKey({ key: holderJwk, format: "jwk" });
		return verify("SHA256", signingInput, { key: pub, dsaEncoding: "ieee-p1363" }, sig);
	}
	return false;
}

export async function verifyPresentation(input: VerifyInput): Promise<VerifyResult> {
	// --- SD-JWT VC / SD-JWT+KB (string) ---
	if (typeof input.presentation === "string") {
		const tildeParts = input.presentation.split("~");
		const issuerJwt = tildeParts[0]!;
		const last = tildeParts[tildeParts.length - 1]!;
		const kbJwt = last && last.includes(".") ? last : null; // last tilde component is a JWT → KB-JWT
		const disclosures = tildeParts.slice(1, kbJwt ? -1 : -1); // drop trailing empty / KB-JWT
		const jwtParts = issuerJwt.split(".");
		if (jwtParts.length !== 3) return { verified: false, status: "rejected", reason: "malformed issuer JWT" };
		const header = JSON.parse(b64urlDecode(jwtParts[0]!).toString("utf8")) as { kid?: string; typ?: string };
		const payload = JSON.parse(b64urlDecode(jwtParts[1]!).toString("utf8")) as { iss?: string; sub?: string; cnf?: { jwk?: Record<string, string> } };
		const rawKid = header.kid;
		const issuerDid = payload.iss;
		if (!rawKid || !issuerDid) return { verified: false, status: "rejected", reason: "missing kid/iss" };
		// `kid` may be the bare kid OR the full did:web#kid verificationMethod — accept both.
		const kid = rawKid.includes("#") ? rawKid.slice(rawKid.lastIndexOf("#") + 1) : rawKid;

		const issuerKey = resolveIssuerKey(issuerDid, kid);
		if (!issuerKey) return { verified: false, status: "unavailable", kid, issuer: issuerDid, reason: "issuer key not resolvable" };

		// Fail-closed: revoked signing key.
		if (await isKidRevoked(kid)) return { verified: false, status: "revoked", kid, issuer: issuerDid, reason: "signing key revoked" };

		// Verify the issuer signature over the full credential (no KB).
		const sdJwtWithoutKb = `${issuerJwt}~${disclosures.join("~")}${disclosures.length > 0 ? "~" : ""}`;
		const fullForSig = kbJwt ? sdJwtWithoutKb : input.presentation;
		const result = await verifySdJwtVc(fullForSig, issuerKey);
		if (!result.signatureValid) return { verified: false, status: "rejected", kid, issuer: issuerDid, reason: "issuer signature invalid" };

		// RFC 9901 §7.1 step 5: reject if any disclosure is not referenced by _sd.
		if (!result.allDisclosuresReferenced) return { verified: false, status: "rejected", kid, issuer: issuerDid, ...(payload.sub ? { subject: payload.sub } : {}), reason: "unreferenced disclosure (RFC 9901 §7.1)" };

		// Key binding (RFC 9901 §7.3).
		if (input.requireKeyBinding && !kbJwt) {
			return { verified: false, status: "rejected", kid, issuer: issuerDid, ...(payload.sub ? { subject: payload.sub } : {}), reason: "key binding required but absent" };
		}
		if (kbJwt) {
			const holderJwk = payload.cnf?.jwk;
			if (!holderJwk) return { verified: false, status: "rejected", kid, issuer: issuerDid, reason: "KB-JWT present without cnf.jwk" };
			// Pin the holder key to Ed25519 (no algorithm confusion: an attacker
			// cannot substitute an RSA/EC cnf.jwk).
			const okHolderKey = (holderJwk.kty === "OKP" && holderJwk.crv === "Ed25519") || (holderJwk.kty === "EC" && holderJwk.crv === "P-256");
			if (!okHolderKey)
				return { verified: false, status: "rejected", kid, issuer: issuerDid, reason: "cnf.jwk must be Ed25519 (OKP) or P-256 (EC)" };
			const expectedSdHash = sha256B64url(sdJwtWithoutKb);
			const kbOk = await verifyKbJwt(kbJwt, holderJwk, expectedSdHash, input.nonce, input.aud);
			if (!kbOk) return { verified: false, status: "rejected", kid, issuer: issuerDid, ...(payload.sub ? { subject: payload.sub } : {}), reason: "KB-JWT invalid" };
		}

		return { verified: true, status: "valid", kid, issuer: issuerDid, ...(payload.sub ? { subject: payload.sub } : {}) };
	}

	// --- OB3 Data-Integrity (object) ---
	const credential = input.presentation;
	const kid = kidFromVerificationMethod(credential.proof.verificationMethod);
	const issuerDid = credential.issuer.id;
	if (!kid) return { verified: false, status: "rejected", reason: "missing kid in verificationMethod" };

	const issuerKey = resolveIssuerKey(issuerDid, kid);
	if (!issuerKey) return { verified: false, status: "unavailable", kid, issuer: issuerDid, reason: "issuer key not resolvable" };

	if (await isKidRevoked(kid)) return { verified: false, status: "revoked", kid, issuer: issuerDid, reason: "signing key revoked" };

	const sigOk = await verifyOb3(credential, issuerKey);
	if (!sigOk) return { verified: false, status: "rejected", kid, issuer: issuerDid, reason: "Data-Integrity proof invalid" };

	// Fail-closed status check.
	let status: VerifyResult["status"] = "valid";
	if (credential.credentialStatus) {
		const st = getCredentialStatus(credential.id);
		if (st.state === "revoked") return { verified: false, status: "revoked", kid, issuer: issuerDid, subject: credential.credentialSubject.id, reason: "credential revoked" };
		status = st.state;
	}

	return { verified: true, status, kid, issuer: issuerDid, subject: credential.credentialSubject.id };
}

/** Verify an ES256 (P-256) SD-JWT VC presentation presented to the did-issuer's
 * own OpenID4VP receiver -- the HAIP/EUDI wallet-path mirror of the EdDSA/did:web
 * SD-JWT branch in verifyPresentation. The issuer key is the in-process P-256 key
 * (the did-issuer verifying its own ES256 credentials, iss = HTTPS issuer).
 * KB-JWT holder binding pins Ed25519 (OKP/Ed25519) cnf.jwk, same as the EdDSA path. */
export async function verifyEs256Presentation(
	presentation: string,
	p256Key: IssuerP256Key,
	opts: { requireKeyBinding?: boolean; nonce?: string; aud?: string },
): Promise<VerifyResult> {
	const tildeParts = presentation.split("~");
	const issuerJwt = tildeParts[0]!;
	const last = tildeParts[tildeParts.length - 1]!;
	const kbJwt = last && last.includes(".") ? last : null;
	const disclosures = tildeParts.slice(1, kbJwt ? -1 : -1);
	const jwtParts = issuerJwt.split(".");
	if (jwtParts.length !== 3) return { verified: false, status: "rejected", reason: "malformed issuer JWT" };
	const header = JSON.parse(b64urlDecode(jwtParts[0]!).toString("utf8")) as { alg?: string; kid?: string };
	if (header.alg !== "ES256") return { verified: false, status: "rejected", reason: "not an ES256 SD-JWT VC" };
	const payload = JSON.parse(b64urlDecode(jwtParts[1]!).toString("utf8")) as { iss?: string; sub?: string; cnf?: { jwk?: Record<string, string> } };
	const sdJwtWithoutKb = `${issuerJwt}~${disclosures.join("~")}${disclosures.length > 0 ? "~" : ""}`;
	const result = await verifySdJwtVcEs256(kbJwt ? sdJwtWithoutKb : presentation, p256Key);
	if (!result.signatureValid) return { verified: false, status: "rejected", ...(payload.iss ? { issuer: payload.iss } : {}), ...(payload.sub ? { subject: payload.sub } : {}), reason: "issuer signature invalid" };
	if (!result.allDisclosuresReferenced) return { verified: false, status: "rejected", ...(payload.iss ? { issuer: payload.iss } : {}), ...(payload.sub ? { subject: payload.sub } : {}), reason: "unreferenced disclosure (RFC 9901 §7.1)" };
	if (opts.requireKeyBinding && !kbJwt) return { verified: false, status: "rejected", ...(payload.iss ? { issuer: payload.iss } : {}), ...(payload.sub ? { subject: payload.sub } : {}), reason: "key binding required but absent" };
	if (kbJwt) {
		const holderJwk = payload.cnf?.jwk;
		if (!holderJwk) return { verified: false, status: "rejected", ...(payload.iss ? { issuer: payload.iss } : {}), reason: "KB-JWT present without cnf.jwk" };
		const okHolderKey = (holderJwk.kty === "OKP" && holderJwk.crv === "Ed25519") || (holderJwk.kty === "EC" && holderJwk.crv === "P-256");
		if (!okHolderKey) return { verified: false, status: "rejected", ...(payload.iss ? { issuer: payload.iss } : {}), reason: "cnf.jwk must be Ed25519 (OKP) or P-256 (EC)" };
		const expectedSdHash = sha256B64url(sdJwtWithoutKb);
		const kbOk = await verifyKbJwt(kbJwt, holderJwk, expectedSdHash, opts.nonce, opts.aud);
		if (!kbOk) return { verified: false, status: "rejected", ...(payload.iss ? { issuer: payload.iss } : {}), ...(payload.sub ? { subject: payload.sub } : {}), reason: "KB-JWT invalid" };
	}
	return { verified: true, status: "valid", ...(payload.iss ? { issuer: payload.iss } : {}), ...(payload.sub ? { subject: payload.sub } : {}) };
}
