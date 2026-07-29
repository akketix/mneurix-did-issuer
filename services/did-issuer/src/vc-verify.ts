// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Verifier (M6) — POST /v1/presentations:verify for OB3 Data-Integrity VCs,
 * SD-JWT VCs, and SD-JWT+KB (Key Binding JWT per RFC 9901 §7.3).
 *
 * Fail-closed: a VC signed by a revoked issuer kid (F15 tombstone) is rejected;
 * a credential whose status bit is revoked is rejected. The issuer signing key
 * is resolved from the did:web DID document (the verificationMethod publicKeyJwk
 * matching the VC's `kid`), so the verifier trusts the published key, not a
 * private store.
 *
 * Purity: node:crypto + vc-issue + sdjwt + store + revoked-kids + status. */
import { createHash, createPublicKey } from "node:crypto";
import { expandKey, verifyOb3 } from "./vc-issue";
import { verifySdJwtVc } from "./sdjwt";
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
	// Verify the KB-JWT Ed25519 signature with the holder public key (cnf.jwk).
	const publicKeyPem = createPublicKey({ key: holderJwk, format: "jwk" }).export({ format: "pem", type: "spki" }) as string;
	const { publicKey } = expandKey({ privateKeyPem: "", publicKeyPem, kid: "holder" });
	const { verifyAsync } = await import("@noble/ed25519");
	const sig = new Uint8Array(b64urlDecode(s));
	const signingInput = Buffer.from(`${h}.${p}`, "ascii");
	return verifyAsync(sig, signingInput, publicKey);
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
		const sdJwtWithoutKb = `${issuerJwt}~${disclosures.join("~")}${disclosures.length > 0 || kbJwt ? "~" : "~"}`;
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