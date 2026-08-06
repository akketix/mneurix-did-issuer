// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** OpenID for Verifiable Credential Issuance (OID4VCI, draft-ietf-oauth-4-vc)
 * — the pre-authorized-code flow (issuer-initiated): the operator mints a
 * credential offer bound to a subject/vct/claims; a wallet redeems the
 * pre-authorized_code at the token endpoint for an access token, then calls
 * the credential endpoint with the access token to obtain the SD-JWT VC.
 *
 * v1 scope: the pre-authorized-code grant (single-use code + single-use
 * access token, in-memory). The authorization-code grant + DPoP + batch
 * issuance + key/wallet attestations are follow-ups. Purity: node:crypto. */
import { randomBytes } from "node:crypto";

export type SdJwtAlg = "EdDSA" | "ES256";

export interface CredentialOffer {
	preAuthorizedCode: string;
	subject: string;
	vct: string;
	claims: Record<string, unknown>;
	selectivelyDisclosable: string[];
	alg: SdJwtAlg;
	holderJwk?: Record<string, string>;
	createdAt: number;
	consumed: boolean;
}

interface AccessTokenEntry {
	token: string;
	offer: CredentialOffer;
	createdAt: number;
	consumed: boolean;
}

const offers = new Map<string, CredentialOffer>();
/** c_nonce store: token -> { nonce, consumed } (single-use, same TTL as the token). */
const cNonces = new Map<string, { nonce: string; consumed: boolean; createdAt: number; holderJwk?: Record<string, string> }>();
const tokens = new Map<string, AccessTokenEntry>();

const OFFER_TTL_MS = 10 * 60 * 1000; // 10 min
const TOKEN_TTL_MS = 5 * 60 * 1000; // 5 min

function b64url(buf: Buffer): string {
	return buf.toString("base64url");
}
function randomSecret(): string {
	return b64url(randomBytes(32));
}

/** Decode a `did:jwk:` DID into its JWK. The did:jwk method encodes the public key
 * as base64url(JSON.stringify(jwk)) in the DID path (optionally with a `#vm`
 * fragment). Returns null if the DID isn't a did:jwk or the payload isn't a JWK.
 * Used by verifyProofAsync — AltMe/walt.id sign the OID4VCI proof with a did:jwk
 * holder key (no embedded header.jwk / cnf.jwk). */
export function didJwkToJwk(did: string | undefined): Record<string, string> | null {
	if (!did || !did.startsWith("did:jwk:")) return null;
	const b64 = did.slice("did:jwk:".length).split("#")[0]!;
	try {
		const jwk = JSON.parse(Buffer.from(b64, "base64url").toString("utf8")) as Record<string, string>;
		return jwk.kty ? jwk : null;
	} catch {
		return null;
	}
}

export interface CreateOfferInput {
	subject: string;
	vct: string;
	claims: Record<string, unknown>;
	selectivelyDisclosable?: string[];
	alg?: SdJwtAlg;
	holderJwk?: Record<string, string>;
}

export interface CreateOfferResult {
	/** The credential offer (wallet-consumable). The `pre-authorized_code` is
	 * the single-use secret the wallet posts to /oauth/token. */
	credential_offer: {
		credential_issuer: string;
		credential_configuration_ids: string[];
		grants: {
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": { pre_authorized_code: string; user_pin_required: boolean };
		};
	};
	pre_authorized_code: string;
	expires_in: number;
}

/** Operator-facing: mint a pre-authorized credential offer bound to a subject. */
export function createCredentialOffer(issuerUrl: string, input: CreateOfferInput): CreateOfferResult {
	const code = randomSecret();
	const offer: CredentialOffer = {
		preAuthorizedCode: code,
		subject: input.subject,
		vct: input.vct,
		claims: input.claims,
		selectivelyDisclosable: input.selectivelyDisclosable ?? [],
		alg: input.alg ?? "EdDSA",
		...(input.holderJwk ? { holderJwk: input.holderJwk } : {}),
		createdAt: Date.now(),
		consumed: false,
	};
	offers.set(code, offer);
	return {
		credential_offer: {
			credential_issuer: issuerUrl,
			credential_configuration_ids: [input.vct],
			grants: { "urn:ietf:params:oauth:grant-type:pre-authorized_code": { pre_authorized_code: code, user_pin_required: false } },
		},
		pre_authorized_code: code,
		expires_in: Math.floor(OFFER_TTL_MS / 1000),
	};
}

/** Wallet-facing token endpoint: redeem a pre-authorized_code for an access
 * token. Single-use code; fail-closed on unknown/expired/consumed. */
export function exchangePreAuthorizedCode(code: string): { access_token: string; token_type: "bearer"; expires_in: number; c_nonce?: string; c_nonce_expires_in?: number } | { error: string } {
	const offer = offers.get(code);
	if (!offer || offer.consumed) return { error: "invalid_grant" };
	if (Date.now() - offer.createdAt > OFFER_TTL_MS) {
		offers.delete(code);
		return { error: "invalid_grant" };
	}
	const token = randomSecret();
	const cNonce = randomSecret();
	tokens.set(token, { token, offer, createdAt: Date.now(), consumed: false });
	cNonces.set(token, { nonce: cNonce, consumed: false, createdAt: Date.now() });
	offer.consumed = true; // single-use code
	return { access_token: token, token_type: "bearer", expires_in: Math.floor(TOKEN_TTL_MS / 1000), c_nonce: cNonce, c_nonce_expires_in: Math.floor(TOKEN_TTL_MS / 1000) };
}

/** Resolve (peek) an access token for the credential endpoint. */
export function resolveAccessToken(token: string): AccessTokenEntry | null {
	const entry = tokens.get(token);
	if (!entry || entry.consumed) return null;
	if (Date.now() - entry.createdAt > TOKEN_TTL_MS) {
		tokens.delete(token);
		return null;
	}
	return entry;
}

/** Credential endpoint: validate + consume the access token (single-use),
 * returning the bound offer (the credential to issue). */
export function consumeAccessToken(token: string): CredentialOffer | null {
	const entry = resolveAccessToken(token);
	if (!entry) return null;
	entry.consumed = true;
	return entry.offer;
}

/** Verify a wallet proof-of-possession JWT (OID4VCI §4 + Appendix E).
 * The proof is a JWT signed by the wallet's holder key, containing the c_nonce
 * the issuer provided at the token endpoint. The issuer verifies the signature
 * against the holder's public key (from the proof header jwk or the cnf claim)
 * + checks the nonce matches. Returns the holder JWK on success, null on failure. */
export function verifyProof(
	proofJwt: string,
	expectedNonce: string,
): { valid: boolean; holderJwk?: Record<string, string> } {
	try {
		const parts = proofJwt.split(".");
		if (parts.length !== 3) return { valid: false };
		const [h, p] = parts as [string, string, string];
		const header = JSON.parse(Buffer.from(h.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { alg?: string; jwk?: Record<string, string> };
		const payload = JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { nonce?: string; iss?: string; aud?: string; cnf?: { jwk?: Record<string, string> } };
		// Check the nonce matches
		if (payload.nonce !== expectedNonce) return { valid: false };
		// Extract the holder JWK: from the header jwk (jwt proof type) or the payload cnf.jwk
		const holderJwk = header.jwk ?? payload.cnf?.jwk;
		if (!holderJwk || !holderJwk.kty) return { valid: false };
		// Verify the JWT signature against the holder JWK
		const { createPublicKey, verify } = require("node:crypto");
		const pub = createPublicKey({ key: holderJwk, format: "jwk" });
		const signingInput = Buffer.from(h + "." + p, "ascii");
		const sig = Buffer.from(parts[2]!.replace(/-/g, "+").replace(/_/g, "/"), "base64");
		let valid = false;
		if (header.alg === "ES256") {
			valid = verify("SHA256", signingInput, { key: pub, dsaEncoding: "ieee-p1363" }, sig);
		} else if (header.alg === "EdDSA") {
			const { verifyAsync } = require("@noble/ed25519");
			// noble verify is async — but we can't await in a sync function.
			// Return the holder JWK + let the caller verify the signature async.
			// Actually, let's make this function async.
			return { valid: false }; // placeholder — will be replaced by the async version below
		}
		return { valid, holderJwk };
	} catch {
		return { valid: false };
	}
}

/** Async version of verifyProof — handles both ES256 + EdDSA holder keys. */
export async function verifyProofAsync(
	proofJwt: string,
	expectedNonce: string,
): Promise<{ valid: boolean; holderJwk?: Record<string, string>; holderDid?: string }> {
	try {
		const parts = proofJwt.split(".");
		if (parts.length !== 3) return { valid: false };
		const [h, p, sigB64] = parts as [string, string, string];
		const header = JSON.parse(Buffer.from(h.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { alg?: string; jwk?: Record<string, string>; kid?: string };
		const payload = JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { nonce?: string; iss?: string; aud?: string; cnf?: { jwk?: Record<string, string> } };
		if (payload.nonce !== expectedNonce) return { valid: false };
		// Holder key extraction. OID4VCI wallets place the holder public key in one of:
		//   1. header.jwk (classic jwt proof type)
		//   2. payload.cnf.jwk (the CNF claim)
		//   3. a `did:jwk:` DID in header.kid / payload.iss — the did:jwk method encodes
		//      the JWK as base64url(JSON) in the DID itself (AltMe/walt.id do this).
		const holderJwk = header.jwk ?? payload.cnf?.jwk ?? didJwkToJwk(header.kid) ?? didJwkToJwk(payload.iss);
		if (!holderJwk || !holderJwk.kty) return { valid: false };
		// Holder DID: the wallet's holder identifier (the did:jwk from the proof's
		// iss/kid). Used as the credential `sub` so the issued VC's subject is the
		// wallet's holder key (holder binding), not an issuer-invented did:web.
		const holderDid = (typeof payload.iss === "string" && payload.iss.startsWith("did:jwk:")) ? payload.iss : (typeof header.kid === "string" && header.kid.startsWith("did:jwk:") ? header.kid.split("#")[0]! : undefined);
		const { createPublicKey, verify } = await import("node:crypto");
		const signingInput = Buffer.from(h + "." + p, "ascii");
		const sig = Buffer.from(sigB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
		if (header.alg === "ES256") {
			const pub = createPublicKey({ key: holderJwk, format: "jwk" });
			// JOSE ES256 uses raw r||s (ieee-p1363) per RFC 7518. Some wallet libs emit
			// DER-encoded ECDSA signatures — try raw first, then DER as a fallback.
			let valid = verify("SHA256", signingInput, { key: pub, dsaEncoding: "ieee-p1363" }, sig);
			if (!valid) {
				try { valid = verify("SHA256", signingInput, { key: pub }, sig); } catch { /* sig not DER-shaped */ }
			}
			console.log(`verifyProof ES256: sigLen=${sig.length} rawOrDerValid=${valid}`);
			return { valid, holderJwk, ...(holderDid ? { holderDid } : {}) };
		} else if (header.alg === "EdDSA") {
			const { verifyAsync } = await import("@noble/ed25519");
			const pub = createPublicKey({ key: holderJwk, format: "jwk" });
			const pubPem = pub.export({ format: "pem", type: "spki" }) as string;
			// noble needs the raw 32-byte public key — extract from the JWK x
			const pubRaw = Buffer.from(holderJwk.x!, "base64url");
			const valid = await verifyAsync(new Uint8Array(sig), signingInput, new Uint8Array(pubRaw));
			return { valid, holderJwk, ...(holderDid ? { holderDid } : {}) };
		}
		return { valid: false };
	} catch {
		return { valid: false };
	}
}

/** Get the c_nonce for a given access token (or null if expired/consumed). */
export function getCNonceForToken(token: string): string | null {
	const entry = cNonces.get(token);
	if (!entry || entry.consumed) return null;
	if (Date.now() - entry.createdAt > TOKEN_TTL_MS) { cNonces.delete(token); return null; }
	return entry.nonce;
}

/** Consume the c_nonce for a token (single-use — after the proof is verified). */
export function consumeCNonce(token: string): void {
	const entry = cNonces.get(token);
	if (entry) entry.consumed = true;
}

// --- Authorization-code grant (wallet-initiated issuance) --------------------
// The pre-authorized-code flow above is operator-initiated: the operator mints an
// offer bound to a pre-known subject. The authorization-code flow is
// wallet-initiated: the wallet redirects the learner to /oauth/authorize, the
// learner authenticates (delegated to the lattice, or the did-issuer's own
// minimal consent page when the lattice is unconfigured), the did-issuer issues
// an authorization code, the wallet redeems it (+ PKCE verifier) at /oauth/token
// for an access token, then calls /credentials. See oauth.ts for the auth-code
// + PKCE state machine; the helpers below bridge the auth-code flow into the
// shared token/c_nonce store so /credentials stays grant-agnostic.

/** Operator-facing: mint a credential offer that advertises the
 * `authorization_code` grant (no pre-authorized code, no pre-bound subject — the
 * subject is established during the authorization step). The wallet consumes
 * this offer + redirects the learner to the issuer's authorization_endpoint. */
// issuer_state store: correlates a credential offer's authorization_code
// grant issuer_state to the vct being requested, so /oauth/authorize can recover
// the credential config when the wallet sends issuer_state (AltMe/EUDI) instead
// of an explicit credential_config_id query param.
const issuerStateStore = new Map<string, { vct: string; createdAt: number }>();
const ISSUER_STATE_TTL_MS = 10 * 60 * 1000;

/** Look up the vct bound to a credential offer's issuer_state (single-use-ish,
 * TTL-bounded). Returns null if unknown/expired. */
export function lookupIssuerState(issuerState: string): { vct: string } | null {
	const e = issuerStateStore.get(issuerState);
	if (!e) return null;
	if (Date.now() - e.createdAt > ISSUER_STATE_TTL_MS) {
		issuerStateStore.delete(issuerState);
		return null;
	}
	return { vct: e.vct };
}

export function createAuthorizationCodeCredentialOffer(
	issuerUrl: string,
	input: { vct: string },
): { credential_offer: { credential_issuer: string; credential_configuration_ids: string[]; grants: { authorization_code: { issuer_state: string } } }; issuer_state: string; expires_in: number } {
	const issuerState = randomSecret();
	issuerStateStore.set(issuerState, { vct: input.vct, createdAt: Date.now() });
	return {
		credential_offer: {
			credential_issuer: issuerUrl,
			credential_configuration_ids: [input.vct],
			grants: { authorization_code: { issuer_state: issuerState } },
		},
		issuer_state: issuerState,
		expires_in: Math.floor(OFFER_TTL_MS / 1000),
	};
}

/** Credential request resolved from a successful authorization (auth-code
 * flow). Mirrors the fields of a pre-authorized CredentialOffer so the
 * credential endpoint can issue from either grant without branching. */
export interface CredentialRequest {
	subject: string;
	vct: string;
	claims: Record<string, unknown>;
	selectivelyDisclosable: string[];
	alg: SdJwtAlg;
}

/** Mint an access token (+ c_nonce) bound to a credential request resolved from
 * the authorization-code flow. Reuses the shared `tokens` + `cNonces` stores so
 * /credentials (which calls consumeAccessToken / getCNonceForToken) works
 * unchanged. The credential request is wrapped as a synthetic CredentialOffer
 * (preAuthorizedCode is unused — the code was already redeemed for this token).
 * `cNonce` (optional) is the wallet-supplied nonce from the authorize request —
 * when provided it is returned as the c_nonce (the wallet's proof uses it). */
export function mintAccessTokenForCredentialRequest(
	req: CredentialRequest,
	cNonce?: string,
): { access_token: string; token_type: "bearer"; expires_in: number; c_nonce: string; c_nonce_expires_in: number } {
	const token = randomSecret();
	const nonce = cNonce ?? randomSecret();
	const offer: CredentialOffer = {
		preAuthorizedCode: "", // not used in the auth-code path
		subject: req.subject,
		vct: req.vct,
		claims: req.claims,
		selectivelyDisclosable: req.selectivelyDisclosable,
		alg: req.alg,
		createdAt: Date.now(),
		consumed: false,
	};
	tokens.set(token, { token, offer, createdAt: Date.now(), consumed: false });
	cNonces.set(token, { nonce, consumed: false, createdAt: Date.now() });
	return { access_token: token, token_type: "bearer", expires_in: Math.floor(TOKEN_TTL_MS / 1000), c_nonce: nonce, c_nonce_expires_in: Math.floor(TOKEN_TTL_MS / 1000) };
}

export function _resetOid4vciForTests(): void {
	offers.clear();
	tokens.clear();
	cNonces.clear();
	issuerStateStore.clear();
}