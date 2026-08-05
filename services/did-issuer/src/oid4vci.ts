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
): Promise<{ valid: boolean; holderJwk?: Record<string, string> }> {
	try {
		const parts = proofJwt.split(".");
		if (parts.length !== 3) return { valid: false };
		const [h, p, sigB64] = parts as [string, string, string];
		const header = JSON.parse(Buffer.from(h.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { alg?: string; jwk?: Record<string, string> };
		const payload = JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { nonce?: string; iss?: string; aud?: string; cnf?: { jwk?: Record<string, string> } };
		if (payload.nonce !== expectedNonce) return { valid: false };
		const holderJwk = header.jwk ?? payload.cnf?.jwk;
		if (!holderJwk || !holderJwk.kty) return { valid: false };
		const { createPublicKey, verify } = await import("node:crypto");
		const signingInput = Buffer.from(h + "." + p, "ascii");
		const sig = Buffer.from(sigB64.replace(/-/g, "+").replace(/_/g, "/"), "base64");
		if (header.alg === "ES256") {
			const pub = createPublicKey({ key: holderJwk, format: "jwk" });
			const valid = verify("SHA256", signingInput, { key: pub, dsaEncoding: "ieee-p1363" }, sig);
			return { valid, holderJwk };
		} else if (header.alg === "EdDSA") {
			const { verifyAsync } = await import("@noble/ed25519");
			const pub = createPublicKey({ key: holderJwk, format: "jwk" });
			const pubPem = pub.export({ format: "pem", type: "spki" }) as string;
			// noble needs the raw 32-byte public key — extract from the JWK x
			const pubRaw = Buffer.from(holderJwk.x!, "base64url");
			const valid = await verifyAsync(new Uint8Array(sig), signingInput, new Uint8Array(pubRaw));
			return { valid, holderJwk };
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
export function createAuthorizationCodeCredentialOffer(
	issuerUrl: string,
	input: { vct: string },
): { credential_offer: { credential_issuer: string; credential_configuration_ids: string[]; grants: { authorization_code: { issuer_state: string } } }; issuer_state: string; expires_in: number } {
	const issuerState = randomSecret();
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
 * (preAuthorizedCode is unused — the code was already redeemed for this token). */
export function mintAccessTokenForCredentialRequest(
	req: CredentialRequest,
): { access_token: string; token_type: "bearer"; expires_in: number; c_nonce: string; c_nonce_expires_in: number } {
	const token = randomSecret();
	const cNonce = randomSecret();
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
	cNonces.set(token, { nonce: cNonce, consumed: false, createdAt: Date.now() });
	return { access_token: token, token_type: "bearer", expires_in: Math.floor(TOKEN_TTL_MS / 1000), c_nonce: cNonce, c_nonce_expires_in: Math.floor(TOKEN_TTL_MS / 1000) };
}

export function _resetOid4vciForTests(): void {
	offers.clear();
	tokens.clear();
	cNonces.clear();
}