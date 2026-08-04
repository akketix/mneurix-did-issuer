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
export function exchangePreAuthorizedCode(code: string): { access_token: string; token_type: "bearer"; expires_in: number; c_nonce?: string } | { error: string } {
	const offer = offers.get(code);
	if (!offer || offer.consumed) return { error: "invalid_grant" };
	if (Date.now() - offer.createdAt > OFFER_TTL_MS) {
		offers.delete(code);
		return { error: "invalid_grant" };
	}
	const token = randomSecret();
	tokens.set(token, { token, offer, createdAt: Date.now(), consumed: false });
	offer.consumed = true; // single-use code
	return { access_token: token, token_type: "bearer", expires_in: Math.floor(TOKEN_TTL_MS / 1000) };
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

export function _resetOid4vciForTests(): void {
	offers.clear();
	tokens.clear();
}