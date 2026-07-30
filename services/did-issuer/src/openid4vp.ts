// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** OpenID for Verifiable Presentations (OpenID4VP, openid-4-verifiable-
 * presentations-1_0) — the verifier side. The did-issuer acts as a verifier:
 * it generates an authorization request (a DCQL query for an SD-JWT VC by vct,
 * an `openid4vp://` URI by value, unsigned v1) + a response_uri the wallet
 * POSTs the vp_token to (the receiver lands in 1.3).
 *
 * v1 scope: unsigned request by value + the direct_post response mode; a
 * single-use session (nonce/state) for the verifier to match the response.
 * Signed requests (JAR), the W3C Digital Credentials API transport, the
 * encrypted response (direct_post.jwt / JWE), + the response receiver +
 * KB-JWT holder binding are follow-ups (1.3-1.6). Purity: node:crypto. */
import { randomBytes, timingSafeEqual } from "node:crypto";

export interface VerifierSession {
	nonce: string;
	state: string;
	vct: string;
	claims: string[];
	clientId: string;
	responseUri: string;
	createdAt: number;
	consumed: boolean;
}

const sessions = new Map<string, VerifierSession>();
const SESSION_TTL_MS = 10 * 60 * 1000;

function b64url(buf: Buffer): string {
	return buf.toString("base64url");
}
function randomSecret(): string {
	return b64url(randomBytes(32));
}
function constTimeEqual(a: string, b: string): boolean {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	if (ab.length !== bb.length) return false;
	return timingSafeEqual(ab, bb);
}

export interface CreateAuthRequestInput {
	/** The credential type to request (the SD-JWT VC vct). */
	vct: string;
	/** Claim paths to request (e.g. ["score", "given_name"]). */
	claims?: string[];
	/** Verifier client id (defaults to the did-issuer HTTPS origin). */
	clientId?: string;
	/** Where the wallet POSTs the vp_token (defaults to <issuer>/openid4vp/response). */
	responseUri?: string;
}

export interface AuthRequestResult {
	/** The `openid4vp://?...` authorization request URI (by value, unsigned). */
	uri: string;
	/** The DCQL query (also embedded in the uri's dcql_query param). */
	dcql_query: { credentials: Array<{ id: string; format: string; meta: { vct_values: string[] }; claims: Array<{ path: string[] }> }> };
	/** The verifier session (nonce/state) for matching the response later. */
	session: { nonce: string; state: string; responseUri: string; vct: string; claims: string[] };
}

/** Verifier-facing: generate an OpenID4VP authorization request for an SD-JWT
 * VC of the given vct. Stores a single-use session keyed by `state`. */
export function createAuthorizationRequest(issuerUrl: string, input: CreateAuthRequestInput): AuthRequestResult {
	const nonce = randomSecret();
	const state = randomSecret();
	const clientId = input.clientId ?? issuerUrl;
	const responseUri = input.responseUri ?? `${issuerUrl}/openid4vp/response`;
	const claims = input.claims ?? [];
	const dcqlQuery: AuthRequestResult["dcql_query"] = {
		credentials: [
			{
				id: "sd_jwt_vc",
				format: "dc+sd-jwt",
				meta: { vct_values: [input.vct] },
				claims: claims.map((c) => ({ path: [c] })),
			},
		],
	};
	const params = new URLSearchParams({
		response_type: "vp_token",
		response_mode: "direct_post",
		client_id: clientId,
		response_uri: responseUri,
		nonce,
		state,
		dcql_query: JSON.stringify(dcqlQuery),
	});
	const uri = `openid4vp://?${params.toString()}`;
	const session: VerifierSession = {
		nonce,
		state,
		vct: input.vct,
		claims,
		clientId,
		responseUri,
		createdAt: Date.now(),
		consumed: false,
	};
	sessions.set(state, session);
	return { uri, dcql_query: dcqlQuery, session: { nonce, state, responseUri, vct: input.vct, claims } };
}

/** Match an incoming wallet response to a verifier session (by state + nonce).
 * Fail-closed on unknown/expired/consumed/nonce-mismatch. (Used by the
 * response receiver, 1.3.) */
export function resolveSession(state: string, nonce: string): VerifierSession | null {
	const s = sessions.get(state);
	if (!s || s.consumed) return null;
	if (Date.now() - s.createdAt > SESSION_TTL_MS) {
		sessions.delete(state);
		return null;
	}
	if (!constTimeEqual(s.nonce, nonce)) return null;
	return s;
}

export function _resetOpenid4vpForTests(): void {
	sessions.clear();
}