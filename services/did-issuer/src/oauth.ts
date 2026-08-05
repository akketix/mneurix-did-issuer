// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** OID4VCI authorization-code grant state machine (wallet-initiated issuance).
 *
 * The wallet redirects the learner to the issuer's authorization endpoint
 * (/oauth/authorize) with a PKCE code_challenge + the credential configuration
 * it wants. The learner authenticates — v1 DELEGATES this to the lattice's
 * existing auth when MNEURIX_LATTICE_AUTH_URL is set, otherwise the did-issuer
 * shows its own minimal consent page (the independently-deployable fallback; the
 * lattice wiring degrades gracefully when unconfigured, per the architecture
 * principle). On consent, the did-issuer issues a single-use authorization code
 * bound to (PKCE challenge + the authenticated subject + the credential request
 * + the wallet's redirect_uri + state) and redirects the browser back to the
 * wallet's redirect_uri with the code. The wallet redeems the code + its PKCE
 * verifier at /oauth/token for an access token, then calls /credentials.
 *
 * This module owns ONLY the auth-code + PKCE state machine. The access-token +
 * c_nonce minting reuses oid4vci.ts's shared store (mintAccessTokenForCredentialRequest)
 * so /credentials stays grant-agnostic. Purity: node:crypto. */
import { createHash, randomBytes } from "node:crypto";
import type { CredentialRequest, SdJwtAlg } from "./oid4vci";

/** A pending authorization request — created at /oauth/authorize, carried
 * through the consent/delegation step, and redeemed into an auth code. The
 * `state` is the wallet-supplied opaque value echoed back to the wallet. */
export interface AuthorizationRequestInput {
	credentialConfigurationId: string;
	vct: string; // the credential_configuration_id with any #dc-sd-jwt suffix stripped
	redirectUri: string;
	state: string;
	codeChallenge: string;
	codeChallengeMethod: "S256";
	/** issuer_state from the credential offer (optional correlation). */
	issuerState?: string;
}
interface AuthorizationRequest extends AuthorizationRequestInput {
	createdAt: number;
}

/** An issued authorization code — single-use, PKCE-bound. */
interface AuthorizationCodeEntry extends AuthorizationRequest {
	code: string;
	subject: string; // the authenticated learner (did:web-style identifier)
	claims: Record<string, unknown>;
	selectivelyDisclosable: string[];
	alg: SdJwtAlg;
	consumed: boolean;
}

const pendingRequests = new Map<string, AuthorizationRequest>(); // keyed by pendingState
const authCodes = new Map<string, AuthorizationCodeEntry>(); // keyed by code

const PENDING_TTL_MS = 10 * 60 * 1000; // 10 min for the authorize -> consent -> code leg
const CODE_TTL_MS = 5 * 60 * 1000; // 5 min for the code -> token leg

function b64url(buf: Buffer): string {
	return buf.toString("base64url");
}
function randomSecret(): string {
	return b64url(randomBytes(32));
}

/** Verify a PKCE S256 code_verifier against the stored code_challenge.
 * `code_challenge = base64url(sha256(code_verifier))` (RFC 7636 §4.2). */
export function verifyPkce(codeVerifier: string, codeChallenge: string): boolean {
	const computed = b64url(createHash("sha256").update(codeVerifier, "ascii").digest());
	return computed === codeChallenge;
}

/** Store a pending authorization request under `pendingState` (the did-issuer's
 * own state for the authorize -> callback leg, distinct from the wallet's
 * `state`). Used by the delegated path: /oauth/authorize stores the request +
 * redirects to the lattice; the lattice callback looks it up by pendingState. */
export function storePendingAuthRequest(pendingState: string, req: AuthorizationRequestInput): void {
	pendingRequests.set(pendingState, { ...req, createdAt: Date.now() });
}

export function takePendingAuthRequest(pendingState: string): AuthorizationRequest | null {
	const entry = pendingRequests.get(pendingState);
	if (!entry) return null;
	if (Date.now() - entry.createdAt > PENDING_TTL_MS) {
		pendingRequests.delete(pendingState);
		return null;
	}
	pendingRequests.delete(pendingState); // single-use
	return entry;
}

export interface IssueAuthCodeInput extends AuthorizationRequestInput {
	subject: string;
	claims: Record<string, unknown>;
	selectivelyDisclosable?: string[];
	alg?: SdJwtAlg;
}

/** Issue a single-use authorization code bound to the authenticated subject +
 * the credential request + PKCE. The code is returned to /oauth/consent (or the
 * delegated callback) which 302-redirects the browser to the wallet's
 * redirect_uri with `?code=...&state=...`. */
export function issueAuthorizationCode(input: IssueAuthCodeInput): { code: string; state: string; redirectUri: string } {
	const code = randomSecret();
	authCodes.set(code, {
		...input,
		createdAt: Date.now(),
		code,
		selectivelyDisclosable: input.selectivelyDisclosable ?? [],
		alg: input.alg ?? "EdDSA",
		consumed: false,
	});
	return { code, state: input.state, redirectUri: input.redirectUri };
}

/** Redeem an authorization code + PKCE verifier. Validates the code is
 * single-use + unexpired + the PKCE verifier matches the stored challenge.
 * On success returns the credential request (subject/vct/claims/alg) for
 * mintAccessTokenForCredentialRequest; on failure returns an error code. */
export function exchangeAuthorizationCode(
	code: string,
	codeVerifier: string,
): { ok: true; request: CredentialRequest } | { ok: false; error: "invalid_grant" | "invalid_pkce" } {
	const entry = authCodes.get(code);
	if (!entry || entry.consumed) return { ok: false, error: "invalid_grant" };
	if (Date.now() - entry.createdAt > CODE_TTL_MS) {
		authCodes.delete(code);
		return { ok: false, error: "invalid_grant" };
	}
	if (!verifyPkce(codeVerifier, entry.codeChallenge)) {
		// Do not consume the code on a PKCE mismatch — but RFC 7636 recommends
		// rejecting the code entirely. We consume it to defeat PKCE brute-force.
		entry.consumed = true;
		return { ok: false, error: "invalid_pkce" };
	}
	entry.consumed = true; // single-use
	return {
		ok: true,
		request: {
			subject: entry.subject,
			vct: entry.vct,
			claims: entry.claims,
			selectivelyDisclosable: entry.selectivelyDisclosable,
			alg: entry.alg,
		},
	};
}

/** The minimal self-hosted consent page (HTML). Shown at /oauth/authorize when
 * MNEURIX_LATTICE_AUTH_URL is unset. The learner confirms their identity + the
 * credential being requested, then POSTs to /oauth/consent. v1 is a plain form
 * (no did-issuer-side user auth — the did-issuer stays auth-delegated, not
 * auth-hosting; this page is the fallback when the lattice is unconfigured). */
export function consentPageHtml(opts: {
	credentialConfigurationId: string;
	redirectUri: string;
	state: string;
	codeChallenge: string;
	issuerState?: string;
	issuerName: string;
	defaultLearnerId?: string;
}): string {
	const esc = (s: string): string =>
		s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
	const fields = `
      <input type="hidden" name="credential_configuration_id" value="${esc(opts.credentialConfigurationId)}">
      <input type="hidden" name="redirect_uri" value="${esc(opts.redirectUri)}">
      <input type="hidden" name="state" value="${esc(opts.state)}">
      <input type="hidden" name="code_challenge" value="${esc(opts.codeChallenge)}">
      <input type="hidden" name="code_challenge_method" value="S256">
      ${opts.issuerState ? `<input type="hidden" name="issuer_state" value="${esc(opts.issuerState)}">` : ""}`;
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(opts.issuerName)} — authorize credential</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:480px;margin:40px auto;padding:0 16px;color:#0f172a;background:#f8fafc}
  h1{font-size:18px;margin:0 0 8px}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:20px}
  label{display:block;font-weight:600;margin:14px 0 4px}
  input[type=text]{width:100%;padding:9px 10px;border:1px solid #cbd5e1;border-radius:6px;box-sizing:border-box;font:inherit}
  button{margin-top:20px;width:100%;padding:11px;background:#0ea5e9;color:#fff;border:0;border-radius:7px;font:inherit;font-weight:600;cursor:pointer}
  button:hover{background:#0284c7}
  .muted{color:#64748b;font-size:13px}
  .req{background:#f1f5f9;border-radius:6px;padding:10px;font-size:13px;word-break:break-all}
</style>
</head>
<body>
  <div class="card">
    <h1>${esc(opts.issuerName)}</h1>
    <p class="muted">A wallet is requesting a verifiable credential. Confirm your identity to issue it.</p>
    <label for="learnerId">Your learner ID</label>
    <input id="learnerId" name="learnerId" type="text" value="${esc(opts.defaultLearnerId ?? "")}" placeholder="learner-123" required>
    <label>Requested credential</label>
    <div class="req">${esc(opts.credentialConfigurationId)}</div>
    <form method="POST" action="/oauth/consent" autocomplete="off">${fields}
      <button type="submit">Approve &amp; issue</button>
    </form>
    <p class="muted" style="margin-top:16px">By approving, ${esc(opts.issuerName)} issues a verifiable credential to the wallet that initiated this request. The credential is bound to your holder key (the wallet proves possession); it is not stored by the issuer.</p>
  </div>
</body>
</html>`;
}

export function _resetOauthForTests(): void {
	pendingRequests.clear();
	authCodes.clear();
}