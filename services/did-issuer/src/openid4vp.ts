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
import { randomBytes, timingSafeEqual, generateKeyPairSync, createHash } from "node:crypto";
import { signEs256Jwt, type IssuerP256Key } from "./keys";

export interface VerifierSession {
	nonce: string;
	state: string;
	vct: string;
	claims: string[];
	clientId: string;
	responseUri: string;
	/** Per-request ephemeral ECDH-ES recipient private key (encrypted responses). */
	recipientPrivateKeyPem?: string;
	createdAt: number;
	consumed: boolean;
}

const sessions = new Map<string, VerifierSession>();
/** Signed request objects (JAR) keyed by state, served at /openid4vp/request/:id. */
const requestObjects = new Map<string, string>();
export function getRequestObject(id: string): string | undefined {
	return requestObjects.get(id);
}
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
	/** Request an encrypted direct_post.jwt response (JWE ECDH-ES + A128GCM); the
	 * verifier advertises a per-request ephemeral recipient public key. */
	encrypted?: boolean;
	/** Delivery transport: "openid4vp" (the openid4vp:// URI, default) or "dc_api"
	 * (the W3C Digital Credentials API — the request is a JSON object for
	 * navigator.credentials.get; the frontend relays the response to response_uri). */
	transport?: "openid4vp" | "dc_api" | "openid4vp-redirect";
}

export interface AuthRequestResult {
	/** The `openid4vp://?...` authorization request URI (by value, unsigned). */
	uri: string;
	/** The DCQL query (also embedded in the uri's dcql_query param). */
	dcql_query: { credentials: Array<{ id: string; format: string; meta: { vct_values: string[] }; claims: Array<{ path: string[] }> }> };
	/** The client_metadata (encrypted-response params + ephemeral recipient JWK),
	 * present only for encrypted (direct_post.jwt) requests. */
	client_metadata?: Record<string, unknown>;
	/** The DC API request object (for navigator.credentials.get), present only for
	 * transport "dc_api". */
	dc_api_request?: Record<string, unknown>;
	/** The claimed-https redirect URL (transport "openid4vp-redirect") — the request
	 * params in an https URL for universal-links/app-links wallet invocation. */
	redirect_url?: string;
	/** The signed request object (JAR JWT), present for signed requests. */
	request_object?: string;
	/** The request_uri hosting the signed request object (JAR). */
	request_uri?: string;
	/** The verifier session (nonce/state) for matching the response later. */
	session: { nonce: string; state: string; responseUri: string; vct: string; claims: string[] };
}

/** Verifier-facing: generate an OpenID4VP authorization request for an SD-JWT
 * VC of the given vct. Stores a single-use session keyed by `state`. */
export function createAuthorizationRequest(issuerUrl: string, input: CreateAuthRequestInput): AuthRequestResult {
	const nonce = randomSecret();
	const state = randomSecret();
	const clientId = input.clientId ?? issuerUrl;
	const claims = input.claims ?? [];
	const dcqlQuery: AuthRequestResult["dcql_query"] = {
		credentials: [
			{ id: "sd_jwt_vc", format: "dc+sd-jwt", meta: { vct_values: [input.vct] }, claims: claims.map((c) => ({ path: [c] })) },
		],
	};
	let responseMode: "direct_post" | "direct_post.jwt" | "dc_api" | "dc_api.jwt" = "direct_post";
	let responseUri = input.responseUri ?? `${issuerUrl}/openid4vp/response`;
	let recipientPrivateKeyPem: string | undefined;
	let clientMetadata: Record<string, unknown> | undefined;
	if (input.encrypted) {
		// Per-request ephemeral ECDH-ES recipient key (P-256); the wallet encrypts the
		// response to its public JWK; the receiver decrypts with the private key.
		const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
		recipientPrivateKeyPem = privateKey.export({ format: "pem", type: "pkcs8" }) as string;
		const epk = publicKey.export({ format: "jwk" }) as Record<string, string>;
		responseMode = "direct_post.jwt";
		responseUri = input.responseUri ?? `${issuerUrl}/openid4vp/response/${state}`;
		clientMetadata = {
			encrypted_response_alg: "ECDH-ES",
			encrypted_response_enc: "A128GCM",
			jwks: { keys: [epk] },
			vp_formats: { "dc+sd-jwt": { "sd-jwt_alg_values": ["EdDSA", "ES256"], "kb-jwt_alg_values": ["EdDSA", "ES256"] } },
		};
	}
	if (input.transport === "dc_api") {
		// W3C Digital Credentials API delivery: the verifier's web frontend passes the
		// dc_api_request object to navigator.credentials.get({ digital: { protocol:
		// "openid4vp", request: ... } }); the wallet returns the response via the DC API
		// + the frontend relays it to response_uri (the receiver, unchanged).
		responseMode = input.encrypted ? "dc_api.jwt" : "dc_api";
	}
	const dcApiRequest = input.transport === "dc_api"
		? { response_type: "vp_token", response_mode: responseMode, client_id: clientId, nonce, state, dcql_query: dcqlQuery, response_uri: responseUri, ...(clientMetadata ? { client_metadata: clientMetadata } : {}) }
		: undefined;
	const params = new URLSearchParams({
		response_type: "vp_token",
		response_mode: responseMode,
		client_id: clientId,
		response_uri: responseUri,
		nonce,
		state,
		dcql_query: JSON.stringify(dcqlQuery),
		...(clientMetadata ? { client_metadata: JSON.stringify(clientMetadata) } : {}),
	});
	const uri = `openid4vp://?${params.toString()}`;
	const redirectUrl = input.transport === "openid4vp-redirect" ? `${issuerUrl}/openid4vp?${params.toString()}` : undefined;
	const session: VerifierSession = {
		nonce,
		state,
		vct: input.vct,
		claims,
		clientId,
		responseUri,
		createdAt: Date.now(),
		consumed: false,
		...(recipientPrivateKeyPem ? { recipientPrivateKeyPem } : {}),
	};
	sessions.set(state, session);
	return { uri, dcql_query: dcqlQuery, ...(clientMetadata ? { client_metadata: clientMetadata } : {}), ...(dcApiRequest ? { dc_api_request: dcApiRequest } : {}), ...(redirectUrl ? { redirect_url: redirectUrl } : {}), session: { nonce, state, responseUri, vct: input.vct, claims } };
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

/** Look up a verifier session by state (for the encrypted direct_post.jwt
 * receiver, where the state is carried in the response_uri path). */
export function getSessionByState(state: string): VerifierSession | null {
	return sessions.get(state) ?? null;
}

/** Peek the KB-JWT nonce from an SD-JWT VC presentation (the holder-bound
 * nonce the wallet binds into the KB-JWT). Returns null if there is no KB-JWT
 * (a non-holder-bound credential) — OpenID4VP requires the nonce binding, so
 * the receiver rejects such a presentation. */
export function peekKbJwtNonce(presentation: string): string | null {
	const parts = presentation.split("~");
	const last = parts[parts.length - 1];
	if (!last || !last.includes(".")) return null;
	try {
		const payloadB64 = last.split(".")[1];
		if (!payloadB64) return null;
		const payload = JSON.parse(Buffer.from(payloadB64.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { nonce?: unknown };
		return typeof payload.nonce === "string" ? payload.nonce : null;
	} catch {
		return null;
	}
}

/** Mark a verifier session consumed (single-use, after a successful verify so a
 * replayed presentation cannot be re-verified). No-op if the session is gone. */
export function consumeSession(state: string): void {
	const s = sessions.get(state);
	if (s) s.consumed = true;
}

/** Verifier-facing: generate a signed OpenID4VP authorization request (JAR —
 * the request params as a signed Request Object JWT, passed by reference via
 * request_uri) with the x509_hash client-id scheme (HAIP §5). The request JWT is
 * ES256-signed with the issuer P-256 key + carries x5c; the wallet fetches
 * request_uri (GET) + verifies it. v1: signed request + direct_post (unencrypted);
 * the JAR + encrypted combo is a follow-up. */
export function createSignedAuthorizationRequest(issuerUrl: string, p256Key: IssuerP256Key, input: CreateAuthRequestInput): AuthRequestResult {
	const nonce = randomSecret();
	const state = randomSecret();
	const claims = input.claims ?? [];
	const dcqlQuery: AuthRequestResult["dcql_query"] = {
		credentials: [{ id: "sd_jwt_vc", format: "dc+sd-jwt", meta: { vct_values: [input.vct] }, claims: claims.map((c) => ({ path: [c] })) }],
	};
	const responseUri = input.responseUri ?? `${issuerUrl}/openid4vp/response`;
	const certDer = Buffer.from(p256Key.x5c![0]!, "base64");
	const clientId = `x509_hash:${b64url(createHash("sha256").update(certDer).digest())}`;
	const requestObjectPayload: Record<string, unknown> = {
		response_type: "vp_token",
		response_mode: "direct_post",
		client_id: clientId,
		response_uri: responseUri,
		nonce,
		state,
		dcql_query: dcqlQuery,
	};
	const requestObject = signEs256Jwt(requestObjectPayload, p256Key, p256Key.kid, "oauth-authz-req+jwt", p256Key.x5c);
	requestObjects.set(state, requestObject);
	const requestUri = `${issuerUrl}/openid4vp/request/${state}`;
	const params = new URLSearchParams({ client_id: clientId, request_uri: requestUri, request_uri_method: "get" });
	const uri = `openid4vp://?${params.toString()}`;
	const session: VerifierSession = { nonce, state, vct: input.vct, claims, clientId, responseUri, createdAt: Date.now(), consumed: false };
	sessions.set(state, session);
	return { uri, dcql_query: dcqlQuery, request_object: requestObject, request_uri: requestUri, session: { nonce, state, responseUri, vct: input.vct, claims } };
}

export function _resetOpenid4vpForTests(): void {
	sessions.clear();
	requestObjects.clear();
}