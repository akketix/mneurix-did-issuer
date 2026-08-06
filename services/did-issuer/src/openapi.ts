// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** OpenAPI 3.1 document for the did-issuer service. Served at GET /v1/openapi.json.
 * Covers the v1 management API (DID mint/resolve/rotate/revoke/publish, VC issue
 * + verify) AND the wallet-facing OID4VCI / OpenID4VP surface (credential
 * offers, the authorization-code + pre-authorized-code grants, the credential
 * endpoint, OpenID4VP request/response, the /.well-known discovery metadata).
 * The /qr page is a wallet-integration test helper. */
export const openApiDoc = {
	openapi: "3.1.0",
	info: {
		title: "Mneurix DID Token Issuer",
		version: "0.1.0",
		description: "did:web + W3C Verifiable Credentials (OB3 data-integrity / SD-JWT VC) issuer + verifier, with wallet-facing OID4VCI issuance (pre-authorized-code + authorization-code grants) and OpenID4VP verification.",
		license: { name: "Elastic License 2.0", url: "https://www.elastic.co/licensing/elastic-license" },
	},
	servers: [{ url: "/v1", description: "relative" }],
	components: {
		securitySchemes: {
			serviceToken: { type: "apiKey", in: "header", name: "x-mneurix-service-token" },
			bearerAccess: { type: "http", scheme: "bearer", description: "Wallet access token from /oauth/token (OID4VCI credential endpoint)." },
		},
		responses: {
			NotImplemented: {
				description: "Endpoint declared but not implemented in this milestone.",
				content: { "application/json": { schema: { $ref: "#/components/schemas/Error" } } },
			},
		},
		schemas: {
			Error: {
				type: "object",
				properties: {
					error: {
						type: "object",
						properties: { code: { type: "string" }, message: { type: "string" }, details: {} },
						required: ["code", "message"],
					},
				},
				required: ["error"],
			},
		},
	},
	paths: {
"/.well-known/did.json": { get: { summary: "did:web DID document (canonical origin)", operationId: "wellKnownDid", security: [], responses: { "200": { description: "DID document" } } } },
"/.well-known/jwt-vc-issuer": { get: { summary: "SD-JWT VC issuer metadata (legacy path)", operationId: "wellKnownJwtVcIssuer", security: [], responses: { "200": { description: "Issuer metadata" } } } },
"/.well-known/oauth-authorization-server": { get: { summary: "OID4VCI OAuth 2.0 authorization-server metadata (RFC 8414): token endpoint, authorization_endpoint, grant_types (pre-authorized-code + authorization_code), PKCE S256", operationId: "wellKnownOauthAuthorizationServer", security: [], responses: { "200": { description: "Authorization-server metadata" } } } },
"/.well-known/openid-credential-issuer": { get: { summary: "OID4VCI credential-issuer metadata (draft-ietf-oauth-4-vc): credential endpoint + credential configurations (SD-JWT VC, dual vc+sd-jwt/dc+sd-jwt format labels for wallet compat)", operationId: "wellKnownOpenidCredentialIssuer", security: [], responses: { "200": { description: "Credential-issuer metadata" } } } },
"/.well-known/oauth-credential-issuer": { get: { summary: "OID4VCI credential-issuer metadata (older alias; same body as openid-credential-issuer)", operationId: "wellKnownOauthCredentialIssuer", security: [], responses: { "200": { description: "Credential-issuer metadata" } } } },
"/health": { get: { summary: "Health check", operationId: "health", security: [], responses: { "200": { description: "ok" } } } },
"/qr": { get: { summary: "Wallet-integration test page (text/html): mints an authorization_code credential offer + renders a QR for a wallet to scan", operationId: "qrTestPage", security: [], responses: { "200": { description: "HTML page with a credential-offer QR" } } } },
"/v1/dids": {
	post: {
		summary: "Mint a did:web identifier + publish its DID document",
		operationId: "post_v1_dids",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/v1/dids/{did}": {
	get: {
		summary: "Resolve a did:web identifier (fan-out + quorum)",
		operationId: "get_v1_dids_did_",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/v1/vcs:issue": {
	post: {
		summary: "Issue a Verifiable Credential (OB3 Data-Integrity or SD-JWT VC)",
		operationId: "post_v1_vcs_issue",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/v1/presentations:verify": {
	post: {
		summary: "Verify a Verifiable Presentation / VC (operator-facing)",
		operationId: "post_v1_presentations_verify",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/v1/presentations/request": {
	post: {
		summary: "Generate an OpenID4VP authorization request (DCQL query for an SD-JWT VC by vct) + a verifier session (nonce/state). Supports single + multi-credential DCQL.",
		operationId: "post_v1_presentations_request",
		security: [{ serviceToken: [] }],
		responses: { "201": { description: "OpenID4VP request + session" } },
	},
},
"/v1/credential-offers": {
	post: {
		summary: "Mint a credential offer (OID4VCI). grantType=pre-authorized_code (operator-initiated, subject pre-bound) or authorization_code (wallet-initiated, subject established at /oauth/authorize).",
		operationId: "post_v1_credential_offers",
		security: [{ serviceToken: [] }],
		responses: { "201": { description: "Credential offer" } },
	},
},
"/v1/dids/{did}/keys:rotate": {
	post: {
		summary: "Rotate the assertion key (DID stays stable)",
		operationId: "post_v1_dids_did_keys_rotate",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/v1/dids/{did}/keys:revoke": {
	post: {
		summary: "Revoke an assertion key (tombstone)",
		operationId: "post_v1_dids_did_keys_revoke",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/v1/credentials/{id}/status": {
	get: {
		summary: "Credential revocation status (fail-closed)",
		operationId: "get_v1_credentials_id_status",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/v1/dids/{did}/publish": {
	post: {
		summary: "Publish the DID document to all origins (quorum)",
		operationId: "post_v1_dids_did_publish",
		security: [{ serviceToken: [] }],
		responses: { "200": { description: "OK" } },
	},
},
"/oauth/authorize": {
	get: {
		summary: "OID4VCI authorization endpoint (wallet-initiated, PKCE S256). When MNEURIX_LATTICE_AUTH_URL is set, delegates learner auth to the lattice; otherwise renders a minimal self-hosted consent page. Issues a single-use authorization code bound to (PKCE + subject + credential request).",
		operationId: "get_oauth_authorize",
		security: [],
		responses: { "200": { description: "Consent page (self-hosted)" }, "302": { description: "Redirect to the lattice (delegated) or to the wallet redirect_uri with ?code&state" }, "400": { description: "Invalid request" } },
	},
},
"/oauth/consent": {
	post: {
		summary: "Self-hosted consent submit (form-encoded). The learner confirms their identity; the did-issuer issues an authorization code + 302-redirects to the wallet's redirect_uri.",
		operationId: "post_oauth_consent",
		security: [],
		responses: { "302": { description: "Redirect to the wallet redirect_uri with ?code&state" }, "400": { description: "Invalid request" } },
	},
},
"/oauth/callback": {
	get: {
		summary: "Delegated-auth callback: the lattice redirects here with a signed auth_result (HS256 with MNEURIX_LATTICE_AUTH_SHARED_SECRET) after authenticating the learner. Issues the authorization code + 302-redirects to the wallet. Fail-closed when delegation is unconfigured.",
		operationId: "get_oauth_callback",
		security: [],
		responses: { "302": { description: "Redirect to the wallet redirect_uri with ?code&state" }, "400": { description: "Delegation unconfigured / invalid request" }, "401": { description: "auth_result signature invalid" } },
	},
},
"/oauth/token": {
	post: {
		summary: "OID4VCI token endpoint. Redeems a pre-authorized_code OR an authorization_code (+ PKCE verifier) for a bearer access token + c_nonce. Accepts form-encoded (RFC 6749) or JSON.",
		operationId: "post_oauth_token",
		security: [],
		responses: { "200": { description: "access_token + c_nonce" }, "400": { description: "INVALID_GRANT / INVALID_PKCE / INVALID_REQUEST" } },
	},
},
"/credentials": {
	post: {
		summary: "OID4VCI credential endpoint. The wallet posts the Bearer access token + a proof-of-possession JWT (signed by the wallet holder key, containing the c_nonce) and receives the SD-JWT VC (EdDSA or ES256).",
		operationId: "post_credentials",
		security: [{ bearerAccess: [] }],
		responses: { "200": { description: "SD-JWT VC" }, "401": { description: "Invalid/expired access token or proof verification failed" } },
	},
},
"/openid4vp/response": {
	post: {
		summary: "OpenID4VP presentation receiver (direct_post). The wallet POSTs the vp_token (SD-JWT VC + KB-JWT) + state; the receiver verifies the issuer signature, disclosures, holder binding, revocation, and the DCQL query (single or multi-credential).",
		operationId: "post_openid4vp_response",
		security: [],
		responses: { "200": { description: "Verification result" }, "401": { description: "Verification failed (fail-closed)" } },
	},
},
	},
} as const;