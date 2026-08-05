// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

import { Hono, type Context } from "hono";
import { serve } from "@hono/node-server";
import { pathToFileURL } from "node:url";
import { requireServiceToken } from "./serviceAuth";
import { jsonError } from "./errors";
import { openApiDoc } from "./openapi";
import { buildDidDocument, buildDidDocumentMulti, originFromDid, didFor, didHash, publicKeyJwkFromPem, type DidMethod } from "./did";
import { loadOrCreateIssuerKey, rotateIssuerKey, getKeyByKid, knownKids, loadOrCreateP256IssuerKey, signEs256Jwt, persistP256Cert } from "./keys";
import { generateSelfSignedCert } from "./x509";
import { putDid, getDid, setPublished } from "./store";
import { loadOriginsFromEnv, originListFromUrls } from "./origins";
import { resolveDid } from "./resolve";
import { publishDid } from "./publish";
import { randomUUID, randomBytes, createHmac, timingSafeEqual } from "node:crypto";
/** A random URL-safe secret (for pending-state correlation). */
function cryptoRandomSecret(): string {
	return randomBytes(32).toString("base64url");
}
/** Verify an HS256 JWT (the lattice auth-result callback) + return its payload,
 * or null if the signature is invalid / structure is wrong. Constant-time compare. */
function verifyHs256Jwt(jwt: string, secret: string): Record<string, unknown> | null {
	try {
		const parts = jwt.split(".");
		if (parts.length !== 3) return null;
		const [h, p, s] = parts as [string, string, string];
		const header = JSON.parse(Buffer.from(h.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { alg?: string };
		if (header.alg !== "HS256") return null;
		const signingInput = Buffer.from(h + "." + p, "ascii");
		const sig = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64");
		const expected = createHmac("sha256", secret).update(signingInput).digest();
		if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
		return JSON.parse(Buffer.from(p.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as Record<string, unknown>;
	} catch {
		return null;
	}
}
import { issueOb3 } from "./vc-issue";
import { issueSdJwtVc, signIssuerJwt } from "./sdjwt";
import { allocateOb3Status, allocateSdJwtStatus, getCredentialStatus, getEncodedStatusList } from "./status";
import { createCredentialOffer, createAuthorizationCodeCredentialOffer, exchangePreAuthorizedCode, consumeAccessToken, getCNonceForToken, consumeCNonce, verifyProofAsync, mintAccessTokenForCredentialRequest, type CredentialRequest } from "./oid4vci";
import { issueAuthorizationCode, exchangeAuthorizationCode, storePendingAuthRequest, takePendingAuthRequest, consentPageHtml, verifyPkce } from "./oauth";
import { createAuthorizationRequest, createSignedAuthorizationRequest, resolveSession, peekKbJwtNonce, consumeSession, getSessionByState, getRequestObject } from "./openid4vp";
import { decryptResponse } from "./jwe";
import { revokeKid } from "./revoked-kids";
import { requireOperator } from "./operatorAuth";
import { verifyPresentation, verifyEs256Presentation, verifyJwsWithJwk } from "./vc-verify";
import type { Achievement, BadgeEvidence, StatusPurpose } from "@mneurix/shared";
import { assertRestEncryptionInProd } from "@mneurix/shared";
import { assertPlatformLicense, getLicenseState } from "@mneurix/licensing";

// Run platform license boot guard (Phase F)
assertPlatformLicense({});

function checkIssuanceLicenseGate(c: Context) {
	const state = getLicenseState();
	if (state?.degraded || state?.trialExpired) {
		return jsonError(
			c,
			402,
			"LICENSE_REQUIRED",
			state?.trialExpired
				? "The 90-day evaluation period has ended. Register your license at https://mneurix.dev/credential-infrastructure"
				: "Platform license expired and past the grace period. Renew at https://mneurix.dev/credential-infrastructure",
		);
	}
	if (state?.unlicensed && !state?.trialExpired) {
		c.header("X-Mneurix-License-Warning", "TRIAL_MODE; register at https://mneurix.dev/credential-infrastructure");
	}
	if (state?.expired && state?.validUntil) {
		c.header(
			"X-Mneurix-License-Warning",
			`LICENSE_GRACE_PERIOD; valid_until=${state.validUntil}`,
		);
	}
	return null;
}

const SERVICE_TOKEN =
	process.env.MNEURIX_DID_ISSUER_SERVICE_TOKEN ?? "dev-did-issuer-token";
if (
	process.env.MNEURIX_ENV === "production" &&
	(!SERVICE_TOKEN || SERVICE_TOKEN === "dev-did-issuer-token")
) {
	throw new Error(
		"MNEURIX_DID_ISSUER_SERVICE_TOKEN must be set to a non-default value in production",
	);
}

const ISSUER_ORIGIN = process.env.MNEURIX_DID_ISSUER_ORIGIN ?? "did-issuer.mneurix.example";
let issuerKey = loadOrCreateIssuerKey(process.env.MNEURIX_KEY_DIR);
let p256Key = loadOrCreateP256IssuerKey(process.env.MNEURIX_KEY_DIR);
const ISSUER_URL = (process.env.MNEURIX_DID_ISSUER_URL ?? "https://did-issuer.mneurix.example").replace(/\/+$/, "");
// HAIP §6.1.1: the ES256 SD-JWT VC carries the issuer cert chain in `x5c`. v1
// generates a self-signed DEV cert (exercises the x5c plumbing); prod replaces it
// with an IACA-issued cert (procurement). Derived from the P-256 key at boot.
// M-4 fix: only generate the cert if it wasn't loaded from the persisted key file.
if (!p256Key.x5c) {
	p256Key.x5c = generateSelfSignedCert(p256Key, new URL(ISSUER_URL).host);
	persistP256Cert(process.env.MNEURIX_KEY_DIR, p256Key.x5c);
}
const ISSUER_NAME = process.env.MNEURIX_ISSUER_NAME ?? "Mneurix";
// OID4VCI authorization-code flow (phase-2 Task 1): when
// MNEURIX_LATTICE_AUTH_URL is set, /oauth/authorize delegates learner
// authentication to the lattice's existing auth (the did-issuer stays
// auth-delegated, not auth-hosting). When unset, the did-issuer shows its own
// minimal consent page (the independently-deployable fallback; graceful degrade
// when the lattice is unconfigured, per the architecture principle). Read lazily
// per-request so tests can configure delegation mid-suite. The shared secret
// signs the lattice's auth-result callback (HS256).
const latticeAuthUrl = (): string => process.env.MNEURIX_LATTICE_AUTH_URL ?? "";
const latticeAuthSharedSecret = (): string => process.env.MNEURIX_LATTICE_AUTH_SHARED_SECRET ?? "";
const ISSUER_HOST = new URL(ISSUER_URL).host;
const issuerDid = didFor(ISSUER_ORIGIN);
function currentVerificationMethod(): string {
	return `${issuerDid}#${issuerKey.kid}`;
}

function mintFor(origin: string): { did: string; document: ReturnType<typeof buildDidDocument> } {
	const jwk = publicKeyJwkFromPem(issuerKey.publicKeyPem);
	const document = buildDidDocument(origin, issuerKey.kid, jwk);
	const did = didFor(origin);
	putDid(did, document, issuerKey.kid);
	return { did, document };
}

export const app = new Hono();

// Request logger (dev/debug, opt-in): method path status duration -> stdout.
// Lets us see exactly which endpoints a wallet (AltMe) hits during an OID4VCI
// flow. Gated behind MNEURIX_REQUEST_LOG=1 so production never ships per-request
// stdout noise. Enable during wallet-integration testing only.
if (process.env.MNEURIX_REQUEST_LOG === "1") {
	app.use("/*", async (c, next) => {
		const start = Date.now();
		await next();
		const ms = Date.now() - start;
		console.log(`${c.req.method} ${c.req.path} ${c.res.status} ${ms}ms`);
	});
}
// CISO encryption-at-rest enforcement (T4): refuse to boot in prod without
// MNEURIX_REST_ENCRYPTION=attested or =app-dek.
assertRestEncryptionInProd();
// M-5 warning: revocation tombstones + status bits are in-memory only. A restart
// resurrects revoked keys/credentials. Durable persistence is tracked as a
// follow-up (M10); until then, warn in production.
if (process.env.MNEURIX_ENV === "production") {
	console.warn("[revocation] WARNING: revocation tombstones + status bits are in-memory only. A restart resurrects revoked keys/credentials. Durable persistence is a follow-up (M10).");
}
app.get("/health", (c) => c.json({ status: "ok", service: "did-issuer" }));
app.get("/v1/openapi.json", (c) => c.json(openApiDoc));

// Public did:web well-known (canonical origin).
app.get("/.well-known/did.json", (c) => {
	// H3 fix: serve the STORED document (not re-mint on every GET). mintFor writes
	// to the store (putDid) — calling it on every GET clobbers the rotated DID doc
	// (after a key rotation, the next well-known fetch replaces the multi-method
	// rotated doc with a single-method current-key-only doc → old credentials
	// can't verify). Only mint if the store has no doc yet.
	const stored = getDid(issuerDid);
	if (stored) return c.json(stored.document);
	const { document } = mintFor(ISSUER_ORIGIN);
	return c.json(document);
});

// Public SD-JWT VC issuer metadata (draft-ietf-oauth-sd-jwt-vc §3): the issuer
// origin + the issuer Ed25519 JWK (with kid + alg) for key discovery.
// vct taxonomy: the credential types this issuer supports + their claim
// schemas (wallet/verifier discovery via /.well-known/jwt-vc-issuer vct_values +
// GET /vct/:name). v1 ships a small set (achievement, competency, mastery); the
// registry is advisory — issuance accepts any caller-supplied vct.
const VCT_DEFINITIONS: Record<string, { name: string; description: string; claims: Record<string, string> }> = {
	achievement: { name: "Mneurix Achievement", description: "A verifiable achievement/competency credential issued by Mneurix.", claims: { score: "number", agreement: "number", given_name: "string" } },
	competency: { name: "Mneurix Competency", description: "A council-verified competency attestation.", claims: { score: "number", agreement: "number", criterionScores: "array" } },
	mastery: { name: "Mneurix Mastery", description: "A mastery credential (a competency at mastery level).", claims: { score: "number", level: "string", achievedAt: "string" } },
};
function vctUri(name: string): string { return `${ISSUER_URL}/vct/${name}`; }
function vctValues(): string[] { return Object.keys(VCT_DEFINITIONS).map(vctUri); }
const DEFAULT_VCT = vctUri("achievement");

// Public SD-JWT VC issuer metadata (draft-ietf-oauth-sd-jwt-vc): issuer origin
// + the issuer Ed25519 JWK (kid + alg) for key discovery, + the supported vct
// values (wallet/verifier discovery of the credential type).
app.get("/.well-known/jwt-vc-issuer", (c) => {
	const edJwk = publicKeyJwkFromPem(issuerKey.publicKeyPem);
	return c.json({
		issuer: ISSUER_URL,
		// Hybrid key model: Ed25519/EdDSA (did:web, self-sovereign) + P-256/ES256
		// (HAIP/EUDI wallet path). Wallets pick the issuer key by alg.
		jwks: {
			keys: [
				{ ...edJwk, kid: issuerKey.kid, alg: "EdDSA" },
				{ ...p256Key.jwk, kid: p256Key.kid, alg: "ES256", ...(p256Key.x5c ? { x5c: p256Key.x5c } : {}) },
			],
		},
		vct_values: vctValues(),
	});
});

// SD-JWT VC vct type metadata: the definition for a vct value. v1 serves a
// minimal definition for the default achievement vct; the full per-achievement-
// type vct taxonomy is a follow-up.
app.get("/vct/:name", (c) => {
	const name = c.req.param("name");
	const def = VCT_DEFINITIONS[name];
	if (!def) return c.json({ error: "unknown vct" }, 404);
	return c.json({ vct: vctUri(name), name: def.name, description: def.description, claims: def.claims });
});

// IETF Token Status List (draft-ietf-oauth-status-list): the status list for a
// purpose, served as a signed JWT (statuslist+jwt) at the uri a credential's
// `status.status_list.uri` points to. A verifier fetches this, checks the issuer
// signature (against /.well-known/jwt-vc-issuer), + reads the bit at the
// credential's `status.status_list.idx` (0 = valid, 1 = revoked, fail-closed).
app.get("/statuslists/:purpose/:id", async (c) => {
	const purpose = c.req.param("purpose") as StatusPurpose;
	if (purpose !== "revocation" && purpose !== "refresh" && purpose !== "delisted") {
		return c.json({ error: "invalid status purpose" }, 400);
	}
	const alg = c.req.query("alg") === "ES256" ? "ES256" : "EdDSA";
	const base = `${ISSUER_URL}/statuslists/${purpose}/${c.req.param("id")}`;
	const uri = alg === "ES256" ? `${base}?alg=ES256` : base;
	const payload = {
		sub: uri,
		iat: Math.floor(Date.now() / 1000),
		status_list: { bits: 1, vals: getEncodedStatusList(purpose) },
	};
	// HAIP §6.1: the status-list token for the ES256 path is ES256-signed + carries
	// x5c; the Ed25519 token serves the did:web/self-sovereign path.
	const jwt = alg === "ES256"
		? signEs256Jwt(payload, p256Key, p256Key.kid, "statuslist+jwt", p256Key.x5c)
		: await signIssuerJwt(payload, issuerKey, issuerKey.kid, "statuslist+jwt");
	return c.body(jwt, 200, { "content-type": "application/statuslist+jwt" });
});

const v1 = new Hono();
v1.use(requireServiceToken(SERVICE_TOKEN));

// POST /v1/dids — mint/ensure a did:web document for an origin.
v1.post("/dids", async (c) => {
	const body = (await c.req.json().catch(() => null)) as { origin?: string } | null;
	if (!body || !body.origin || !/^[a-z0-9.:-]+$/i.test(body.origin)) {
		return jsonError(c, 400, "BAD_REQUEST", "origin is required (host[:path], alnum/dot/dash/colon)");
	}
	const { did, document } = mintFor(body.origin);
	return c.json({ did, document, kid: issuerKey.kid }, 201);
});

// GET /v1/dids/:did — resolve. With origins configured (MNEURIX_DID_ORIGINS):
// fan out + quorum across origins, pinning against the stored publish hash.
// Without origins, fall back to the local store (M3 behaviour).
v1.get("/dids/:did", async (c) => {
	const did = c.req.param("did");
	const stored = getDid(did);
	if (!stored) return jsonError(c, 404, "DID_NOT_FOUND", did + " is not in the local store (mint it first)");
	const originList = stored.origins && stored.origins.length > 0 ? originListFromUrls(stored.origins) : loadOriginsFromEnv();
	if (originList.origins.length === 0) {
		return c.json({ did, document: stored.document, resolvedFrom: ["local"], docHash: didHash(stored.document), verified: true, mismatches: [] });
	}
	const result = await resolveDid(did, originList, stored.docHash);
	if (result.document === null) {
		// All origins unreachable / wrong id — fall back to the local doc, not verified.
		return c.json({ did, document: stored.document, resolvedFrom: ["local"], docHash: didHash(stored.document), verified: false, mismatches: result.mismatches });
	}
	return c.json({ did, document: result.document, resolvedFrom: result.resolvedFrom, docHash: result.docHash, verified: result.verified, mismatches: result.mismatches });
});

// M6: rotate / revoke / verify / status are live; no v1 stubs remain.

// POST /v1/dids/:did/keys:rotate — mint a new assertion key; republish the DID
// doc with old (tombstoned) + new verificationMethod; tombstone the old kid.
// The DID stays stable; the new key signs all subsequent VCs (operator-auth).
v1.post("/dids/:did/keys:rotate", requireOperator(["issuer", "revoker"]), async (c) => {
	const did = c.req.param("did");
	const stored = getDid(did);
	if (!stored) return jsonError(c, 404, "DID_NOT_FOUND", did + " is not in the local store (mint it first)");
	const oldKid = stored.kid;
	const oldKey = issuerKey;
	const newKey = rotateIssuerKey(oldKey);
	const origin = originFromDid(did);
	const methods: DidMethod[] = [
		{ kid: oldKid, publicKeyJwk: publicKeyJwkFromPem(oldKey.publicKeyPem) },
		{ kid: newKey.kid, publicKeyJwk: publicKeyJwkFromPem(newKey.publicKeyPem) },
	];
	const document = buildDidDocumentMulti(origin, methods, [newKey.kid]);

	// Atomic multi-origin republish (if origins are configured).
	const originList = stored.origins && stored.origins.length > 0 ? originListFromUrls(stored.origins) : loadOriginsFromEnv();
	let publishedTo: string[] = [];
	if (originList.origins.length > 0) {
		const pub = await publishDid(originList, did, document);
		if (!pub.staged) return jsonError(c, 503, "PUBLISH_QUORUM_FAILED", `rotate publish failed quorum (${pub.confirmed}/${originList.origins.length})`, pub);
		publishedTo = pub.publishedTo;
	}

	// H-3 fix: keep the old kid VALID (rotation is NOT revocation -- existing
	// credentials signed by the old key stay verifiable). Only keys:revoke
	// tombstones (for compromise). Flip the module issuer key to the new key.
	issuerKey = newKey;
	putDid(did, document, newKey.kid);
	if (publishedTo.length > 0) setPublished(did, publishedTo, didHash(document));
	return c.json({ did, newKid: newKey.kid, retainedKid: oldKid, publishedTo, docHash: didHash(document) });
});

// POST /v1/dids/:did/keys:revoke — tombstone a kid + remove it from the DID doc;
// republish atomically (operator-auth). Body: { kid?: string } (defaults to current).
v1.post("/dids/:did/keys:revoke", requireOperator(["revoker"]), async (c) => {
	const did = c.req.param("did");
	const stored = getDid(did);
	if (!stored) return jsonError(c, 404, "DID_NOT_FOUND", did + " is not in the local store (mint it first)");
	const body = (await c.req.json().catch(() => ({}))) as { kid?: string };
	const kid = body.kid ?? stored.kid;
	// H-3 fix: refuse to revoke the active signing key without a successor.
	if (kid === issuerKey.kid) {
		return jsonError(c, 400, "BAD_REQUEST", "cannot revoke the active signing key -- rotate first (POST /v1/dids/" + did + "/keys:rotate)");
	}
	await revokeKid(kid, issuerKey, currentVerificationMethod());

	// Rebuild the doc WITHOUT the revoked kid.
	const origin = originFromDid(did);
	const remaining: DidMethod[] = stored.document.verificationMethod
		.filter((vm) => vm.id !== `${did}#${kid}`)
		.map((vm) => ({ kid: vm.id.split("#")[1]!, publicKeyJwk: vm.publicKeyJwk }));
	const assertionKids = remaining.map((m) => m.kid);
	const document = remaining.length > 0 ? buildDidDocumentMulti(origin, remaining, assertionKids) : buildDidDocumentMulti(origin, [], []);

	const originList = stored.origins && stored.origins.length > 0 ? originListFromUrls(stored.origins) : loadOriginsFromEnv();
	let publishedTo: string[] = [];
	if (originList.origins.length > 0) {
		const pub = await publishDid(originList, did, document);
		if (!pub.staged) return jsonError(c, 503, "PUBLISH_QUORUM_FAILED", `revoke publish failed quorum (${pub.confirmed}/${originList.origins.length})`, pub);
		publishedTo = pub.publishedTo;
	}
	// M-10 fix: update stored.kid if it was the revoked kid (prevent stale kid).
	const newStoredKid = stored.kid === kid ? (assertionKids[0] ?? issuerKey.kid) : stored.kid;
	putDid(did, document, newStoredKid);
	if (publishedTo.length > 0) setPublished(did, publishedTo, didHash(document));
	return c.json({ did, revokedKid: kid, publishedTo, docHash: didHash(document) });
});

// POST /v1/presentations:verify — verify an OB3 VC / SD-JWT VC / SD-JWT+KB,
// fail-closed on a revoked signing key (F15 tombstone) or revoked status.
v1.post("/presentations:verify", async (c) => {
	const body = (await c.req.json().catch(() => null)) as {
		presentation?: unknown;
		requireKeyBinding?: boolean;
		nonce?: string;
		aud?: string;
	} | null;
	if (!body || body.presentation === undefined || body.presentation === null) {
		return jsonError(c, 400, "BAD_REQUEST", "presentation is required");
	}
	// M-6 fix: dispatch on the issuer-JWT alg (ES256 -> verifyEs256Presentation, else verifyPresentation)
	let result: { verified: boolean; subject?: string; issuer?: string; status: string; kid?: string; reason?: string };
	try {
		if (typeof body.presentation === "string" && body.presentation.includes("~")) {
			const issuerJwt = body.presentation.split("~")[0]!;
			const hdr = JSON.parse(Buffer.from(issuerJwt.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { alg?: string };
			result = hdr.alg === "ES256"
				? await verifyEs256Presentation(body.presentation, p256Key, {
						...(body.requireKeyBinding ? { requireKeyBinding: body.requireKeyBinding } : {}),
						...(body.nonce ? { nonce: body.nonce } : {}),
						...(body.aud ? { aud: body.aud } : {}),
					})
				: await verifyPresentation({
						presentation: body.presentation as Parameters<typeof verifyPresentation>[0]["presentation"],
						...(body.requireKeyBinding ? { requireKeyBinding: body.requireKeyBinding } : {}),
						...(body.nonce ? { nonce: body.nonce } : {}),
						...(body.aud ? { aud: body.aud } : {}),
					});
		} else {
			result = await verifyPresentation({
				presentation: body.presentation as Parameters<typeof verifyPresentation>[0]["presentation"],
				...(body.requireKeyBinding ? { requireKeyBinding: body.requireKeyBinding } : {}),
				...(body.nonce ? { nonce: body.nonce } : {}),
				...(body.aud ? { aud: body.aud } : {}),
			});
		}
	} catch {
		return c.json({ verified: false, status: "rejected", reason: "malformed presentation" });
	}
	return c.json(result);
});

// GET /v1/credentials/:id/status — credential revocation status (fail-closed).
v1.get("/credentials/:id/status", (c) => {
	const id = decodeURIComponent(c.req.param("id"));
	const st = getCredentialStatus(id);
	return c.json({ id, state: st.state, revoked: st.revoked, statusPurpose: st.statusPurpose, statusListIndex: st.statusListIndex });
});

// POST /v1/vcs:issue — issue a VC in one of two envelopes (M5):
// data-integrity (OB3 ed25519-jcs-2020) or sd-jwt-vc (RFC 9901 SD-JWT VC, Ed25519-only).
v1.post("/vcs:issue", async (c) => {
	const gate = checkIssuanceLicenseGate(c);
	if (gate) return gate;
	const body = (await c.req.json().catch(() => null)) as {
		subjectId?: string;
		secure?: string;
		achievement?: Achievement;
		evidence?: BadgeEvidence;
		credentialId?: string;
		vct?: string;
		claims?: Record<string, unknown>;
		selectivelyDisclosable?: string[];
		holderJwk?: Record<string, string>;
		/** Issuer-signed JWT algorithm: "EdDSA" (default, did:web) or "ES256"
		 * (HAIP/EUDI wallet path, P-256 + x5c). */
		alg?: "EdDSA" | "ES256";
	} | null;
	if (!body || !body.subjectId || !body.secure) {
		return jsonError(c, 400, "BAD_REQUEST", "subjectId and secure are required (secure: data-integrity | sd-jwt-vc)");
	}
	const statusListId = body.alg === "ES256"
		? `${ISSUER_URL}/statuslists/revocation/1?alg=ES256`
		: `${ISSUER_URL}/statuslists/revocation/1`;

	if (body.secure === "data-integrity") {
		if (!body.achievement || !body.evidence) {
			return jsonError(c, 400, "BAD_REQUEST", "data-integrity issue requires achievement + evidence");
		}
		const credentialId = body.credentialId ?? `${ISSUER_URL}/credentials/${randomUUID()}`;
		const credentialStatus = allocateOb3Status(statusListId, "revocation", credentialId);
		const issuer = { id: issuerDid, type: ["Profile"], name: ISSUER_NAME };
		const credential = await issueOb3(body.subjectId, body.achievement, body.evidence, issuer, issuerKey, currentVerificationMethod(), credentialId, credentialStatus);
		return c.json({ credential, format: "ob3", statusIndex: credentialStatus.statusListIndex }, 201);
	}

	if (body.secure === "sd-jwt-vc") {
		if (!body.vct || !body.claims) {
			return jsonError(c, 400, "BAD_REQUEST", "sd-jwt-vc issue requires vct + claims");
		}
		const selectivelyDisclosable = body.selectivelyDisclosable ?? [];
		const status = allocateSdJwtStatus(statusListId, "revocation", undefined);
		let result: Awaited<ReturnType<typeof issueSdJwtVc>>;
		try {
			result = await issueSdJwtVc({
				iss: body.alg === "ES256" ? ISSUER_URL : issuerDid,
				sub: body.subjectId,
				vct: body.vct,
				claims: body.claims,
				selectivelyDisclosable,
				...(body.holderJwk ? { holderJwk: body.holderJwk } : {}),
				status,
				verificationMethod: currentVerificationMethod(),
				...(body.alg ? { alg: body.alg } : {}),
			}, issuerKey, p256Key);
		} catch (e) {
			return jsonError(c, 400, "BAD_REQUEST", `cannot issue: ${(e as Error).message}`);
		}
		return c.json({ credential: result.credential, format: "dc+sd-jwt", statusIndex: status.status_list.idx }, 201);
	}

	return jsonError(c, 400, "BAD_REQUEST", "secure must be data-integrity or sd-jwt-vc");
});

// POST /v1/credential-offers (OID4VCI pre-authorized-code flow, service-token-
// gated): an operator mints a credential offer bound to a subject/vct/claims.
// The wallet consumes the returned credential_offer (the pre_authorized_code).
v1.post("/credential-offers", async (c) => {
	const gate = checkIssuanceLicenseGate(c);
	if (gate) return gate;
	const body = (await c.req.json().catch(() => null)) as {
		subjectId?: string;
		vct?: string;
		claims?: Record<string, unknown>;
		selectivelyDisclosable?: string[];
		alg?: "EdDSA" | "ES256";
		holderJwk?: Record<string, string>;
		/** grantType: "pre-authorized_code" (default, operator-initiated, subject
		 * pre-bound) or "authorization_code" (wallet-initiated, subject established
		 * during the authorization step). */
		grantType?: "pre-authorized_code" | "authorization_code";
	} | null;
	if (!body || !body.vct) {
		return jsonError(c, 400, "BAD_REQUEST", "vct is required");
	}
	// Authorization-code grant: advertise the authorization_code grant; the
	// subject is NOT pre-bound (the wallet redirects the learner to
	// /oauth/authorize, where the learner authenticates). claims/alg are
	// resolved at the authorization step, not here.
	if (body.grantType === "authorization_code") {
		const result = createAuthorizationCodeCredentialOffer(ISSUER_URL, { vct: body.vct });
		return c.json(result.credential_offer, 201);
	}
	if (!body.subjectId || !body.claims) {
		return jsonError(c, 400, "BAD_REQUEST", "subjectId + claims are required for the pre-authorized_code grant");
	}
	const result = createCredentialOffer(ISSUER_URL, {
		subject: body.subjectId,
		vct: body.vct,
		claims: body.claims,
		...(body.selectivelyDisclosable ? { selectivelyDisclosable: body.selectivelyDisclosable } : {}),
		...(body.alg ? { alg: body.alg } : {}),
		...(body.holderJwk ? { holderJwk: body.holderJwk } : {}),
	});
	return c.json(result.credential_offer, 201);
});

// POST /v1/presentations/request (OpenID4VP verifier, service-token-gated):
// generate an openid4vp:// authorization request (a DCQL query for an SD-JWT VC
// by vct) + a verifier session (nonce/state). The wallet POSTs the vp_token to
// the response_uri (the receiver lands in 1.3).
v1.post("/presentations/request", async (c) => {
	const body = (await c.req.json().catch(() => null)) as {
		vct?: string;
		claims?: string[];
		clientId?: string;
		responseUri?: string;
		encrypted?: boolean;
		transport?: "openid4vp" | "dc_api" | "openid4vp-redirect";
		/** Sign the request (JAR) + use the x509_hash client-id scheme (HAIP §5). */
		signed?: boolean;
		/** Multi-credential DCQL: an array of credential queries (vct + claims). */
		credentials?: Array<{ vct: string; claims?: string[] }>;
	} | null;
	if (!body || (!body.vct && !body.credentials)) {
		return jsonError(c, 400, "BAD_REQUEST", "vct is required");
	}
	const result = (body.signed && body.vct)
		? createSignedAuthorizationRequest(ISSUER_URL, p256Key, {
			vct: body.vct,
			...(body.claims ? { claims: body.claims } : {}),
			...(body.clientId ? { clientId: body.clientId } : {}),
			...(body.responseUri ? { responseUri: body.responseUri } : {}),
		})
		: createAuthorizationRequest(ISSUER_URL, {
			...(body.vct ? { vct: body.vct } : {}),
			...(body.claims ? { claims: body.claims } : {}),
			...(body.clientId ? { clientId: body.clientId } : {}),
			...(body.responseUri ? { responseUri: body.responseUri } : {}),
			...(body.encrypted ? { encrypted: body.encrypted } : {}),
			...(body.transport ? { transport: body.transport } : {}),
		...(body.credentials ? { credentials: body.credentials } : {}),
		});
	return c.json(result, 201);
});

// POST /v1/dids/:did/publish — atomic 2-phase publish to all configured (or
// body-supplied) origins; 200 only on quorum confirm, 503 on quorum failure.
v1.post("/dids/:did/publish", async (c) => {
	const did = c.req.param("did");
	const stored = getDid(did);
	if (!stored) return jsonError(c, 404, "DID_NOT_FOUND", did + " is not in the local store (mint it first)");
	const body = (await c.req.json().catch(() => ({}))) as { origins?: string[] };
	const originList = body.origins && body.origins.length > 0 ? originListFromUrls(body.origins) : loadOriginsFromEnv();
	if (originList.origins.length === 0) {
		return jsonError(c, 400, "NO_ORIGINS", "no origins configured (set MNEURIX_DID_ORIGINS or pass origins in the body)");
	}
	const result = await publishDid(originList, did, stored.document);
	if (!result.staged) {
		return jsonError(c, 503, "PUBLISH_QUORUM_FAILED", `quorum ${originList.quorum} not met (${result.confirmed}/${originList.origins.length} origins confirmed)`, result);
	}
	setPublished(did, result.publishedTo, result.docHash);
	return c.json({ did, publishedTo: result.publishedTo, quorum: result.quorum, confirmed: result.confirmed, docHash: result.docHash });
});

// Wallet-integration test helper (GET /qr): mints an authorization_code
// credential offer server-side (no service token exposed to the browser) +
// renders a QR encoding the `openid-credential-offer://` URI for a wallet
// (AltMe, Talao) to scan. The wallet fetches the offer -> sees the
// authorization_code grant -> redirects the learner to /oauth/authorize ->
// consent -> code -> token -> credential. Intended for self-hosted wallet
// testing; the QR image is rendered by a public QR service (no client-side JS).
app.get("/qr", (c) => {
	const offer = createAuthorizationCodeCredentialOffer(ISSUER_URL, { vct: DEFAULT_VCT });
	const offerJson = JSON.stringify(offer.credential_offer);
	const offerUri = `openid-credential-offer://?credential_offer=${encodeURIComponent(offerJson)}`;
	const qrImg = `https://api.qrserver.com/v1/create-qr-code/?size=360x360&margin=0&data=${encodeURIComponent(offerUri)}`;
	const esc = (s: string): string => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
	return c.html(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(ISSUER_NAME)} — wallet test</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;max-width:520px;margin:32px auto;padding:0 16px;color:#0f172a;background:#f8fafc}
  h1{font-size:18px;margin:0 0 6px}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:20px;text-align:center}
  img{border:1px solid #e2e8f0;border-radius:8px;width:360px;height:360px}
  .muted{color:#64748b;font-size:13px;margin:14px 0 0}
  details{text-align:left;margin-top:16px;background:#f1f5f9;border-radius:8px;padding:10px}
  summary{cursor:pointer;font-weight:600;font-size:13px}
  code{display:block;word-break:break-all;font-size:11px;white-space:pre-wrap;margin-top:8px;color:#475569}
</style>
</head>
<body>
  <div class="card">
    <h1>${esc(ISSUER_NAME)}</h1>
    <p class="muted">Scan with a wallet (AltMe, Talao) to receive a verifiable credential via the OID4VCI authorization-code flow.</p>
    <img src="${qrImg}" alt="credential offer QR">
    <p class="muted">Issuer: <strong>${esc(ISSUER_URL)}</strong></p>
    <details><summary>Raw credential offer URI</summary><code>${esc(offerUri)}</code></details>
    <p class="muted">Refresh the page for a fresh offer. The flow: wallet fetches the offer -> /oauth/authorize -> consent -> code -> /oauth/token -> /credentials.</p>
  </div>
</body>
</html>`, 200);
});

// OID4VCI: OAuth 2.0 Authorization Server metadata (RFC 8414) — the
// pre-authorized-code grant + the token endpoint (wallet-facing, public).
// `authorization_endpoint` is advertised (pointing at /oauth/authorize) so that
// wallets that probe for it during discovery don't silently abort; the
// pre-authorized-code flow does not use it, but its absence has been observed to
// cause conformant wallets to stall after metadata fetch + fall back to a browser.
app.get("/.well-known/oauth-authorization-server", (c) => {
	return c.json({
		issuer: ISSUER_URL,
		authorization_endpoint: `${ISSUER_URL}/oauth/authorize`,
		token_endpoint: `${ISSUER_URL}/oauth/token`,
		token_endpoint_auth_methods_supported: ["none"],
		// Both OID4VCI grants are supported: the pre-authorized-code grant
		// (operator-initiated) + the authorization-code grant (wallet-initiated,
		// PKCE S256, per RFC 7636). Wallets that key on authorization_code (AltMe,
		// Talao for SD-JWT VC) use the latter.
		grant_types_supported: [
			"urn:ietf:params:oauth:grant-type:pre-authorized_code",
			"authorization_code",
		],
		response_types_supported: ["code"],
		code_challenge_methods_supported: ["S256"],
		response_mode_supported: ["query"],
		"pre-authorized_grant_anonymous_access_supported": true,
	});
});

// OID4VCI: credential-issuer metadata — the credential endpoint + the supported
// credential configurations (the default achievement vct, both SD-JWT VC format
// labels for wallet compat). Served at BOTH the current spec path
// `openid-credential-issuer` (draft-ietf-oauth-4-vc) and the older
// `oauth-credential-issuer` alias for wallet compatibility. AltMe and other
// conformant wallets fetch `openid-credential-issuer`; the older path is kept
// for verifiers/SDKs still on the earlier draft. `authorization_servers` points
// the wallet at this issuer's own oauth-authorization-server metadata for the
// token endpoint.
//
// FORMAT COMPAT: the SD-JWT VC format identifier was renamed `vc+sd-jwt` ->
// `dc+sd-jwt` in later drafts. Many wallets (AltMe, Talao) still key on
// `vc+sd-jwt` and silently abort if they cannot find a config with a format
// they recognise. We advertise BOTH: the primary config id (`<vct>`) uses
// `vc+sd-jwt` (wallet-friendly, referenced by default offers); a secondary
// config id (`<vct>#dc-sd-jwt`) advertises `dc+sd-jwt` for spec-latest clients.
// The credential endpoint returns the format matching the config id redeemed.
function credentialIssuerMetadata() {
	const base = {
		scope: "MneurixAchievement",
		cryptographic_binding_methods_supported: ["did:web", "jwk"],
		credential_signing_alg_values_supported: ["EdDSA", "ES256"],
		vct: DEFAULT_VCT,
	};
	return {
		credential_issuer: ISSUER_URL,
		credential_endpoint: `${ISSUER_URL}/credentials`,
		authorization_servers: [ISSUER_URL],
		credential_configurations_supported: {
			[DEFAULT_VCT]: { ...base, format: "vc+sd-jwt" },
			[`${DEFAULT_VCT}#dc-sd-jwt`]: { ...base, format: "dc+sd-jwt" },
		},
	};
}
app.get("/.well-known/openid-credential-issuer", (c) => c.json(credentialIssuerMetadata()));
app.get("/.well-known/oauth-credential-issuer", (c) => c.json(credentialIssuerMetadata()));

// OID4VCI authorization endpoint (wallet-initiated, GET — the wallet opens
// this in the learner's browser with a PKCE code_challenge + the credential
// configuration requested). When MNEURIX_LATTICE_AUTH_URL is set, the did-issuer
// DELEGATES learner authentication to the lattice (stores the pending request
// + 302-redirects to the lattice's auth endpoint); the lattice authenticates the
// learner + redirects back to /oauth/callback with a signed auth result. When
// unset, the did-issuer shows its own minimal consent page (the fallback).
function learnerSubject(learnerId: string): string {
	return `did:web:${ISSUER_HOST}:learners:${learnerId}`;
}
function minimalClaims(learnerId: string, vct: string): { claims: Record<string, unknown>; selectivelyDisclosable: string[] } {
	return { claims: { name: learnerId, achievement: vct, issuedAt: new Date().toISOString() }, selectivelyDisclosable: ["name", "achievement"] };
}
/** Strip the `#dc-sd-jwt` format-suffix alias from a credential_configuration_id
 * to get the canonical vct (the credential endpoint returns the format matching
 * the config id redeemed; the vct inside the SD-JWT VC is the canonical one). */
function vctFromConfigId(configId: string): string {
	return configId.replace(/#dc-sd-jwt$/, "");
}
app.get("/oauth/authorize", (c) => {
	const credentialConfigurationId = c.req.query("credential_configuration_id");
	const redirectUri = c.req.query("redirect_uri");
	const state = c.req.query("state");
	const codeChallenge = c.req.query("code_challenge");
	const codeChallengeMethod = c.req.query("code_challenge_method");
	const issuerState = c.req.query("issuer_state");
	if (!credentialConfigurationId || !redirectUri || !state || !codeChallenge) {
		return jsonError(c, 400, "INVALID_REQUEST", "credential_configuration_id, redirect_uri, state + code_challenge are required");
	}
	if (codeChallengeMethod !== "S256") {
		return jsonError(c, 400, "INVALID_REQUEST", "code_challenge_method must be S256");
	}
	const req = {
		credentialConfigurationId,
		vct: vctFromConfigId(credentialConfigurationId),
		redirectUri,
		state,
		codeChallenge,
		codeChallengeMethod: "S256" as const,
		...(issuerState ? { issuerState } : {}),
	};
	const lattice = latticeAuthUrl();
	if (lattice) {
		// Delegated path: store the pending request + redirect to the lattice.
		// The lattice authenticates the learner + redirects back to /oauth/callback
		// with pending_state + a signed auth_result (HS256 shared secret).
		const pendingState = cryptoRandomSecret();
		storePendingAuthRequest(pendingState, req);
		const cb = `${ISSUER_URL}/oauth/callback`;
		const dest = `${lattice}?callback=${encodeURIComponent(cb)}&pending_state=${encodeURIComponent(pendingState)}&state=${encodeURIComponent(state)}`;
		return c.redirect(dest, 302);
	}
	// Self-hosted fallback: render the minimal consent page.
	return c.html(consentPageHtml({
		credentialConfigurationId,
		redirectUri,
		state,
		codeChallenge,
		...(issuerState ? { issuerState } : {}),
		issuerName: ISSUER_NAME,
	}), 200);
});

// OID4VCI consent submit (self-hosted fallback, POST form). The learner confirms
// their identity on the consent page; the did-issuer issues a single-use
// authorization code bound to (PKCE challenge + the learner subject + the
// credential request) + 302-redirects the browser back to the wallet's
// redirect_uri with ?code=...&state=... The wallet then redeems the code + its
// PKCE verifier at /oauth/token.
app.post("/oauth/consent", async (c) => {
	const form = await c.req.parseBody().catch(() => null) as Record<string, string> | null;
	const learnerId = typeof form?.learnerId === "string" ? form.learnerId.trim() : "";
	const credentialConfigurationId = typeof form?.credential_configuration_id === "string" ? form.credential_configuration_id : "";
	const redirectUri = typeof form?.redirect_uri === "string" ? form.redirect_uri : "";
	const state = typeof form?.state === "string" ? form.state : "";
	const codeChallenge = typeof form?.code_challenge === "string" ? form.code_challenge : "";
	const issuerState = typeof form?.issuer_state === "string" ? form.issuer_state : undefined;
	if (!learnerId || !credentialConfigurationId || !redirectUri || !state || !codeChallenge) {
		return jsonError(c, 400, "INVALID_REQUEST", "learnerId, credential_configuration_id, redirect_uri, state + code_challenge are required");
	}
	const vct = vctFromConfigId(credentialConfigurationId);
	const { claims, selectivelyDisclosable } = minimalClaims(learnerId, vct);
	const issued = issueAuthorizationCode({
		credentialConfigurationId,
		vct,
		redirectUri,
		state,
		codeChallenge,
		codeChallengeMethod: "S256",
		...(issuerState ? { issuerState } : {}),
		subject: learnerSubject(learnerId),
		claims,
		selectivelyDisclosable,
		alg: "EdDSA",
	});
	const dest = `${redirectUri}?code=${encodeURIComponent(issued.code)}&state=${encodeURIComponent(issued.state)}`;
	return c.redirect(dest, 302);
});

// OID4VCI delegated-auth callback (the lattice redirects here after
// authenticating the learner). Receives pending_state + a signed auth_result
// (HS256 with MNEURIX_LATTICE_AUTH_SHARED_SECRET) carrying { learnerId, claims? }.
// Verifies the signature, looks up the pending request, issues the auth code,
// + 302-redirects to the wallet's redirect_uri. Fail-closed if delegation is
// unconfigured or the signature is invalid. (The lattice side of this contract is
// future work; the self-hosted fallback is the v1 deploy path.)
app.get("/oauth/callback", async (c) => {
	if (!latticeAuthUrl()) {
		return jsonError(c, 400, "DELEGATION_UNCONFIGURED", "MNEURIX_LATTICE_AUTH_URL is not set; the delegated callback is not available");
	}
	const pendingState = c.req.query("pending_state");
	const authResult = c.req.query("auth_result");
	const state = c.req.query("state");
	if (!pendingState || !authResult || !state) {
		return jsonError(c, 400, "INVALID_REQUEST", "pending_state, auth_result + state are required");
	}
	const secret = latticeAuthSharedSecret();
	if (!secret) {
		return jsonError(c, 500, "DELEGATION_MISCONFIGURED", "MNEURIX_LATTICE_AUTH_SHARED_SECRET is not set; cannot verify the lattice auth result");
	}
	const parsed = verifyHs256Jwt(authResult, secret) as { learnerId?: string; claims?: Record<string, unknown> } | null;
	if (!parsed || !parsed.learnerId) {
		return jsonError(c, 401, "UNAUTHORIZED", "auth_result signature invalid or learnerId missing");
	}
	const pending = takePendingAuthRequest(pendingState);
	if (!pending) {
		return jsonError(c, 400, "INVALID_REQUEST", "pending request not found or expired");
	}
	const { claims, selectivelyDisclosable } = parsed.claims
		? { claims: parsed.claims, selectivelyDisclosable: [] as string[] }
		: minimalClaims(parsed.learnerId, pending.vct);
	const issued = issueAuthorizationCode({
		credentialConfigurationId: pending.credentialConfigurationId,
		vct: pending.vct,
		redirectUri: pending.redirectUri,
		state,
		codeChallenge: pending.codeChallenge,
		codeChallengeMethod: "S256",
		...(pending.issuerState ? { issuerState: pending.issuerState } : {}),
		subject: learnerSubject(parsed.learnerId),
		claims,
		selectivelyDisclosable,
		alg: "EdDSA",
	});
	const dest = `${pending.redirectUri}?code=${encodeURIComponent(issued.code)}&state=${encodeURIComponent(state)}`;
	return c.redirect(dest, 302);
});

// OID4VCI token endpoint: redeem a pre-authorized_code OR an authorization_code
// for an access token. Both grants share the /credentials endpoint downstream.
app.post("/oauth/token", async (c) => {
	// M-3 fix: accept form-encoded (RFC 6749 §4.1.1) OR JSON (wallets may use either).
	let grantType: string | undefined;
	let preAuthorizedCode: string | undefined;
	let authCode: string | undefined;
	let codeVerifier: string | undefined;
	const ct = c.req.header("content-type") ?? "";
	if (ct.includes("application/json")) {
		const body = await c.req.json().catch(() => null) as {
			grant_type?: string; pre_authorized_code?: string; code?: string; code_verifier?: string;
		} | null;
		grantType = body?.grant_type;
		preAuthorizedCode = body?.pre_authorized_code;
		authCode = body?.code;
		codeVerifier = body?.code_verifier;
	} else {
		const form = await c.req.parseBody().catch(() => null) as Record<string, string | File> | null;
		const f = (k: string): string | undefined => (typeof form?.[k] === "string" ? form[k] as string : undefined);
		grantType = f("grant_type");
		preAuthorizedCode = f("pre_authorized_code");
		authCode = f("code");
		codeVerifier = f("code_verifier");
	}
	// Authorization-code grant (wallet-initiated, PKCE S256).
	if (grantType === "authorization_code") {
		if (!authCode || !codeVerifier) {
			return jsonError(c, 400, "INVALID_REQUEST", "grant_type=authorization_code requires code + code_verifier");
		}
		const exchanged = exchangeAuthorizationCode(authCode, codeVerifier);
		if (!exchanged.ok) {
			const msg = exchanged.error === "invalid_pkce" ? "PKCE verification failed" : "invalid or expired authorization code";
			return jsonError(c, 400, exchanged.error === "invalid_pkce" ? "INVALID_PKCE" : "INVALID_GRANT", msg);
		}
		const token = mintAccessTokenForCredentialRequest(exchanged.request);
		return c.json(token, 200, { "Cache-Control": "no-store", "Pragma": "no-cache" });
	}
	// Pre-authorized-code grant (operator-initiated).
	if (grantType !== "urn:ietf:params:oauth:grant-type:pre-authorized_code" || !preAuthorizedCode) {
		return jsonError(c, 400, "INVALID_REQUEST", "grant_type must be authorization_code or pre-authorized_code");
	}
	const result = exchangePreAuthorizedCode(preAuthorizedCode);
	if ("error" in result) return jsonError(c, 400, "INVALID_GRANT", result.error);
	// M-3 fix: RFC 6749 §5.1 requires Cache-Control: no-store on token responses.
	return c.json(result, 200, { "Cache-Control": "no-store", "Pragma": "no-cache" });
});

// OID4VCI credential endpoint: the wallet posts the Bearer access token +
// receives the SD-JWT VC. The access token is single-use + bound to the offer
// (subject/vct/claims/alg minted by the operator). No service token here.
app.post("/credentials", async (c) => {
	const gate = checkIssuanceLicenseGate(c);
	if (gate) return gate;
	const auth = c.req.header("authorization") ?? "";
	const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
	if (!token) return jsonError(c, 401, "UNAUTHORIZED", "missing Bearer access token");
	const offer = consumeAccessToken(token);
	if (!offer) return jsonError(c, 401, "UNAUTHORIZED", "invalid or expired access token");

	// M-2 fix: OID4VCI proof-of-possession. The wallet sends a proof JWT
	// (signed by its holder key, containing the c_nonce from the token response).
	// The issuer verifies the proof + extracts the holder key from it.
	const cNonce = getCNonceForToken(token);
	let holderJwk: Record<string, string> | undefined = offer.holderJwk;
	if (cNonce) {
		// A c_nonce was issued — the wallet MUST send a proof.
		const body = await c.req.json().catch(() => null) as { proof?: { jwt?: string; proof_type?: string } } | null;
		const proofJwt = body?.proof?.jwt;
		if (!proofJwt) {
			return jsonError(c, 400, "INVALID_REQUEST", "proof-of-possession required: send a proof.jwt containing the c_nonce");
		}
		const proofResult = await verifyProofAsync(proofJwt, cNonce);
		if (!proofResult.valid || !proofResult.holderJwk) {
			return jsonError(c, 401, "UNAUTHORIZED", "proof verification failed: invalid signature or nonce mismatch");
		}
		consumeCNonce(token); // single-use nonce
		holderJwk = proofResult.holderJwk; // use the wallet's key, not the operator's
	}

	const oidcStatusListId = offer.alg === "ES256" ? `${ISSUER_URL}/statuslists/revocation/1?alg=ES256` : `${ISSUER_URL}/statuslists/revocation/1`;
	const status = allocateSdJwtStatus(oidcStatusListId, "revocation", undefined);
	const iss = offer.alg === "ES256" ? ISSUER_URL : issuerDid;
	let result: Awaited<ReturnType<typeof issueSdJwtVc>>;
	try {
		result = await issueSdJwtVc({
			iss,
			sub: offer.subject,
			vct: offer.vct,
			claims: offer.claims,
			selectivelyDisclosable: offer.selectivelyDisclosable,
			...(holderJwk ? { holderJwk } : {}),
			status,
			verificationMethod: currentVerificationMethod(),
			alg: offer.alg,
		}, issuerKey, p256Key);
	} catch (e) {
		return jsonError(c, 502, "ISSUER_ERROR", `cannot issue credential: ${(e as Error).message}`);
	}
	return c.json({ format: offer.vct.endsWith("#dc-sd-jwt") ? "dc+sd-jwt" : "vc+sd-jwt", credential: result.credential }, 200, { "Cache-Control": "no-store", "Pragma": "no-cache" });
});

// OID4VP response receiver (POST /openid4vp/response, wallet-facing, public):
// the wallet POSTs the vp_token (SD-JWT VC + KB-JWT) + state (direct_post). The
// receiver binds the presentation to the verifier session (state + the KB-JWT
// nonce), then verifies the SD-JWT VC issuer signature + disclosures + the
// KB-JWT holder binding (reuses verifyPresentation). EdDSA/did:web path; the
// ES256/HTTPS-issuer verify path is a follow-up (fail-closed until then).
app.post("/openid4vp/response", async (c) => {
	const form = await c.req.parseBody();
	const rawVpToken = typeof form.vp_token === "string" ? form.vp_token : null;
	const state = typeof form.state === "string" ? form.state : null;
	if (!rawVpToken || !state) return jsonError(c, 400, "INVALID_REQUEST", "vp_token + state are required");
	// Multi-credential DCQL: vp_token is a JSON object keyed by query id (OID4VP §8.1);
	// a bare string is the single-credential case (N=1).
	let vpTokens: string[];
	const trimmed = rawVpToken.trim();
	if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
		try {
			const obj = JSON.parse(trimmed) as Record<string, unknown>;
			vpTokens = Object.values(obj).filter((v): v is string => typeof v === "string");
		} catch {
			vpTokens = [rawVpToken];
		}
	} else {
		vpTokens = [rawVpToken];
	}
	if (vpTokens.length === 0) return jsonError(c, 400, "INVALID_REQUEST", "no vp_token presentations");
	const nonce = peekKbJwtNonce(vpTokens[0]!);
	if (!nonce) return jsonError(c, 401, "UNAUTHORIZED", "no KB-JWT / holder binding");
	const session = resolveSession(state, nonce);
	if (!session) return jsonError(c, 401, "UNAUTHORIZED", "no matching verifier session (state/nonce)");
	consumeSession(state); // consume BEFORE the async verify (closes the concurrent-replay race; the wallet does not retry the same session)
	// H-1 fix: check the presented count matches the requested DCQL query count
	if (session.vcts.length > 0 && vpTokens.length !== session.vcts.length) {
		return jsonError(c, 401, "UNAUTHORIZED", `expected ${session.vcts.length} credential(s), received ${vpTokens.length}`);
	}
	let lastResult: { verified: boolean; subject?: string; issuer?: string; reason?: string; status: string } | undefined;
	for (const vpToken of vpTokens) {
		let r: { verified: boolean; subject?: string; issuer?: string; reason?: string; status: string };
		try {
			const issuerJwt = vpToken.split("~")[0]!;
			const hdr = JSON.parse(Buffer.from(issuerJwt.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { alg?: string };
			// H-1 fix: check the presented vct matches the requested DCQL vct
			const vcPayload = JSON.parse(Buffer.from(issuerJwt.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { vct?: string };
			if (session.vcts.length > 0 && (!vcPayload.vct || !session.vcts.includes(vcPayload.vct))) {
				return jsonError(c, 401, "UNAUTHORIZED", `credential vct "${vcPayload.vct ?? "(none)"}" does not match the requested type`);
			}
			r = hdr.alg === "ES256"
				? await verifyEs256Presentation(vpToken, p256Key, { requireKeyBinding: true, nonce: session.nonce, aud: session.clientId })
				: await verifyPresentation({ presentation: vpToken, requireKeyBinding: true, nonce: session.nonce, aud: session.clientId });
		} catch {
			return jsonError(c, 401, "UNAUTHORIZED", "malformed presentation");
		}
		if (!r.verified) return jsonError(c, 401, "UNAUTHORIZED", `presentation rejected: ${r.reason ?? r.status}`);
		lastResult = r;
	}
	return c.json({ verified: true, credentials: vpTokens.length, ...(lastResult?.subject ? { subject: lastResult.subject } : {}), ...(lastResult?.issuer ? { issuer: lastResult.issuer } : {}) }, 200);
});

// OID4VP encrypted response receiver (POST /openid4vp/response/:state, direct_post.jwt):
// the wallet POSTs response=<JWE> encrypted to the verifier's per-request ephemeral
// ECDH-ES key (advertised in the request client_metadata). The receiver looks up
// the session by the state in the path, decrypts the JWE (jose), parses the form
// (vp_token + state), verifies state matches the path, then verifies the SD-JWT VC
// + KB-JWT holder binding (same alg-dispatch as the unencrypted receiver).
app.post("/openid4vp/response/:state", async (c) => {
	const state = c.req.param("state");
	const session = getSessionByState(state);
	if (!session || session.consumed || !session.recipientPrivateKeyPem) return jsonError(c, 401, "UNAUTHORIZED", "no matching encrypted verifier session");
	consumeSession(state); // consume BEFORE the async decrypt/verify (closes the concurrent-replay race)
	const form = await c.req.parseBody();
	const jwe = typeof form.response === "string" ? form.response : null;
	if (!jwe) return jsonError(c, 400, "INVALID_REQUEST", "response (JWE) is required for direct_post.jwt");
	let plaintext: string;
	try {
		plaintext = await decryptResponse(jwe, session.recipientPrivateKeyPem);
	} catch {
		return jsonError(c, 401, "UNAUTHORIZED", "JWE decryption failed");
	}
	// The JWE plaintext is either a form (vp_token=...&state=...) OR a JARM
	// signed-JWT (a wallet-signed JWT whose payload carries vp_token + state + aud).
	let vpToken: string | null = null;
	let innerState: string | null = null;
	if (!plaintext.includes("=") && !plaintext.includes("&") && !plaintext.includes("~") && plaintext.split(".").length === 3) {
		// JARM signed-JWT layer (HAIP dc_api.jwt / direct_post.jwt JARM).
		try {
			const jarmHeader = JSON.parse(Buffer.from(plaintext.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { jwk?: Record<string, string> };
			if (!jarmHeader.jwk) return jsonError(c, 401, "UNAUTHORIZED", "JARM missing signing jwk");
			const jarm = await verifyJwsWithJwk(plaintext, jarmHeader.jwk);
			if (!jarm.valid) return jsonError(c, 401, "UNAUTHORIZED", "JARM signature invalid");
			const jp = (jarm.payload ?? {}) as { vp_token?: string; state?: string; aud?: string };
			vpToken = typeof jp.vp_token === "string" ? jp.vp_token : null;
			innerState = typeof jp.state === "string" ? jp.state : null;
			if (jp.aud !== session.clientId) return jsonError(c, 401, "UNAUTHORIZED", "JARM aud does not match the verifier client_id");
		} catch {
			return jsonError(c, 401, "UNAUTHORIZED", "malformed JARM response");
		}
	} else {
		const inner = new URLSearchParams(plaintext);
		vpToken = inner.get("vp_token");
		innerState = inner.get("state");
	}
	if (!vpToken || !innerState) return jsonError(c, 400, "INVALID_REQUEST", "decrypted response missing vp_token + state");
	if (innerState !== state) return jsonError(c, 401, "UNAUTHORIZED", "decrypted state does not match the response_uri state");
	// H-1 fix: the decrypted vp_token must match the session's requested vct
	const encIssuerJwt = vpToken.split("~")[0]!;
	const encPayload = JSON.parse(Buffer.from(encIssuerJwt.split(".")[1]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { vct?: string };
	if (session.vcts.length > 0 && (!encPayload.vct || !session.vcts.includes(encPayload.vct))) {
		return jsonError(c, 401, "UNAUTHORIZED", `credential vct "${encPayload.vct ?? "(none)"}" does not match the requested type`);
	}
	let result: { verified: boolean; subject?: string; issuer?: string; reason?: string; status: string };
	try {
		const issuerJwt = vpToken.split("~")[0]!;
		const hdr = JSON.parse(Buffer.from(issuerJwt.split(".")[0]!.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8")) as { alg?: string };
		result = hdr.alg === "ES256"
			? await verifyEs256Presentation(vpToken, p256Key, { requireKeyBinding: true, nonce: session.nonce, aud: session.clientId })
			: await verifyPresentation({ presentation: vpToken, requireKeyBinding: true, nonce: session.nonce, aud: session.clientId });
	} catch {
		return jsonError(c, 401, "UNAUTHORIZED", "malformed presentation");
	}
	if (!result.verified) return jsonError(c, 401, "UNAUTHORIZED", `presentation rejected: ${result.reason ?? result.status}`);
	return c.json({ verified: true, subject: result.subject, issuer: result.issuer }, 200);
});

// JAR: the signed Request Object is hosted at request_uri (the wallet fetches it
// via GET). Served as application/oauth-authz-req+jwt; the wallet verifies the
// ES256+x5c signature + uses the request params inside.
app.get("/openid4vp/request/:id", (c) => {
	const jwt = getRequestObject(c.req.param("id"));
	if (!jwt) return jsonError(c, 404, "NOT_FOUND", "no signed request object for that id");
	return c.body(jwt, 200, { "content-type": "application/oauth-authz-req+jwt" });
});

// M-11 fix: serve the claimed-https redirect URL (GET /openid4vp) that the
// openid4vp-redirect transport points at. A universal-links/app-links interceptor
// catches this URL + opens the wallet; without the interceptor, this route
// redirects to the openid4vp:// URI (same params) so a browser can still launch
// a registered wallet handler.
app.get("/openid4vp", (c) => {
	const params = new URLSearchParams(c.req.query());
	if (params.toString()) {
		return c.redirect(`openid4vp://?${params.toString()}`, 302);
	}
	return c.json({ error: "missing openid4vp parameters" }, 400);
});

app.route("/v1", v1);

const isMain =
	typeof process.argv[1] === "string" && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
	const port = Number(process.env.DID_ISSUER_PORT ?? 7004);
	serve({ fetch: app.fetch, port }, (info) => console.log("did-issuer on :" + info.port));
}
