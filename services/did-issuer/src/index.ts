// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { pathToFileURL } from "node:url";
import { requireServiceToken } from "./serviceAuth";
import { jsonError } from "./errors";
import { openApiDoc } from "./openapi";
import { buildDidDocument, buildDidDocumentMulti, originFromDid, didFor, didHash, publicKeyJwkFromPem, type DidMethod } from "./did";
import { loadOrCreateIssuerKey, rotateIssuerKey, getKeyByKid, knownKids, loadOrCreateP256IssuerKey } from "./keys";
import { putDid, getDid, setPublished } from "./store";
import { loadOriginsFromEnv, originListFromUrls } from "./origins";
import { resolveDid } from "./resolve";
import { publishDid } from "./publish";
import { randomUUID } from "node:crypto";
import { issueOb3 } from "./vc-issue";
import { issueSdJwtVc, signIssuerJwt } from "./sdjwt";
import { allocateOb3Status, allocateSdJwtStatus, getCredentialStatus, getEncodedStatusList } from "./status";
import { createCredentialOffer, exchangePreAuthorizedCode, consumeAccessToken } from "./oid4vci";
import { revokeKid } from "./revoked-kids";
import { requireOperator } from "./operatorAuth";
import { verifyPresentation } from "./vc-verify";
import type { Achievement, BadgeEvidence, StatusPurpose } from "@mneurix/shared";
import { assertRestEncryptionInProd } from "@mneurix/shared";

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
const ISSUER_NAME = process.env.MNEURIX_ISSUER_NAME ?? "Mneurix";
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
// CISO encryption-at-rest enforcement (T4): refuse to boot in prod without
// MNEURIX_REST_ENCRYPTION=attested or =app-dek.
assertRestEncryptionInProd();
app.get("/health", (c) => c.json({ status: "ok", service: "did-issuer" }));
app.get("/v1/openapi.json", (c) => c.json(openApiDoc));

// Public did:web well-known (canonical origin).
app.get("/.well-known/did.json", (c) => {
	const { did, document } = mintFor(ISSUER_ORIGIN);
	return c.json({ ...document, alsoKnownAs: [did] });
});

// Public SD-JWT VC issuer metadata (draft-ietf-oauth-sd-jwt-vc §3): the issuer
// origin + the issuer Ed25519 JWK (with kid + alg) for key discovery.
// Default vct for Mneurix achievement credentials (the vct definition is
// served at GET /vct/:name). Caller-supplied vcts are still accepted at
// issuance; this advertises the default for wallet/verifier discovery.
const DEFAULT_VCT = `${ISSUER_URL}/vct/achievement`;

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
				{ ...p256Key.jwk, kid: p256Key.kid, alg: "ES256" },
			],
		},
		vct_values: [DEFAULT_VCT],
	});
});

// SD-JWT VC vct type metadata: the definition for a vct value. v1 serves a
// minimal definition for the default achievement vct; the full per-achievement-
// type vct taxonomy is a follow-up.
app.get("/vct/:name", (c) => {
	const name = c.req.param("name");
	if (name !== "achievement") return c.json({ error: "unknown vct" }, 404);
	return c.json({
		vct: DEFAULT_VCT,
		name: "Mneurix Achievement",
		description: "A verifiable achievement/competency credential issued by Mneurix.",
		claims: {},
	});
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
	const uri = `${ISSUER_URL}/statuslists/${purpose}/${c.req.param("id")}`;
	const payload = {
		sub: uri,
		iat: Math.floor(Date.now() / 1000),
		status_list: { bits: 1, vals: getEncodedStatusList(purpose) },
	};
	const jwt = await signIssuerJwt(payload, issuerKey, issuerKey.kid, "statuslist+jwt");
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

	// Tombstone the old kid (signed by the NEW key) + flip the module issuer key.
	await revokeKid(oldKid, newKey, `${did}#${newKey.kid}`);
	issuerKey = newKey;
	putDid(did, document, newKey.kid);
	if (publishedTo.length > 0) setPublished(did, publishedTo, didHash(document));
	return c.json({ did, newKid: newKey.kid, tombstonedKid: oldKid, publishedTo, docHash: didHash(document) });
});

// POST /v1/dids/:did/keys:revoke — tombstone a kid + remove it from the DID doc;
// republish atomically (operator-auth). Body: { kid?: string } (defaults to current).
v1.post("/dids/:did/keys:revoke", requireOperator(["revoker"]), async (c) => {
	const did = c.req.param("did");
	const stored = getDid(did);
	if (!stored) return jsonError(c, 404, "DID_NOT_FOUND", did + " is not in the local store (mint it first)");
	const body = (await c.req.json().catch(() => ({}))) as { kid?: string };
	const kid = body.kid ?? stored.kid;
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
	putDid(did, document, stored.kid);
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
	const result = await verifyPresentation({
		presentation: body.presentation as Parameters<typeof verifyPresentation>[0]["presentation"],
		...(body.requireKeyBinding ? { requireKeyBinding: body.requireKeyBinding } : {}),
		...(body.nonce ? { nonce: body.nonce } : {}),
		...(body.aud ? { aud: body.aud } : {}),
	});
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
	const statusListId = `${ISSUER_URL}/statuslists/revocation/1`;

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
		const result = await issueSdJwtVc({
			iss: issuerDid,
			sub: body.subjectId,
			vct: body.vct,
			claims: body.claims,
			selectivelyDisclosable,
			...(body.holderJwk ? { holderJwk: body.holderJwk } : {}),
			status,
			verificationMethod: currentVerificationMethod(),
			...(body.alg ? { alg: body.alg } : {}),
		}, issuerKey, p256Key);
		return c.json({ credential: result.credential, format: "dc+sd-jwt", statusIndex: status.status_list.idx }, 201);
	}

	return jsonError(c, 400, "BAD_REQUEST", "secure must be data-integrity or sd-jwt-vc");
});

// POST /v1/credential-offers (OID4VCI pre-authorized-code flow, service-token-
// gated): an operator mints a credential offer bound to a subject/vct/claims.
// The wallet consumes the returned credential_offer (the pre_authorized_code).
v1.post("/credential-offers", async (c) => {
	const body = (await c.req.json().catch(() => null)) as {
		subjectId?: string;
		vct?: string;
		claims?: Record<string, unknown>;
		selectivelyDisclosable?: string[];
		alg?: "EdDSA" | "ES256";
		holderJwk?: Record<string, string>;
	} | null;
	if (!body || !body.subjectId || !body.vct || !body.claims) {
		return jsonError(c, 400, "BAD_REQUEST", "subjectId, vct, and claims are required");
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

// OID4VCI: OAuth 2.0 Authorization Server metadata (RFC 8414) — the
// pre-authorized-code grant + the token endpoint (wallet-facing, public).
app.get("/.well-known/oauth-authorization-server", (c) => {
	return c.json({
		issuer: ISSUER_URL,
		token_endpoint: `${ISSUER_URL}/oauth/token`,
		token_endpoint_auth_methods_supported: ["none"],
		grant_types_supported: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
		"pre-authorized_grant_anonymous_access_supported": true,
	});
});

// OID4VCI: credential-issuer metadata — the credential endpoint + the supported
// credential configurations (the default achievement vct, dc+sd-jwt, both algs).
app.get("/.well-known/oauth-credential-issuer", (c) => {
	return c.json({
		credential_issuer: ISSUER_URL,
		credential_endpoint: `${ISSUER_URL}/credentials`,
		credential_configurations_supported: {
			[DEFAULT_VCT]: {
				format: "dc+sd-jwt",
				scope: "MneurixAchievement",
				cryptographic_binding_methods_supported: ["did:web", "jwk"],
				credential_signing_alg_values_supported: ["EdDSA", "ES256"],
				vct: DEFAULT_VCT,
			},
		},
	});
});

// OID4VCI token endpoint: redeem a pre-authorized_code for an access token.
app.post("/oauth/token", async (c) => {
	const body = (await c.req.json().catch(() => null)) as {
		grant_type?: string;
		pre_authorized_code?: string;
	} | null;
	if (!body || body.grant_type !== "urn:ietf:params:oauth:grant-type:pre-authorized_code" || !body.pre_authorized_code) {
		return jsonError(c, 400, "INVALID_REQUEST", "grant_type must be pre-authorized_code + pre_authorized_code required");
	}
	const result = exchangePreAuthorizedCode(body.pre_authorized_code);
	if ("error" in result) return jsonError(c, 400, "INVALID_GRANT", result.error);
	return c.json(result, 200);
});

// OID4VCI credential endpoint: the wallet posts the Bearer access token +
// receives the SD-JWT VC. The access token is single-use + bound to the offer
// (subject/vct/claims/alg minted by the operator). No service token here.
app.post("/credentials", async (c) => {
	const auth = c.req.header("authorization") ?? "";
	const token = auth.startsWith("Bearer ") ? auth.slice(7) : null;
	if (!token) return jsonError(c, 401, "UNAUTHORIZED", "missing Bearer access token");
	const offer = consumeAccessToken(token);
	if (!offer) return jsonError(c, 401, "UNAUTHORIZED", "invalid or expired access token");
	const status = allocateSdJwtStatus(`${ISSUER_URL}/statuslists/revocation/1`, "revocation", undefined);
	const iss = offer.alg === "ES256" ? ISSUER_URL : issuerDid;
	const result = await issueSdJwtVc({
		iss,
		sub: offer.subject,
		vct: offer.vct,
		claims: offer.claims,
		selectivelyDisclosable: offer.selectivelyDisclosable,
		...(offer.holderJwk ? { holderJwk: offer.holderJwk } : {}),
		status,
		verificationMethod: currentVerificationMethod(),
		alg: offer.alg,
	}, issuerKey, p256Key);
	return c.json({ format: "dc+sd-jwt", credential: result.credential }, 200);
});

app.route("/v1", v1);

const isMain =
	typeof process.argv[1] === "string" && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
	const port = Number(process.env.DID_ISSUER_PORT ?? 7004);
	serve({ fetch: app.fetch, port }, (info) => console.log("did-issuer on :" + info.port));
}
