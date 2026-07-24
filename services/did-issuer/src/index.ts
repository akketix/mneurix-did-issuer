import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { pathToFileURL } from "node:url";
import { requireServiceToken } from "./serviceAuth";
import { jsonError } from "./errors";
import { openApiDoc } from "./openapi";
import { buildDidDocument, didFor, didHash, publicKeyJwkFromPem } from "./did";
import { loadOrCreateIssuerKey } from "./keys";
import { putDid, getDid, setPublished } from "./store";
import { loadOriginsFromEnv, originListFromUrls } from "./origins";
import { resolveDid } from "./resolve";
import { publishDid } from "./publish";
import { randomUUID } from "node:crypto";
import { issueOb3 } from "./vc-issue";
import { issueSdJwtVc } from "./sdjwt";
import { allocateOb3Status, allocateSdJwtStatus } from "./status";
import type { Achievement, BadgeEvidence } from "@mneurix/shared";

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
const issuerKey = loadOrCreateIssuerKey(process.env.MNEURIX_KEY_DIR);
const ISSUER_URL = (process.env.MNEURIX_DID_ISSUER_URL ?? "https://did-issuer.mneurix.example").replace(/\/+$/, "");
const ISSUER_NAME = process.env.MNEURIX_ISSUER_NAME ?? "Mneurix";
const issuerDid = didFor(ISSUER_ORIGIN);
const verificationMethod = `${issuerDid}#${issuerKey.kid}`;

function mintFor(origin: string): { did: string; document: ReturnType<typeof buildDidDocument> } {
	const jwk = publicKeyJwkFromPem(issuerKey.publicKeyPem);
	const document = buildDidDocument(origin, issuerKey.kid, jwk);
	const did = didFor(origin);
	putDid(did, document, issuerKey.kid);
	return { did, document };
}

export const app = new Hono();
app.get("/health", (c) => c.json({ status: "ok", service: "did-issuer" }));
app.get("/v1/openapi.json", (c) => c.json(openApiDoc));

// Public did:web well-known (canonical origin).
app.get("/.well-known/did.json", (c) => {
	const { did, document } = mintFor(ISSUER_ORIGIN);
	return c.json({ ...document, alsoKnownAs: [did] });
});

// Public SD-JWT VC issuer metadata (draft-ietf-oauth-sd-jwt-vc §3): the issuer
// origin + the issuer Ed25519 JWK (with kid + alg) for key discovery.
app.get("/.well-known/jwt-vc-issuer", (c) => {
	const jwk = publicKeyJwkFromPem(issuerKey.publicKeyPem);
	return c.json({ issuer: ISSUER_URL, jwks: { keys: [{ ...jwk, kid: issuerKey.kid, alg: "EdDSA" }] } });
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

// The remaining v1 endpoints (presentations:verify, keys:rotate/revoke,
// credentials status) stay stubbed until M6. VC issue + publish are live (M5/M4).
const notImpl = (path: string) => (c: import("hono").Context) =>
	jsonError(c, 501, "NOT_IMPLEMENTED", path + " is declared in the v1 contract but not implemented in this milestone (see M6).");
v1.post("/presentations:verify", notImpl("/v1/presentations:verify"));
v1.post("/dids/:did/keys:rotate", notImpl("/v1/dids/:did/keys:rotate"));
v1.post("/dids/:did/keys:revoke", notImpl("/v1/dids/:did/keys:revoke"));
v1.get("/credentials/:id/status", notImpl("/v1/credentials/:id/status"));

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
		const credentialStatus = allocateOb3Status(statusListId);
		const issuer = { id: issuerDid, type: ["Profile"], name: ISSUER_NAME };
		const credential = await issueOb3(body.subjectId, body.achievement, body.evidence, issuer, issuerKey, verificationMethod, credentialId, credentialStatus);
		return c.json({ credential, format: "ob3", statusIndex: credentialStatus.statusListIndex }, 201);
	}

	if (body.secure === "sd-jwt-vc") {
		if (!body.vct || !body.claims) {
			return jsonError(c, 400, "BAD_REQUEST", "sd-jwt-vc issue requires vct + claims");
		}
		const selectivelyDisclosable = body.selectivelyDisclosable ?? [];
		const status = allocateSdJwtStatus(statusListId);
		const result = await issueSdJwtVc({
			iss: issuerDid,
			sub: body.subjectId,
			vct: body.vct,
			claims: body.claims,
			selectivelyDisclosable,
			...(body.holderJwk ? { holderJwk: body.holderJwk } : {}),
			status,
			verificationMethod,
		}, issuerKey);
		return c.json({ credential: result.credential, format: "dc+sd-jwt", statusIndex: status.statusListIndex }, 201);
	}

	return jsonError(c, 400, "BAD_REQUEST", "secure must be data-integrity or sd-jwt-vc");
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

app.route("/v1", v1);

const isMain =
	typeof process.argv[1] === "string" && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
	const port = Number(process.env.DID_ISSUER_PORT ?? 7004);
	serve({ fetch: app.fetch, port }, (info) => console.log("did-issuer on :" + info.port));
}
