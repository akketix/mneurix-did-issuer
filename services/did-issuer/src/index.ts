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

// The remaining v1 endpoints (VC issue, presentations:verify, keys:rotate/revoke,
// credentials status) stay stubbed until M5/M6. Publish is implemented in M4.
const notImpl = (path: string) => (c: import("hono").Context) =>
	jsonError(c, 501, "NOT_IMPLEMENTED", path + " is declared in the v1 contract but not implemented in this milestone (see M5/M6).");
v1.post("/vcs:issue", notImpl("/v1/vcs:issue"));
v1.post("/presentations:verify", notImpl("/v1/presentations:verify"));
v1.post("/dids/:did/keys:rotate", notImpl("/v1/dids/:did/keys:rotate"));
v1.post("/dids/:did/keys:revoke", notImpl("/v1/dids/:did/keys:revoke"));
v1.get("/credentials/:id/status", notImpl("/v1/credentials/:id/status"));

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
