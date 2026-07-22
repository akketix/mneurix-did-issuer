import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { pathToFileURL } from "node:url";
import { requireServiceToken } from "./serviceAuth";
import { jsonError } from "./errors";
import { openApiDoc } from "./openapi";
import { buildDidDocument, didFor, publicKeyJwkFromPem } from "./did";
import { loadOrCreateIssuerKey } from "./keys";
import { putDid, getDid } from "./store";

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

// GET /v1/dids/:did — resolve (M3: local store; M4 adds multi-origin fan-out).
v1.get("/dids/:did", (c) => {
	const did = c.req.param("did");
	const stored = getDid(did);
	if (!stored) return jsonError(c, 404, "DID_NOT_FOUND", did + " not in the local store (mint it, or see M4 for multi-origin resolution)");
	return c.json({ did, document: stored.document, resolvedFrom: ["local"], docHash: "", verified: true });
});

// The remaining v1 endpoints (VC issue, presentations:verify, keys:rotate/revoke,
// credentials status, publish) stay stubbed until M5/M6.
const notImpl = (path: string) => (c: import("hono").Context) =>
	jsonError(c, 501, "NOT_IMPLEMENTED", path + " is declared in the v1 contract but not implemented in M3 (see M5/M6).");
v1.post("/vcs:issue", notImpl("/v1/vcs:issue"));
v1.post("/presentations:verify", notImpl("/v1/presentations:verify"));
v1.post("/dids/:did/keys:rotate", notImpl("/v1/dids/:did/keys:rotate"));
v1.post("/dids/:did/keys:revoke", notImpl("/v1/dids/:did/keys:revoke"));
v1.get("/credentials/:id/status", notImpl("/v1/credentials/:id/status"));
v1.post("/dids/:did/publish", notImpl("/v1/dids/:did/publish"));

app.route("/v1", v1);

const isMain =
	typeof process.argv[1] === "string" && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
	const port = Number(process.env.DID_ISSUER_PORT ?? 7004);
	serve({ fetch: app.fetch, port }, (info) => console.log("did-issuer on :" + info.port));
}
