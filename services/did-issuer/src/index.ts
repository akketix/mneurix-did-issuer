import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { pathToFileURL } from "node:url";
import { requireServiceToken } from "./serviceAuth";
import { jsonError } from "./errors";
import { openApiDoc } from "./openapi";

/**
 * mneurix-did-issuer — HTTP service (M1 contract layer).
 *
 * Public: GET /health, GET /v1/openapi.json (+ the did:web well-known routes on the
 * DID issuer). The /v1 surface is gated by x-mneurix-service-token (constant-time
 * compare, prod boot-guarded). Endpoint handlers are stubs (501) in M1; the real
 * engines land in M2 (proctoring) / M3-M6 (DID issuance). The PlatformLicense
 * boot guard is wired in M9.
 */
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

export const app = new Hono();
app.get("/health", (c) => c.json({ status: "ok", service: "did-issuer" }));
app.get("/v1/openapi.json", (c) => c.json(openApiDoc));
	app.get("/.well-known/did.json", (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "did:web document + multi-cloud publish land in M3/M4."),
	);
	app.get("/.well-known/jwt-vc-issuer", (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "SD-JWT VC issuer metadata lands in M5."),
	);

// /v1 contract — service-token-gated stubs (M1). Real handlers: M2/M5.
	app.post("/v1/dids", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/dids" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);
	app.get("/v1/dids/{did}", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/dids/{did}" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);
	app.post("/v1/vcs:issue", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/vcs:issue" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);
	app.post("/v1/presentations:verify", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/presentations:verify" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);
	app.post("/v1/dids/{did}/keys:rotate", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/dids/{did}/keys:rotate" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);
	app.post("/v1/dids/{did}/keys:revoke", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/dids/{did}/keys:revoke" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);
	app.get("/v1/credentials/{id}/status", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/credentials/{id}/status" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);
	app.post("/v1/dids/{did}/publish", requireServiceToken(SERVICE_TOKEN), (c) =>
		jsonError(c, 501, "NOT_IMPLEMENTED", "/v1/dids/{did}/publish" + " is declared in the v1 contract but not implemented in M1 (see M2/M5)."),
	);

const isMain =
	typeof process.argv[1] === "string" &&
	import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
	const port = Number(process.env.DID_ISSUER_PORT ?? 7004);
	serve({ fetch: app.fetch, port }, (info) =>
		console.log("did-issuer on :" + info.port),
	);
}
