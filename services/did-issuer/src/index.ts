import { Hono } from "hono";
import { serve } from "@hono/node-server";
import { pathToFileURL } from "node:url";

/**
 * mneurix-did-issuer — HTTP service (M0 scaffold).
 *
 * /health is the only route in M0; the /v1 API surface + OpenAPI land in M1+
 * (see .agents/plans/split-did-proctoring in the lattice repo). The service-token
 * boot guard (CISO F2/F34 pattern, mirrored from the lattice credential service)
 * refuses the dev default in production. The PlatformLicense boot guard is
 * wired in M9; @mneurix/licensing is lifted + present but not yet invoked.
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

// TODO(M1): /v1 endpoints + OpenAPI 3.1 at /v1/openapi.json + x-mneurix-service-token gating.

const isMain =
	typeof process.argv[1] === "string" &&
	import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
	const port = Number(process.env.DID_ISSUER_PORT ?? 7004);
	serve({ fetch: app.fetch, port }, (info) =>
		console.log("did-issuer on :" + info.port),
	);
}
