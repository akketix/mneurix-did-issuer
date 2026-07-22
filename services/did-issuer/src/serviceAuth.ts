/**
 * services/credential/src/serviceAuth.ts — R19-style service-to-service auth
 * for the credential service. The `/issue` route is called only by trusted
 * internal services (the api service after a council grade, the progression
 * service on a micro-badge mastery mint, the review-queue on a human-review
 * approve). Those callers present a shared secret in the
 * `x-mneurix-service-token` header; this middleware enforces it in constant
 * time.
 *
 * CISO scan F1: `/issue` previously minted Ed25519-signed Open Badges from
 * attacker-supplied scores with NO auth — total academic-integrity collapse.
 * This gate closes that: an unauthenticated actor can no longer call `/issue`.
 *
 * Config (env): `MNEURIX_CREDENTIAL_SERVICE_TOKEN` — shared secret. Defaults
 * to `dev-credential-token` for local dev (matches the api + progression
 * default); the credential service refuses to boot in production if the
 * default is used (see the boot guard in `index.ts`).
 *
 * Purity: `@mneurix/shared/operator` (constantTimeEqual) + Hono.
 */
import type { MiddlewareHandler } from "hono";
import { constantTimeEqual } from "@mneurix/shared";

/** Hono middleware: require the `x-mneurix-service-token` header to equal
 * `expected` (constant-time compare). 401 on missing/invalid. */
export function requireServiceToken(
	expected: string,
): MiddlewareHandler {
	return async (c, next) => {
		const got = c.req.header("x-mneurix-service-token") ?? "";
		if (!got || !constantTimeEqual(got, expected)) {
			return c.json({ error: "missing/invalid service token" }, 401);
		}
		await next();
	};
}