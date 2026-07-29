// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/**
 * services/did-issuer/src/serviceAuth.ts — R19-style service-to-service auth
 * for the did-issuer service. The mutation routes (/v1/vcs:issue, key
 * rotate/revoke, publish) are called only by trusted internal callers, which
 * present a shared secret in the `x-mneurix-service-token` header; this
 * middleware enforces it in constant time.
 *
 * Config (env): `MNEURIX_DID_ISSUER_SERVICE_TOKEN` — shared secret. Defaults
 * to `dev-did-issuer-token` for local dev; the did-issuer refuses to boot in
 * production if the default is used (see the boot guard in `index.ts`).
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