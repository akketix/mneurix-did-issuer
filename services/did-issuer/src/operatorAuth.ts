// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Operator-auth middleware for the did-issuer (M6) — governance acts
 * (rotate / revoke) require an operator role, mirroring the lattice's
 * `services/credential/src/operatorAuth.ts` over `@mneurix/shared/operator`.
 *
 * Reads `MNEURIX_OPERATORS` PER REQUEST (not at route-setup time) so tests can
 * set the env after import. Dev fallback: when no operators are configured
 * (empty env), the service token alone (enforced router-wide) suffices —
 * matching the lattice's `MNEURIX_REVOCATION_ENABLED` gating pattern.
 *
 * Header: `authorization: Bearer <operatorToken>`. Purity: @mneurix/shared. */
import type { MiddlewareHandler } from "hono";
import { type Operator, loadOperators, operatorByToken } from "@mneurix/shared";

export function requireOperator(roles: string[]): MiddlewareHandler<{ Variables: { operator: Operator | { id: string; roles: string[] } } }> {
	return async (c, next) => {
		const operators = loadOperators(); // per-request env read
		if (operators.length === 0) {
			// Dev fallback: no operators configured — the router-wide service
			// token already authenticated the caller; allow with a synthetic operator.
			c.set("operator", { id: "dev", roles });
			await next();
			return;
		}
		const auth = c.req.header("authorization") ?? "";
		const m = auth.match(/^Bearer\s+(.+)$/i);
		if (!m) return c.json({ error: "missing operator bearer token" }, 401);
		const op = operatorByToken(m[1]!, operators);
		if (!op) return c.json({ error: "invalid operator token" }, 401);
		if (!roles.some((r) => op.roles.includes(r))) {
			return c.json({ error: `operator ${op.id} lacks role [${roles.join("|")}]` }, 403);
		}
		c.set("operator", op);
		await next();
	};
}