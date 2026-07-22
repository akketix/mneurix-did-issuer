/**
 * @mneurix/shared/operator — v1 operator identity, role + two-person logic.
 *
 * Pure (no Hono) so both the API service and the credential service share one
 * implementation of the operator table, constant-time token compare, the
 * two-person distinct-id rule, and the revocation boot quorum. Each service
 * keeps a thin Hono `operatorAuth` middleware wrapper that calls these helpers.
 *
 * Config (env, shared by all governance-bearing services):
 *   MNEURIX_OPERATORS=alice:revoker+appealsReviewer:<token>,bob:publisher:<token>
 *     entries are `id:roles:token`, comma-separated; roles are `+`-joined;
 *     the token may contain colons (everything after the 2nd colon).
 *   MNEURIX_REVOCATION_ENABLED=true  — activates the two-person boot gate.
 *
 * Purity: self-built on node:crypto (constant-time compare); no new deps.
 */
import { timingSafeEqual } from "node:crypto";

export interface Operator {
	id: string;
	roles: string[];
	token: string;
	/** Optional OIDC identity this operator is bound to (admin OIDC sessions). */
	oidcIssuer?: string;
	oidcSub?: string;
}

/** Parse MNEURIX_OPERATORS=id:roles:token,... (roles '+'-separated). */
export function loadOperators(): Operator[] {
	const raw = process.env.MNEURIX_OPERATORS ?? "";
	return raw
		.split(",")
		.map((s) => s.trim())
		.filter(Boolean)
		.map((entry) => {
			const parts = entry.split(":");
			if (parts.length < 3) {
				throw new Error(
					`MNEURIX_OPERATORS: malformed entry "${entry}" (expected id:roles:token)`,
				);
			}
			const id = parts[0]!;
			const rolesStr = parts[1]!;
			const token = parts.slice(2).join(":"); // token may contain colons
			const roles = rolesStr
				.split("+")
				.map((r) => r.trim())
				.filter(Boolean);
			return { id, roles, token } satisfies Operator;
		});
}

/** Constant-time string equality. */
export function constantTimeEqual(a: string, b: string): boolean {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	return ab.length === bb.length && timingSafeEqual(ab, bb);
}

/** Look up an operator by its bearer token (constant-time compare). */
export function operatorByToken(
	token: string,
	operators: Operator[] = loadOperators(),
): Operator | undefined {
	return operators.find((o) => constantTimeEqual(o.token, token));
}

/** Look up an operator bound to a specific OIDC identity. */
export function operatorByOidc(
	issuer: string,
	sub: string,
	operators: Operator[] = loadOperators(),
): Operator | undefined {
	return operators.find((o) => o.oidcIssuer === issuer && o.oidcSub === sub);
}

/**
 * Two-person rule: the counter-signer MUST be a different operator id than the
 * original actor. Both ids are recorded in the audit record.
 */
export function assertDistinctOperator(a: string, b: string): void {
	if (a === b) {
		throw new Error(
			`two-person rule violated: counter-signer must differ from the original operator (both "${a}")`,
		);
	}
}

/**
 * Boot gate: when revocation verbs are enabled (MNEURIX_REVOCATION_ENABLED=true)
 * and fewer than 2 distinct operator ids are configured, refuse to boot —
 * otherwise misconduct / key-compromise revocation silently degrades to
 * single-person.
 */
export function assertTwoPersonQuorum(
	operators: Operator[] = loadOperators(),
): void {
	if (process.env.MNEURIX_REVOCATION_ENABLED !== "true") return;
	const distinctIds = new Set(operators.map((o) => o.id));
	if (distinctIds.size < 2) {
		throw new Error(
			`MNEURIX_REVOCATION_ENABLED=true requires >=2 distinct operator ids in MNEURIX_OPERATORS (found ${distinctIds.size}); two-person revocation cannot be enforced.`,
		);
	}
}
