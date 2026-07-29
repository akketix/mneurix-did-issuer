// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/** Canonical error shape (both services): { error: { code, message, details? } }.
 * Mirrors the split-did-proctoring plan §Cross-cutting "API conventions". */
import type { Context } from "hono";

export interface ErrorBody {
	error: { code: string; message: string; details?: unknown };
}

/** Respond with the canonical error shape. */
export function jsonError(
	c: Context,
	status: number,
	code: string,
	message: string,
	details?: unknown,
): Response {
	const body: ErrorBody = {
		error: { code, message, ...(details !== undefined ? { details } : {}) },
	};
	return c.json(body, status as never);
}
