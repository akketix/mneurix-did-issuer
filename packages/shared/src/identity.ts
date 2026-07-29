// Copyright (c) 2026 Mneurix. Licensed under the Elastic License 2.0 (ELv2) — see LICENSE.
// You may not remove or circumvent license keys, or re-host this as a managed service.

/**
 * @mneurix/shared/identity — liveness/face-match plug-in interface (G-ID-1,
 * the "person half" of identity: "is the person at the keyboard the account?").
 *
 * The account half is closed by the OIDC BFF (oidc.ts). This module closes the
 * STRUCTURAL gap the policy named — the `IdentityProvider`/liveness plug-in
 * point was unimplemented. It ships:
 *  - the `LivenessProvider` interface,
 *  - a `LivenessAttestation` shape (P-SEC-10: any liveness SDK's outputs MUST
 *    be cryptographically attested and bound into the credential),
 *  - a `NoOpLivenessProvider` dev default so `identityVerified` stays false
 *    (P-PRIV-02: no learner may be falsely flagged as liveness-verified).
 *
 * A real face-match engine is a DEPLOY-TIME plug-in (a self-hosted face-match
 * service, or Keycloak's liveness authentication flow) selected by
 * `MNEURIX_LIVENESS_PROVIDER`. The plug-in returns a passing result ONLY with
 * a valid attestation; until such a provider is configured, `identityVerified`
 * is false and credentials bind to the account identity alone (P-PRIV-02).
 *
 * Purity: zod + node:crypto only; no ML/SDK deps.
 */
import { z } from "zod";

/** ISO-8601 with offset (defined locally to avoid a barrel import cycle). */
const IsoTimestampSchema = z.string().datetime({ offset: true });

/** A provider's signed proof of a liveness/match result (P-SEC-10). */
export const LivenessAttestationSchema = z.object({
	/** The liveness provider's name/id. */
	providerName: z.string().min(1),
	/** Signature algorithm the provider used, e.g. "Ed25519". */
	algorithm: z.string().min(1),
	/** When the provider signed the attestation (ISO). */
	signedAt: IsoTimestampSchema,
	/** The canonical payload the signature covers (provider-defined). */
	payload: z.string().min(1),
	/** The signature over `payload` (base64). */
	signature: z.string().min(1),
});
export type LivenessAttestation = z.infer<typeof LivenessAttestationSchema>;

/** The structured outcome a LivenessProvider returns. */
export const LivenessResultSchema = z.object({
	passed: z.boolean(),
	providerName: z.string().min(1),
	/** 0..1 — confidence the subject is a live person. */
	livenessScore: z.number().min(0).max(1).optional(),
	/** 0..1 — confidence the live face matches the reference identity. */
	matchScore: z.number().min(0).max(1).optional(),
	/** REQUIRED for a passing result (P-SEC-10). Absent on failure. */
	attestation: LivenessAttestationSchema.optional(),
	/** Present when the check did not pass. */
	error: z.string().optional(),
	/** When the check ran (ISO). */
	checkedAt: IsoTimestampSchema,
});
export type LivenessResult = z.infer<typeof LivenessResultSchema>;

/** Input to a liveness check. `payload` is opaque/provider-specific. */
export interface LivenessInput {
	learnerId: string;
	/** Provider-specific capture (frames, challenge response, token, …). */
	payload: unknown;
}

/** A liveness/face-match provider plug-in. */
export interface LivenessProvider {
	readonly name: string;
	verifyLiveness(input: LivenessInput): Promise<LivenessResult>;
}

/**
 * Dev / unconfigured provider. ALWAYS returns `passed: false` — so
 * `identityVerified` stays false and no learner is falsely flagged
 * (P-PRIV-02). Used when `MNEURIX_LIVENESS_PROVIDER` is unset or "none".
 */
export class NoOpLivenessProvider implements LivenessProvider {
	readonly name = "none";
	async verifyLiveness(): Promise<LivenessResult> {
		return {
			passed: false,
			providerName: "none",
			checkedAt: new Date().toISOString(),
			error: "no liveness provider configured (set MNEURIX_LIVENESS_PROVIDER)",
		};
	}
}

/**
 * A provider id was configured but no implementation is linked into this build.
 * Returns `passed: false` (never falsely claim liveness — P-PRIV-02) with an
 * error that surfaces the misconfiguration at the /me/liveness call site.
 */
class UnimplementedLivenessProvider implements LivenessProvider {
	constructor(readonly name: string) {}
	async verifyLiveness(): Promise<LivenessResult> {
		return {
			passed: false,
			providerName: this.name,
			checkedAt: new Date().toISOString(),
			error: `liveness provider "${this.name}" is configured but not implemented in this build — wire the plug-in before claiming liveness (G-ID-1)`,
		};
	}
}

/** Resolve the liveness provider from `MNEURIX_LIVENESS_PROVIDER` (default "none"). */
export function loadLivenessProvider(): LivenessProvider {
	const id = (process.env.MNEURIX_LIVENESS_PROVIDER ?? "none").trim().toLowerCase();
	if (id === "" || id === "none") return new NoOpLivenessProvider();
	// Future: map known ids ("keycloak", a face-match service URL) to real
	// implementations. Until then, never falsely pass.
	return new UnimplementedLivenessProvider(id);
}

/** The liveness fields bound into a credential's identity evidence (P-SEC-10). */
export const LivenessEvidenceSchema = z.object({
	livenessProvider: z.string().min(1),
	livenessScore: z.number().min(0).max(1).optional(),
	matchScore: z.number().min(0).max(1).optional(),
	livenessAttestation: LivenessAttestationSchema,
	livenessCheckedAt: IsoTimestampSchema,
});
export type LivenessEvidence = z.infer<typeof LivenessEvidenceSchema>;