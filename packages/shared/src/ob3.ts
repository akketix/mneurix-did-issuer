/**
 * @mneurix/shared/ob3 — Open Badges 3.0 / W3C Verifiable Credentials data model.
 *
 * These schemas model the CONTENT of an OB 3.0 badge (the 1EdTech education
 * layer inside a W3C VC envelope). The cryptographic `proof` is shaped per
 * Ed25519Signature2020; see the credential service for how the proofValue is
 * produced and the conformance status (Data Integrity proof via the correct
 * canonicalization path is a tracked task).
 *
 * The killer field here is `evidence`: it carries the Mneurix council's
 * CompetencyScore (fractional score, per-criterion verdicts, agreement) plus
 * proctoring metadata — so a badge asserts competence WITH its proof, not just
 * "passed".
 */
import { z } from "zod";
import { LivenessAttestationSchema } from "./identity";
import { RubricProvenanceSchema } from "./questions";

// Local primitives (kept here to avoid a circular index with index.ts).
const IdSchema = z.string().min(1);
const IsoTimestampSchema = z.string().datetime({ offset: true });

/** Resolution of a flagged council grade — deterministic system resolution
 * (R13/R14), never a per-attempt human/CISO adjudication. Lives here (not
 * index.ts) so both CompetencyScoreSchema and CompetencyEvidenceSchema can
 * reference it without a circular import. */
export const ResolutionSchema = z.object({
	/** 0 = initial grade honored (no flag); 1 = the re-grade round. */
	round: z.number().int().min(0),
	outcome: z.enum(["pass", "fail", "retry"]),
	/** ISO timestamp the learner may re-attempt after (outcome:"retry" only). */
	retryableAfter: IsoTimestampSchema.optional(),
	/** True once the round + decision are written to the hash-chained audit log. */
	audited: z.boolean(),
});
export type Resolution = z.infer<typeof ResolutionSchema>;

// ---------------------------------------------------------------------------
// Alignment — mapping to skills/qualifications frameworks (EQF, ESCO, ...)
// ---------------------------------------------------------------------------

export const AlignmentSchema = z.object({
	type: z.literal("Alignment").default("Alignment"),
	/** URL of the framework. */
	target: z.string().url(),
	/** Human-readable framework name, e.g. "European Qualifications Framework". */
	framework: z.string().min(1),
	/** Code within the framework, e.g. "EQF 5" or an ESCO occupation URI. */
	targetCode: z.string().min(1),
	/** Human-readable label for the aligned target. */
	targetName: z.string().min(1),
});
export type Alignment = z.infer<typeof AlignmentSchema>;

// ---------------------------------------------------------------------------
// Criteria & Achievement (constructive alignment)
// ---------------------------------------------------------------------------

export const CriteriaSchema = z.object({
	id: z.string().url().optional(),
	/** Narrative describing what the learner must do to earn the achievement. */
	narrative: z.string().min(1),
});
export type Criteria = z.infer<typeof CriteriaSchema>;

export const AchievementSchema = z.object({
	id: z.string().url(),
	type: z.array(z.string()).default(["Achievement"]),
	name: z.string().min(1),
	description: z.string().min(1),
	achievementType: z
		.enum(["introductory", "intermediate", "advanced", "expert"])
		.optional(),
	criteria: CriteriaSchema,
	alignment: z.array(AlignmentSchema).default([]),
});
export type Achievement = z.infer<typeof AchievementSchema>;

// ---------------------------------------------------------------------------
// Evidence — the Mneurix differentiator: competence proof baked into the badge
// ---------------------------------------------------------------------------

/**
 * The competency evidence block. Embeds the council's CompetencyScore-derived
 * data so the badge is substantively verifiable, not a hollow "passed".
 */

/**
 * Identity evidence — how the credential's subject was bound to a real
 * identity. When absent, the subject is self-declared (the weak session
 * fallback). When present, it records the OIDC IdP that vouches for the
 * subject, the stable `sub`, and the identity-assurance level reached.
 */
export const IdentityEvidenceSchema = z.object({
	/** Which IdP vouches for this identity, e.g. "orcid" or "google". */
	provider: z.string().min(1),
	/** The IdP issuer URL (the OIDC `iss`), e.g. "https://orcid.org". */
	issuer: z.string().url(),
	/** The OIDC `sub` — the stable, IdP-scoped subject identifier. */
	sub: z.string().min(1),
	/** Authentication methods used (OIDC `amr`), e.g. ["mfa"]. */
	amr: z.array(z.string()).optional(),
	/** ISO timestamp of the IdP authentication (from `auth_time`). */
	authTime: z.string().optional(),
	identityAssurance: z.enum([
		"self-declared",
		"oidc-verified",
		"oidc-verified-mfa",
		"liveness-verified",
	]),
	/** Liveness/face-match binding (G-ID-1 person half, P-SEC-10). Present only
	 * when a real liveness provider passed + attested; identityAssurance is then
	 * "liveness-verified". */
	livenessProvider: z.string().min(1).optional(),
	livenessScore: z.number().min(0).max(1).optional(),
	matchScore: z.number().min(0).max(1).optional(),
	livenessAttestation: LivenessAttestationSchema.optional(),
	livenessCheckedAt: z.string().datetime({ offset: true }).optional(),
});
export type IdentityEvidence = z.infer<typeof IdentityEvidenceSchema>;

export const CompetencyEvidenceSchema = z.object({
	/** Discriminator for the BadgeEvidence union (R15/R25). Defaults so existing
	 * summative badges (no `kind`) still parse under the widened union. */
	kind: z.literal("council-formative").default("council-formative"),
	id: z.string().url(),
	type: z.array(z.string()).default(["Evidence"]),
	narrative: z.string().min(1),
	name: z.string().min(1).optional(),
	score: z.number().min(0).max(1),
	agreement: z.number().min(0).max(1),
	councilSize: z.number().int().min(1),
	criterionScores: z.array(
		z.object({
			criterionId: IdSchema,
			score: z.number().min(0).max(1),
			reasoning: z.string(),
		}),
	),
	requiresHumanReview: z.boolean(),
	/** G-AIP-2: this Mneurix badge is an EQF/ESCO *reference*, NOT an official certification. */
	isOfficialCertification: z.boolean().default(false),
	/** Phase 5: the public-framework baselines the rubric was anchored to. */
	rubricProvenance: z.array(RubricProvenanceSchema).optional(),
	/** Phase 4/5: the deterministic resolution of a flagged grade. */
	resolution: ResolutionSchema.optional(),
	proctoring: z
		.object({
			method: z.string().min(1),
			identityVerified: z.boolean(),
			browserLockout: z.boolean().optional(),
			/** Tab/focus switches detected during the assessment. */
			focusLossCount: z.number().int().min(0).optional(),
			/** ISO timestamp the proctored session started. */
			startedAt: z.string().optional(),
			/** Assessment duration in milliseconds. */
			durationMs: z.number().int().min(0).optional(),
		})
		.optional(),
	/** OIDC identity binding (absent = self-declared subject). */
	identity: IdentityEvidenceSchema.optional(),
	/** Phase 5: alignment to frameworks (e.g. EQF, ESCO). */
	alignment: z.array(AlignmentSchema).default([]),
});
export type CompetencyEvidence = z.infer<typeof CompetencyEvidenceSchema>;

// ---------------------------------------------------------------------------
// Mastery threshold + behavioral evidence variants (CISO R15/R25/R26/R28/R31)
// ---------------------------------------------------------------------------

/** The governed mastery threshold (R31: a controlled pedagogical-legal
 * constant, versioned via `policyVersion` in MasteryCheckEvidence). */

export const MasteryThresholdSchema = z.object({
	consecutiveGood: z.number().int().min(1).default(2),
	minRetrievability: z.number().min(0.5).max(1).default(0.9),
	minIntervalDays: z.number().int().min(1).default(21),
	maxLapses: z.number().int().min(0).default(3),
});
export type MasteryThreshold = z.infer<typeof MasteryThresholdSchema>;

/** Generative-friction evidence — complete-only (R25): the formative
 * score/agreement/requiresHumanReview are learner-private UX, never signed
 * into a credential. `attemptRef` is a server-salted, NON-resolvable
 * commitment (R26), not content-addressed. */
export const GenerativeFrictionEvidenceSchema = z.object({
	kind: z.literal("generative-friction"),
	attemptRef: z.string().min(1),
	complete: z.boolean(),
	bloomLevel: z.enum(["apply", "analyze", "evaluate", "create"]),
});
export type GenerativeFrictionEvidence = z.infer<
	typeof GenerativeFrictionEvidenceSchema
>;

/** Mastery-check evidence. `rigorFloor` (R31) carries the policy floor so a
 * verifier can detect a badge minted under a lowered threshold. */
export const MasteryCheckEvidenceSchema = z.object({
	kind: z.literal("mastery-check"),
	score: z.number().min(0).max(1),
	masteryThreshold: MasteryThresholdSchema,
	policyVersion: z.string().min(1),
	rigorFloor: z.object({
		coolDownFloorMs: z.number().int(),
		minRetrievabilityFloor: z.number(),
		minIntervalDaysFloor: z.number().int(),
	}),
	accommodation: z
		.object({
			type: z.string().min(1),
			authorizedBy: z.string().min(1),
			reference: z.string().min(1),
		})
		.optional(),
	passed: z.boolean(),
	scoredAt: z.string().min(1),
	/** R20: recovery time if the mint was deferred (`:7002` was unavailable). */
	mintedAt: z.string().min(1).optional(),
	elapsedHours: z.number().min(0),
	identity: IdentityEvidenceSchema.optional(),
});
export type MasteryCheckEvidence = z.infer<typeof MasteryCheckEvidenceSchema>;

/** Capstone evidence — the summative course badge that stacks micro-badges
 * via `consistsOf` (verifiable skill tree). */
export const CapstoneEvidenceSchema = z.object({
	kind: z.literal("capstone"),
	consistsOf: z.array(z.string().url()).min(1),
	skillTreeId: z.string().url(),
	score: z.number().min(0).max(1),
	agreement: z.number().min(0).max(1),
	councilSize: z.number().int().min(1),
	requiresHumanReview: z.boolean(),
});
export type CapstoneEvidence = z.infer<typeof CapstoneEvidenceSchema>;

/** Union of evidence shapes a credential may carry. A plain union (not
 * discriminated) so existing summative badges (no `kind`) still match via the
 * CompetencyEvidence `kind` default. */
export const BadgeEvidenceSchema = z.union([
	CompetencyEvidenceSchema,
	GenerativeFrictionEvidenceSchema,
	MasteryCheckEvidenceSchema,
	CapstoneEvidenceSchema,
]);
export type BadgeEvidence = z.infer<typeof BadgeEvidenceSchema>;

/** Credential status (Bitstring Status List) — R10/R22/R28. Optional; absent on
 * the legacy dev badge. `statusPurpose: "delisted"` (R28) is the erasure bit. */
export const CredentialStatusSchema = z.object({
	id: z.string().url(),
	type: z.literal("BitstringStatusListEntry"),
	statusPurpose: z.enum(["revocation", "refresh", "delisted"]),
	statusListIndex: z.number().int().min(0),
	refreshService: z.string().url().optional(),
	statusFreshnessHours: z.number().int().optional(),
});
export type CredentialStatus = z.infer<typeof CredentialStatusSchema>;

// ---------------------------------------------------------------------------
// Issuer profile & credential subject
// ---------------------------------------------------------------------------

export const IssuerProfileSchema = z.object({
	id: z.string().url(),
	type: z.array(z.string()).default(["Profile"]),
	name: z.string().min(1),
	url: z.string().url().optional(),
});
export type IssuerProfile = z.infer<typeof IssuerProfileSchema>;

export const AchievementSubjectSchema = z.object({
	id: z.string().url(),
	type: z.array(z.string()).default(["AchievementSubject"]),
	achievement: AchievementSchema,
});
export type AchievementSubject = z.infer<typeof AchievementSubjectSchema>;

// ---------------------------------------------------------------------------
// Proof — Ed25519Signature2020-shaped (see credential service for conformance)
// ---------------------------------------------------------------------------

export const OB3ProofSchema = z.object({
	type: z.string().min(1),
	/** Cryptosuite name for DataIntegrityProof, e.g. "ed25519-jcs-2020". */
	cryptosuite: z.string().min(1).optional(),
	created: IsoTimestampSchema,
	verificationMethod: z.string().url(),
	proofPurpose: z.literal("assertionMethod").default("assertionMethod"),
	proofValue: z.string().min(1),
});
export type OB3Proof = z.infer<typeof OB3ProofSchema>;

// ---------------------------------------------------------------------------
// OpenBadgeCredential — the W3C VC envelope
// ---------------------------------------------------------------------------

export const OpenBadgeCredentialSchema = z.object({
	"@context": z
		.array(z.string().url())
		.default([
			"https://www.w3.org/ns/credentials/v2",
			"https://purl.imsglobal.org/spec/ob/v3p0/context.json",
		]),
	id: z.string().url(),
	type: z
		.array(z.string())
		.default(["VerifiableCredential", "OpenBadgeCredential"]),
	issuer: IssuerProfileSchema,
	validFrom: IsoTimestampSchema,
	credentialSubject: AchievementSubjectSchema,
	evidence: z.array(BadgeEvidenceSchema).min(1),
	/** R10/R22/R28: revocation/delisting/refresh status list entry. */
	credentialStatus: CredentialStatusSchema.optional(),
	/** R22(d): "lapsed" is a verify-time validUntil check, not a status bit. */
	validUntil: IsoTimestampSchema.optional(),
	proof: OB3ProofSchema,
});
export type OpenBadgeCredential = z.infer<typeof OpenBadgeCredentialSchema>;
