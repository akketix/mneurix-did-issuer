/**
 * @mneurix/shared/questions — rubric + open-ended question schemas.
 *
 * Kept in a standalone module (with its own IdSchema primitive) so that
 * `course.ts` can import OpenEndedQuestionSchema without a circular import
 * back into index.ts (ESM loads `export *` dependencies before the parent
 * module's body runs, which would otherwise hit a temporal-dead-zone error).
 */
import { z } from "zod";

// Local primitive (identical to index.ts's IdSchema) to avoid the cycle.
const IdSchema = z.string().min(1);

/** Rubric criterion provenance — anchors a criterion to a public-framework
 * baseline (EQF level descriptor + ESCO skill definition). Optional in the
 * schema (roll-forward); authoring (Phase 2) refuses to persist a rubric whose
 * criteria lack it. `baselineText` is the verbatim official text; `extended:true`
 * means the council refined wording beyond the baseline. */
export const RubricProvenanceSchema = z.object({
	framework: z.enum(["EQF", "ESCO"]),
	/** e.g. "EQF 6", or an ESCO skill code. */
	targetCode: z.string().min(1),
	/** Canonical URI of the baseline (ESCO skill URI; EQF descriptor page). */
	targetUri: z.string().url().optional(),
	/** Version of the baseline framework the rubric was anchored to. */
	frameworkVersion: z.string().min(1).optional(),
	/** Verbatim official baseline text the criterion is anchored to. */
	baselineText: z.string().min(1),
	/** true = the council refined wording beyond the baseline; false = verbatim. */
	extended: z.boolean().default(false),
});
export type RubricProvenance = z.infer<typeof RubricProvenanceSchema>;

export const RubricCriterionSchema = z.object({
	id: IdSchema,
	name: z.string().min(1),
	description: z.string().min(1),
	weight: z.number().min(0).max(1),
	exemplar: z.string().optional(),
	/** Phase 1: provenance to a public-framework baseline. */
	provenance: RubricProvenanceSchema.optional(),
});
export type RubricCriterion = z.infer<typeof RubricCriterionSchema>;

export const RubricSchema = z.object({
	criteria: z.array(RubricCriterionSchema).min(1),
	/** Competency score (0..1) at or above which a credential is issued. */
	passingThreshold: z.number().min(0).max(1),
});
export type Rubric = z.infer<typeof RubricSchema>;

export const OpenEndedQuestionSchema = z.object({
	id: IdSchema,
	prompt: z.string().min(1),
	expectedResponse: z.string().min(1),
	rubric: RubricSchema,
	maxChars: z.number().int().min(1).max(20000).default(4000),
});
export type OpenEndedQuestion = z.infer<typeof OpenEndedQuestionSchema>;
