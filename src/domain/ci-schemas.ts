import { z } from "zod";
import { CIProviderNameSchema } from "./ci-provider-contracts.js";

export const CI_SCHEMA_VERSION = "1.0" as const;

export const CICategorySchema = z.enum([
  "build",
  "test",
  "lint",
  "dependency",
  "deployment",
  "infrastructure-connectivity",
  "permission",
  "unknown",
]);
export type CICategory = z.infer<typeof CICategorySchema>;

/** Legacy wire field kept opaque; registry identity is name plus kind. */
export const CIProviderClassSchema = CIProviderNameSchema;
export type CIProviderClass = z.infer<typeof CIProviderClassSchema>;
export const CIRepositorySchema = z
  .string()
  .min(3)
  .max(200)
  .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
export const CIWorkflowSchema = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9_./@-]+$/);
export const CIRunIdSchema = z.string().regex(/^\d{1,20}$/);
export const CIJobIdSchema = z.string().regex(/^\d{1,20}$/);
export const CIRequestIdSchema = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/);

export const CIStatusSchema = z.enum(["queued", "in_progress", "completed"]);
export const CIConclusionSchema = z.enum([
  "success",
  "failure",
  "cancelled",
  "skipped",
  "neutral",
  "timed_out",
  "action_required",
  "unknown",
]);
export const CIFreshnessSchema = z.enum(["fresh", "stale", "unknown"]);

const CIWarningSchema = z
  .object({ code: z.string().min(1).max(64), message: z.string().min(1).max(512) })
  .strict();
const CIEnvelopeFields = {
  schemaVersion: z.literal(CI_SCHEMA_VERSION),
  observedAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
  providerClass: CIProviderClassSchema,
  freshness: CIFreshnessSchema,
  truncated: z.boolean(),
  redactionsApplied: z.boolean(),
  warnings: z.array(CIWarningSchema).max(20),
} as const;

const CIWorkflowRunSchema = z
  .object({
    id: CIRunIdSchema,
    repository: CIRepositorySchema,
    workflow: CIWorkflowSchema,
    status: CIStatusSchema,
    conclusion: CIConclusionSchema.nullable(),
    runAttempt: z.number().int().min(1).max(100),
    event: z.string().min(1).max(64),
    ref: z.string().min(1).max(256),
    sha: z.string().regex(/^[a-f0-9]{40}$/),
    createdAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
    updatedAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
  })
  .strict();

const CIJobSchema = z
  .object({
    id: CIJobIdSchema,
    name: z.string().min(1).max(256),
    status: CIStatusSchema,
    conclusion: CIConclusionSchema,
    category: CICategorySchema,
    failedSteps: z.array(z.string().min(1).max(256)).max(50),
  })
  .strict();

const CIInputBaseSchema = z
  .object({ repo: CIRepositorySchema, workflow: CIWorkflowSchema })
  .strict();

export const CIWorkflowStatusInputSchema = CIInputBaseSchema
  .extend({ runId: CIRunIdSchema.optional() })
  .strict();
export const CIFailedJobAnalysisInputSchema = CIInputBaseSchema
  .extend({ runId: CIRunIdSchema })
  .strict();
export const CILogEvidenceInputSchema = CIInputBaseSchema
  .extend({ runId: CIRunIdSchema, jobId: CIJobIdSchema, maxLines: z.number().int().min(1).max(200).default(80) })
  .strict();
export const CIRemediationPlanInputSchema = CIInputBaseSchema
  .extend({ runId: CIRunIdSchema })
  .strict();
export const CIRerunFailedWorkflowInputSchema = CIInputBaseSchema
  .extend({
    runId: CIRunIdSchema,
    runAttempt: z.number().int().min(1).max(100),
    headSha: z.string().regex(/^[a-f0-9]{40}$/),
    requestId: CIRequestIdSchema,
    approvalToken: z.string().min(32).max(4096),
  })
  .strict();

const CIEnvelope = <T extends z.ZodType>(data: T) => z.object({ ...CIEnvelopeFields, data }).strict();

export const CIWorkflowStatusResultSchema = CIEnvelope(z.object({ run: CIWorkflowRunSchema }).strict());
export const CIFailedJobAnalysisResultSchema = CIEnvelope(
  z
    .object({
      run: CIWorkflowRunSchema,
      failedJobs: z.array(CIJobSchema).max(100),
      categorySummary: z.record(CICategorySchema, z.number().int().min(0).max(100)),
    })
    .strict(),
);
export const CILogEvidenceResultSchema = CIEnvelope(
  z
    .object({
      runId: CIRunIdSchema,
      jobId: CIJobIdSchema,
      jobName: z.string().min(1).max(256),
      available: z.boolean(),
      lines: z
        .array(z.object({ sequence: z.number().int().min(1).max(20_000), text: z.string().max(1_024) }).strict())
        .max(200),
      sha256: z.string().regex(/^[a-f0-9]{64}$/),
    })
    .strict(),
);
export const CIRemediationPlanResultSchema = CIEnvelope(
  z
    .object({
      runId: CIRunIdSchema,
      dryRun: z.literal(true),
      actions: z
        .array(
          z
            .object({
              category: CICategorySchema,
              title: z.string().min(1).max(256),
              steps: z.array(z.string().min(1).max(512)).min(1).max(8),
              runbook: z.string().regex(/^docs\/ci-cd-runbook\.md#[a-z0-9-]+$/),
            })
            .strict(),
        )
        .max(8),
    })
    .strict(),
);
export const CIRerunFailedWorkflowResultSchema = CIEnvelope(
  z
    .object({ runId: CIRunIdSchema, requestId: CIRequestIdSchema, accepted: z.literal(true), action: z.literal("rerun-failed-jobs") })
    .strict(),
);

export type CIWorkflowStatusInput = z.infer<typeof CIWorkflowStatusInputSchema>;
export type CIFailedJobAnalysisInput = z.infer<typeof CIFailedJobAnalysisInputSchema>;
export type CILogEvidenceInput = z.infer<typeof CILogEvidenceInputSchema>;
export type CIRemediationPlanInput = z.infer<typeof CIRemediationPlanInputSchema>;
export type CIRerunFailedWorkflowInput = z.infer<typeof CIRerunFailedWorkflowInputSchema>;
export type CIWorkflowRun = z.infer<typeof CIWorkflowRunSchema>;
export type CIJob = z.infer<typeof CIJobSchema>;
export type CIWorkflowStatusResult = z.infer<typeof CIWorkflowStatusResultSchema>;
export type CIFailedJobAnalysisResult = z.infer<typeof CIFailedJobAnalysisResultSchema>;
export type CILogEvidenceResult = z.infer<typeof CILogEvidenceResultSchema>;
export type CIRemediationPlanResult = z.infer<typeof CIRemediationPlanResultSchema>;
export type CIRerunFailedWorkflowResult = z.infer<typeof CIRerunFailedWorkflowResultSchema>;

export function classifyFailure(...parts: readonly string[]): CICategory {
  const text = parts.join(" ").toLowerCase();
  if (/\b(permission|forbidden|unauthori[sz]ed|access denied|\b401\b|\b403\b)/.test(text)) return "permission";
  if (/\b(terraform|kubernetes|kubectl|network|connect|connectivity|dns|timeout|unreachable|socket|infrastructure)\b/.test(text)) return "infrastructure-connectivity";
  if (/\b(deploy|deployment|release|publish|production|staging)\b/.test(text)) return "deployment";
  if (/\b(dependenc|npm audit|pnpm audit|yarn audit|renovate|dependabot|lockfile)\b/.test(text)) return "dependency";
  if (/\b(lint|eslint|prettier|format|style)\b/.test(text)) return "lint";
  if (/\b(tests?|spec|vitest|jest|pytest|coverage)\b/.test(text)) return "test";
  if (/\b(build|compile|typescript|tsc|bundle|compile)\b/.test(text)) return "build";
  return "unknown";
}

export function makeCIEvidence<T>(
  providerClass: CIProviderClass,
  observedAt: Date,
  data: T,
  options: { freshness?: z.infer<typeof CIFreshnessSchema>; truncated?: boolean; redactionsApplied?: boolean; warnings?: readonly { code: string; message: string }[] } = {},
): Record<string, unknown> {
  return {
    schemaVersion: CI_SCHEMA_VERSION,
    observedAt: observedAt.toISOString(),
    providerClass,
    freshness: options.freshness ?? "fresh",
    truncated: options.truncated ?? false,
    redactionsApplied: options.redactionsApplied ?? false,
    warnings: options.warnings === undefined ? [] : [...options.warnings],
    data,
  };
}
