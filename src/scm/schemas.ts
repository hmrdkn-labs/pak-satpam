import { createHash } from "node:crypto";
import { z } from "zod";
import { CIProviderNativeIdSchema } from "../domain/ci-schemas.js";
import { CIProviderNameSchema } from "../domain/ci-provider-contracts.js";

export const SCM_SCHEMA_VERSION = "1.0" as const;

export const SCMRepositorySchema = z
  .string()
  .min(3)
  .max(200)
  .regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/);
export type SCMRepository = z.infer<typeof SCMRepositorySchema>;

export const SCMRefSchema = z
  .string()
  .min(1)
  .max(256)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._/-]*$/)
  .refine((value) => !value.split("/").some((segment) => segment === "." || segment === ".."), "ref must not contain dot segments");
export type SCMRef = z.infer<typeof SCMRefSchema>;

export const SCMCommitSchema = z.string().regex(/^[a-f0-9]{40}$/i);
export type SCMCommit = z.infer<typeof SCMCommitSchema>;

const SCMRevisionSchema = z.union([SCMCommitSchema, SCMRefSchema]);
export const SCMCompareRangeSchema = z.object({ base: SCMRevisionSchema, head: SCMRevisionSchema }).strict()
  .refine((value) => value.base !== value.head, "compare range must have distinct revisions");
export type SCMCompareRange = z.infer<typeof SCMCompareRangeSchema>;

export const SCMProviderNativeIdSchema = CIProviderNativeIdSchema;

export const SCMFileStatusSchema = z.enum(["added", "modified", "removed", "renamed", "copied", "changed", "unknown"]);
export type SCMFileStatus = z.infer<typeof SCMFileStatusSchema>;

export const SCMBudgetSchema = z
  .object({
    maxBytes: z.number().int().min(256).max(256 * 1_024),
    maxFiles: z.number().int().min(1).max(100),
    maxHunks: z.number().int().min(1).max(100),
    maxLines: z.number().int().min(1).max(10_000),
    maxProviderRequests: z.number().int().min(1).max(16),
    maxDurationMs: z.number().int().min(1).max(60_000),
  })
  .strict();
export type SCMBudget = z.infer<typeof SCMBudgetSchema>;

export const SCMBudgetInputSchema = z
  .object({
    maxBytes: z.number().int().min(256).max(256 * 1_024).optional(),
    maxFiles: z.number().int().min(1).max(100).optional(),
    maxHunks: z.number().int().min(1).max(100).optional(),
    maxLines: z.number().int().min(1).max(10_000).optional(),
    maxProviderRequests: z.number().int().min(1).max(16).optional(),
    maxDurationMs: z.number().int().min(1).max(60_000).optional(),
    maxItems: z.number().int().min(1).max(100).optional(),
    maxTokens: z.number().int().min(64).max(64 * 1_024).optional(),
  })
  .strict();

export const DEFAULT_SCM_BUDGET = Object.freeze({
  maxBytes: 64 * 1_024,
  maxFiles: 100,
  maxHunks: 50,
  maxLines: 2_000,
  maxProviderRequests: 4,
  maxDurationMs: 10_000,
} satisfies SCMBudget);

export const SCMSelectorSchema = z
  .object({
    repository: SCMRepositorySchema,
    ref: SCMRefSchema.optional(),
    commit: SCMCommitSchema.optional(),
    pullRequest: SCMProviderNativeIdSchema.optional(),
    compare: SCMCompareRangeSchema.optional(),
  })
  .strict()
  .refine((value) => value.ref !== undefined || value.commit !== undefined || value.pullRequest !== undefined || value.compare !== undefined, "one SCM selector is required");
export type SCMSelector = z.infer<typeof SCMSelectorSchema>;

export const SCMChangeEvidenceInputSchema = SCMSelectorSchema.extend({ budget: SCMBudgetInputSchema.optional() }).strict();
export type SCMChangeEvidenceInput = z.infer<typeof SCMChangeEvidenceInputSchema>;

const SCMIdentitySchema = z
  .object({ ref: SCMRefSchema.optional(), sha: SCMCommitSchema.optional() })
  .strict();

const SCMFileChangeSchema = z
  .object({
    path: z.string().min(1).max(1_024),
    status: SCMFileStatusSchema,
    additions: z.number().int().min(0).max(1_000_000_000),
    deletions: z.number().int().min(0).max(1_000_000_000),
    binary: z.boolean(),
    patch: z.string().max(32 * 1_024).optional(),
    suppressedReason: z.enum(["binary", "secret", "budget", "provider-omitted"]).optional(),
  })
  .strict();

const SCMPullRequestSchema = z
  .object({
    id: SCMProviderNativeIdSchema,
    title: z.string().max(512).optional(),
    state: z.string().min(1).max(64).optional(),
    base: SCMIdentitySchema,
    head: SCMIdentitySchema,
  })
  .strict();

const SCMBudgetUsageSchema = z
  .object({
    maxBytes: z.number().int().positive(),
    maxFiles: z.number().int().positive(),
    maxHunks: z.number().int().positive(),
    maxLines: z.number().int().positive(),
    maxProviderRequests: z.number().int().positive(),
    maxDurationMs: z.number().int().positive(),
    usedBytes: z.number().int().nonnegative(),
    usedFiles: z.number().int().nonnegative(),
    usedHunks: z.number().int().nonnegative(),
    usedLines: z.number().int().nonnegative(),
    usedProviderRequests: z.number().int().nonnegative(),
    usedDurationMs: z.number().int().nonnegative(),
  })
  .strict();

const SCMTruncationSchema = z.object({ files: z.boolean(), hunks: z.boolean(), lines: z.boolean(), bytes: z.boolean(), providerRequests: z.boolean(), timeWindow: z.boolean() }).strict();

const SCMDataSchema = z
  .object({
    repository: SCMRepositorySchema,
    selector: z
      .object({ ref: SCMRefSchema.optional(), commit: SCMCommitSchema.optional(), pullRequest: SCMProviderNativeIdSchema.optional(), compare: SCMCompareRangeSchema.optional() })
      .strict(),
    base: SCMIdentitySchema,
    head: SCMIdentitySchema.extend({ sha: SCMCommitSchema }),
    pullRequest: SCMPullRequestSchema.optional(),
    files: z.array(SCMFileChangeSchema).max(100),
    summary: z
      .object({ files: z.number().int().nonnegative(), additions: z.number().int().nonnegative(), deletions: z.number().int().nonnegative() })
      .strict(),
  })
  .strict();

export const SCMChangeEvidenceResultSchema = z
  .object({
    schemaVersion: z.literal(SCM_SCHEMA_VERSION),
    observedAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
    providerClass: CIProviderNameSchema,
    freshness: z.enum(["fresh", "stale", "unknown"]),
    truncated: z.boolean(),
    truncation: SCMTruncationSchema,
    redactionsApplied: z.boolean(),
    digest: z.string().regex(/^[a-f0-9]{64}$/),
    warnings: z.array(z.object({ code: z.string().min(1).max(64), message: z.string().min(1).max(512) }).strict()).max(20),
    budget: SCMBudgetUsageSchema,
    data: SCMDataSchema,
  })
  .strict();
export type SCMChangeEvidenceResult = z.infer<typeof SCMChangeEvidenceResultSchema>;

export type SCMFileChange = z.infer<typeof SCMFileChangeSchema>;
export type SCMIdentity = z.infer<typeof SCMIdentitySchema>;
export type SCMPullRequest = z.infer<typeof SCMPullRequestSchema>;
export type SCMTruncation = z.infer<typeof SCMTruncationSchema>;

export function resolveSCMBudget(input: z.input<typeof SCMBudgetInputSchema> | undefined): SCMBudget {
  const parsed = SCMBudgetInputSchema.parse(input ?? {});
  const { maxItems, maxTokens: _maxTokens, ...explicit } = parsed;
  return SCMBudgetSchema.parse({
    ...DEFAULT_SCM_BUDGET,
    ...explicit,
    ...(explicit.maxFiles === undefined && maxItems === undefined ? {} : { maxFiles: explicit.maxFiles ?? maxItems }),
  });
}

export function makeSCMEvidence(
  providerClass: string,
  observedAt: Date,
  data: SCMChangeEvidenceResult["data"],
  options: Pick<SCMChangeEvidenceResult, "budget" | "freshness" | "truncated" | "truncation" | "redactionsApplied"> & { warnings?: readonly { code: string; message: string }[] },
): SCMChangeEvidenceResult {
  const envelope = {
    schemaVersion: SCM_SCHEMA_VERSION,
    observedAt: observedAt.toISOString(),
    providerClass,
    freshness: options.freshness,
    truncated: options.truncated,
    truncation: options.truncation,
    redactionsApplied: options.redactionsApplied,
    warnings: options.warnings === undefined ? [] : [...options.warnings],
    budget: options.budget,
    data,
  };
  return SCMChangeEvidenceResultSchema.parse({
    ...envelope,
    digest: createHash("sha256").update(JSON.stringify(data), "utf8").digest("hex"),
  });
}
