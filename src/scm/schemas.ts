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

export const SCMProviderNativeIdSchema = CIProviderNativeIdSchema;

export const SCMFileStatusSchema = z.enum(["added", "modified", "removed", "renamed", "copied", "changed", "unknown"]);
export type SCMFileStatus = z.infer<typeof SCMFileStatusSchema>;

export const SCMBudgetSchema = z
  .object({
    maxBytes: z.number().int().min(256).max(256 * 1_024),
    maxItems: z.number().int().min(1).max(100),
    maxTokens: z.number().int().min(64).max(64 * 1_024),
  })
  .strict();
export type SCMBudget = z.infer<typeof SCMBudgetSchema>;

export const SCMBudgetInputSchema = z
  .object({
    maxBytes: z.number().int().min(256).max(256 * 1_024).optional(),
    maxItems: z.number().int().min(1).max(100).optional(),
    maxTokens: z.number().int().min(64).max(64 * 1_024).optional(),
  })
  .strict();

export const DEFAULT_SCM_BUDGET = Object.freeze({
  maxBytes: 64 * 1_024,
  maxItems: 100,
  maxTokens: 16 * 1_024,
} satisfies SCMBudget);

export const SCMChangeEvidenceInputSchema = z
  .object({
    repository: SCMRepositorySchema,
    ref: SCMRefSchema.optional(),
    commit: SCMCommitSchema.optional(),
    pullRequest: SCMProviderNativeIdSchema.optional(),
    budget: SCMBudgetInputSchema.optional(),
  })
  .strict()
  .refine((value) => value.ref !== undefined || value.commit !== undefined || value.pullRequest !== undefined, "one SCM selector is required");
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
    maxItems: z.number().int().positive(),
    maxTokens: z.number().int().positive(),
    usedBytes: z.number().int().nonnegative(),
    usedItems: z.number().int().nonnegative(),
    usedTokens: z.number().int().nonnegative(),
  })
  .strict();

const SCMDataSchema = z
  .object({
    repository: SCMRepositorySchema,
    selector: z
      .object({ ref: SCMRefSchema.optional(), commit: SCMCommitSchema.optional(), pullRequest: SCMProviderNativeIdSchema.optional() })
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
    redactionsApplied: z.boolean(),
    warnings: z.array(z.object({ code: z.string().min(1).max(64), message: z.string().min(1).max(512) }).strict()).max(20),
    budget: SCMBudgetUsageSchema,
    data: SCMDataSchema,
  })
  .strict();
export type SCMChangeEvidenceResult = z.infer<typeof SCMChangeEvidenceResultSchema>;

export type SCMFileChange = z.infer<typeof SCMFileChangeSchema>;
export type SCMIdentity = z.infer<typeof SCMIdentitySchema>;
export type SCMPullRequest = z.infer<typeof SCMPullRequestSchema>;

export function resolveSCMBudget(input: z.input<typeof SCMBudgetInputSchema> | undefined): SCMBudget {
  const parsed = SCMBudgetInputSchema.parse(input ?? {});
  return SCMBudgetSchema.parse({ ...DEFAULT_SCM_BUDGET, ...parsed });
}

export function makeSCMEvidence(
  providerClass: string,
  observedAt: Date,
  data: SCMChangeEvidenceResult["data"],
  options: Pick<SCMChangeEvidenceResult, "budget" | "freshness" | "truncated" | "redactionsApplied"> & { warnings?: readonly { code: string; message: string }[] },
): SCMChangeEvidenceResult {
  return SCMChangeEvidenceResultSchema.parse({
    schemaVersion: SCM_SCHEMA_VERSION,
    observedAt: observedAt.toISOString(),
    providerClass,
    freshness: options.freshness,
    truncated: options.truncated,
    redactionsApplied: options.redactionsApplied,
    warnings: options.warnings === undefined ? [] : [...options.warnings],
    budget: options.budget,
    data,
  });
}
