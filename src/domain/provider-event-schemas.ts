import { z } from "zod";
import { CIConclusionSchema, CIJobIdSchema, CIRepositorySchema, CIRunIdSchema, CIStatusSchema, CIWorkflowSchema, type CIJob, type CIWorkflowRun } from "./ci-schemas.js";
import { SCMFileStatusSchema } from "../scm/schemas.js";
import { Goal23EventEnvelopeSchema, type Goal23EventEnvelope } from "../observer/event-envelope.js";

/** Provider portability contracts intentionally stay at schema version 1.0. */
export const PROVIDER_EVENT_SCHEMA_VERSION = "1.0" as const;
export const ProviderCapabilityStateSchema = z.enum(["available", "unsupported", "unavailable"]);
export type ProviderCapabilityState = z.infer<typeof ProviderCapabilityStateSchema>;

export const ProviderCapabilitiesSchema = z.object({
  status: ProviderCapabilityStateSchema,
  commit: ProviderCapabilityStateSchema,
  workflow: ProviderCapabilityStateSchema,
  jobs: ProviderCapabilityStateSchema,
  diff: ProviderCapabilityStateSchema,
  logs: ProviderCapabilityStateSchema,
  metrics: ProviderCapabilityStateSchema,
  traces: ProviderCapabilityStateSchema,
  artifact: ProviderCapabilityStateSchema,
  links: ProviderCapabilityStateSchema,
}).strict();
export type ProviderCapabilities = z.infer<typeof ProviderCapabilitiesSchema>;

export const ProviderBindingSchema = z.union([
  z.object({ available: z.literal(true), value: z.string().min(1).max(256) }).strict(),
  z.object({ available: z.literal(false), reason: z.enum(["absent", "unavailable", "invalid"]) }).strict(),
]);
export type ProviderBinding = z.infer<typeof ProviderBindingSchema>;

export const ProviderWorkflowSchema = z.object({
  id: z.string().min(1).max(128),
  name: CIWorkflowSchema,
  ref: z.string().min(1).max(256),
  link: z.string().url().max(2_048).optional(),
}).strict();
export type ProviderWorkflow = z.infer<typeof ProviderWorkflowSchema>;

export const ProviderDiffSchema = z.object({
  path: z.string().min(1).max(512),
  status: SCMFileStatusSchema,
  additions: z.number().int().min(0).max(1_000_000),
  deletions: z.number().int().min(0).max(1_000_000),
  hunkCount: z.number().int().min(0).max(100),
}).strict();
export type ProviderDiff = z.infer<typeof ProviderDiffSchema>;

export const ProviderLogReferenceSchema = z.object({
  id: z.string().min(1).max(128),
  jobId: CIJobIdSchema,
  available: z.boolean(),
  lineCount: z.number().int().min(0).max(20_000),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  link: z.string().url().max(2_048).optional(),
}).strict();
export type ProviderLogReference = z.infer<typeof ProviderLogReferenceSchema>;

export const ProviderMetricSchema = z.object({
  name: z.string().min(1).max(128),
  state: z.enum(["normal", "degraded", "error", "unknown"]),
  value: z.number().finite().optional(),
  sampleCount: z.number().int().min(0).max(1_000_000).optional(),
  reference: z.string().min(1).max(256).optional(),
}).strict();
export type ProviderMetric = z.infer<typeof ProviderMetricSchema>;

export const ProviderTraceSchema = z.object({
  spanDigest: z.string().regex(/^[a-f0-9]{64}$/),
  durationMs: z.number().finite().min(0).max(86_400_000),
  status: z.enum(["ok", "error", "unknown"]),
  reference: z.string().min(1).max(256).optional(),
}).strict();
export type ProviderTrace = z.infer<typeof ProviderTraceSchema>;

export const ProviderArtifactSchema = z.object({
  name: z.string().min(1).max(256).optional(),
  digest: ProviderBindingSchema,
  reference: z.string().url().max(2_048).optional(),
}).strict();
export type ProviderArtifact = z.infer<typeof ProviderArtifactSchema>;

export const ProviderLinkSchema = z.object({
  kind: z.string().min(1).max(64),
  href: z.string().url().max(2_048),
}).strict();
export type ProviderLink = z.infer<typeof ProviderLinkSchema>;

export const ProviderNormalizedEventSchema = z.object({
  schemaVersion: z.literal(PROVIDER_EVENT_SCHEMA_VERSION),
  provider: z.string().min(1).max(64),
  observedAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
  run: z.object({
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
  }).strict(),
  commit: ProviderBindingSchema,
  workflowInfo: ProviderWorkflowSchema,
  jobs: z.array(z.object({
    id: CIJobIdSchema,
    name: z.string().min(1).max(256),
    status: CIStatusSchema,
    conclusion: CIConclusionSchema,
    category: z.string().min(1).max(64),
    failedSteps: z.array(z.string().min(1).max(256)).max(50),
  }).strict()).max(50),
  diff: z.array(ProviderDiffSchema).max(10),
  logs: z.array(ProviderLogReferenceSchema).max(50),
  metrics: z.array(ProviderMetricSchema).max(20),
  traces: z.array(ProviderTraceSchema).max(20),
  artifact: ProviderArtifactSchema,
  links: z.array(ProviderLinkSchema).max(10),
  capabilities: ProviderCapabilitiesSchema,
  envelope: Goal23EventEnvelopeSchema.optional(),
  freshness: z.enum(["fresh", "stale", "unknown"]),
  truncated: z.boolean(),
  redactionsApplied: z.boolean(),
  warnings: z.array(z.object({ code: z.string().min(1).max(64), message: z.string().min(1).max(512) }).strict()).max(20),
}).strict();
export type ProviderNormalizedEvent = z.infer<typeof ProviderNormalizedEventSchema>;
export type NormalizedCIEvent = ProviderNormalizedEvent;
export const NormalizedCIEventSchema = ProviderNormalizedEventSchema;
export type ProviderNormalizedRun = ProviderNormalizedEvent["run"];
export type ProviderNormalizedJob = ProviderNormalizedEvent["jobs"][number];
export type ProviderForensicsEvidence = Pick<ProviderNormalizedEvent, "diff" | "logs" | "metrics" | "traces" | "artifact" | "links" | "capabilities" | "warnings" | "truncated" | "redactionsApplied">;

// Keep these imports observable to downstream consumers without retaining raw CI payloads.
export type { CIJob, CIWorkflowRun, Goal23EventEnvelope };
