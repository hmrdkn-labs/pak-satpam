import { createHash } from "node:crypto";
import { z } from "zod";

import { redactText } from "../ci/redaction.js";

const WEBHOOK_SECRET_PATTERN = /\bwhsec_[A-Za-z0-9_-]+\b/i;
const WEBHOOK_SECRET_FIELD_PATTERN = /(?:webhook(?:[_-]?(?:signing|signature))?[_-]?(?:secret|token|key|signature)|(?:signing|signature)[_-]?secret)/i;

/** Maximum size accepted for a provider-neutral observer envelope. */
export const MAX_OBSERVER_EVENT_BYTES = 64 * 1024;

const SourceSchema = z.enum(["poll", "webhook"]);
const OutcomeSchema = z.enum(["success", "failure", "cancelled", "timed_out", "action_required", "skipped", "neutral", "stale", "unavailable", "malformed"]);
const ConclusionSchema = z.enum(["success", "failure", "cancelled", "timed_out", "skipped", "neutral", "action_required", "unknown"]);
const WarningSchema = z.object({ code: z.string().min(1).max(64), message: z.string().min(1).max(512) }).strict();

const AvailableBindingSchema = z.object({ available: z.literal(true), value: z.string().min(1).max(256) }).strict();
const UnavailableBindingSchema = z.object({ available: z.literal(false), reason: z.enum(["absent", "unavailable", "invalid"]) }).strict();
const BindingSchema = z.union([AvailableBindingSchema, UnavailableBindingSchema]);

export const EventCorrelationSchema = z.object({
  deploymentId: BindingSchema,
  commitSha: BindingSchema,
  artifactDigest: BindingSchema,
  traceId: BindingSchema,
}).strict();
export type EventCorrelation = z.infer<typeof EventCorrelationSchema>;

const IdentitySchema = z.object({
  dedupeKey: z.string().min(1).max(256),
  replayKey: z.string().min(1).max(256),
}).strict();

/** Goal23 status envelope. Legacy top-level fields intentionally remain. */
export const ObserverEventEnvelopeSchema = z.object({
  schemaVersion: z.literal("1.0"),
  type: z.literal("ci.run.observed"),
  eventId: z.string().min(1).max(256),
  dedupeKey: z.string().min(1).max(256),
  replayKey: z.string().min(1).max(256),
  identity: IdentitySchema,
  observedAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
  source: SourceSchema,
  providerClass: z.string().min(1).max(128).optional(),
  repo: z.string().min(3).max(200),
  workflow: z.string().min(1).max(200),
  runId: z.string().min(1).max(128),
  runAttempt: z.number().int().min(1).max(100),
  status: z.object({ state: z.literal("completed"), conclusion: ConclusionSchema, outcome: OutcomeSchema }).strict(),
  terminalConclusion: ConclusionSchema,
  outcome: OutcomeSchema,
  notification: z.enum(["failure", "recovery"]),
  severity: z.enum(["red", "green"]),
  threadId: z.string().min(1).max(256),
  freshness: z.enum(["fresh", "stale"]),
  updatedAt: z.iso.datetime({ offset: true }).refine((value) => value.endsWith("Z")),
  correlation: EventCorrelationSchema,
  warnings: z.array(WarningSchema).max(20),
}).strict();
export type ObserverEventEnvelope = z.infer<typeof ObserverEventEnvelopeSchema>;
export const Goal23EventEnvelopeSchema = ObserverEventEnvelopeSchema;
export type Goal23EventEnvelope = ObserverEventEnvelope;

export interface ObserverEventEnvelopeInput {
  readonly eventId: string;
  readonly dedupeKey?: string;
  readonly replayKey?: string;
  readonly observedAt: string;
  readonly source: "poll" | "webhook";
  readonly providerClass?: string;
  readonly repo: string;
  readonly workflow: string;
  readonly runId: string;
  readonly runAttempt: number;
  readonly terminalConclusion: string | null;
  readonly outcome: string;
  readonly notification: "failure" | "recovery";
  readonly severity: "red" | "green";
  readonly threadId: string;
  readonly freshness: "fresh" | "stale";
  readonly updatedAt: string;
  readonly correlation?: Partial<Record<keyof EventCorrelation, string | null | undefined>> & {
    readonly deployment?: string | null;
    readonly commit?: string | null;
    readonly digest?: string | null;
    readonly trace?: string | null;
  };
  readonly warnings?: readonly { code: string; message: string }[];
}

export function observerReplayKey(input: Pick<ObserverEventEnvelopeInput, "repo" | "workflow" | "runId" | "runAttempt">): string {
  return `${input.repo}:${input.workflow}:${input.runId}:${input.runAttempt}`;
}

export function createObserverEventEnvelope(input: ObserverEventEnvelopeInput): ObserverEventEnvelope {
  if (input === null || typeof input !== "object") throw new Error("event_envelope_missing");
  if (containsSecret(input)) throw new Error("event_envelope_secret");
  const conclusion = normalizeConclusion(input.terminalConclusion);
  const outcome = normalizeOutcome(input.outcome);
  const dedupeKey = input.eventId;
  const replayKey = observerReplayKey(input);
  if (input.dedupeKey !== undefined && input.dedupeKey !== dedupeKey) throw new Error("event_envelope_malformed");
  if (input.replayKey !== undefined && input.replayKey !== replayKey) throw new Error("event_envelope_malformed");
  const envelope = {
    schemaVersion: "1.0" as const,
    type: "ci.run.observed" as const,
    eventId: input.eventId,
    dedupeKey,
    replayKey,
    identity: { dedupeKey, replayKey },
    observedAt: input.observedAt,
    source: input.source,
    ...(input.providerClass === undefined ? {} : { providerClass: input.providerClass }),
    repo: input.repo,
    workflow: input.workflow,
    runId: input.runId,
    runAttempt: input.runAttempt,
    status: { state: "completed" as const, conclusion, outcome },
    terminalConclusion: conclusion,
    outcome,
    notification: input.notification,
    severity: input.severity,
    threadId: input.threadId,
    freshness: input.freshness,
    updatedAt: input.updatedAt,
    correlation: normalizeCorrelation(input.correlation),
    warnings: input.warnings === undefined ? [] : [...input.warnings],
  };
  try { return ObserverEventEnvelopeSchema.parse(envelope); } catch { throw new Error("event_envelope_malformed"); }
}

export const createGoal23EventEnvelope = createObserverEventEnvelope;
export const buildObserverEventEnvelope = createObserverEventEnvelope;
export const createEventEnvelope = createObserverEventEnvelope;
export const stableReplayKey = observerReplayKey;
export const validateObserverEventEnvelope = (value: unknown): ObserverEventEnvelope => {
  try { return ObserverEventEnvelopeSchema.parse(value); } catch { throw new Error("event_envelope_malformed"); }
};

export function serializeObserverEventEnvelope(value: ObserverEventEnvelopeInput | ObserverEventEnvelope, maxBytes = MAX_OBSERVER_EVENT_BYTES): string {
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_OBSERVER_EVENT_BYTES) throw new Error("event_envelope_size_limit");
  if (containsSecret(value)) throw new Error("event_envelope_secret");
  const envelope = ObserverEventEnvelopeSchema.safeParse(value).success
    ? ObserverEventEnvelopeSchema.parse(value)
    : createObserverEventEnvelope(value as ObserverEventEnvelopeInput);
  const body = JSON.stringify(envelope);
  if (Buffer.byteLength(body, "utf8") > maxBytes) throw new Error("event_envelope_too_large");
  return body;
}
export const serializeEventEnvelope = serializeObserverEventEnvelope;

function normalizeConclusion(value: string | null): z.infer<typeof ConclusionSchema> {
  if (value === null) return "unknown";
  if (ConclusionSchema.safeParse(value).success) return value as z.infer<typeof ConclusionSchema>;
  throw new Error("event_envelope_malformed");
}

function normalizeOutcome(value: string): z.infer<typeof OutcomeSchema> {
  if (OutcomeSchema.safeParse(value).success) return value as z.infer<typeof OutcomeSchema>;
  throw new Error("event_envelope_malformed");
}

function normalizeCorrelation(input: ObserverEventEnvelopeInput["correlation"]): EventCorrelation {
  return {
    deploymentId: bindingValue(input?.deploymentId ?? input?.deployment, 128),
    commitSha: bindingValue(input?.commitSha ?? input?.commit, 128, /^[a-f0-9]{40}$/),
    artifactDigest: bindingValue(input?.artifactDigest ?? input?.digest, 256, /^(?:sha256:)?[a-f0-9]{64}$/),
    traceId: bindingValue(input?.traceId ?? input?.trace, 128),
  };
}

function bindingValue(value: unknown, max: number, pattern?: RegExp): z.infer<typeof BindingSchema> {
  const structured = BindingSchema.safeParse(value);
  if (structured.success) {
    const parsed = structured.data;
    if (!parsed.available) return parsed;
    const safe = redactText(parsed.value, max);
    if (safe.redactionsApplied) throw new Error("event_envelope_secret");
    if (safe.truncated || (pattern !== undefined && !pattern.test(parsed.value))) throw new Error("event_envelope_malformed");
    return parsed;
  }
  if (typeof value !== "string" && value !== null && value !== undefined) throw new Error("event_envelope_malformed");
  if (value === undefined || value === null || value === "") return { available: false, reason: "absent" };
  const safe = redactText(value, max);
  if (safe.redactionsApplied) throw new Error("event_envelope_secret");
  if (safe.truncated || (pattern !== undefined && !pattern.test(value))) throw new Error("event_envelope_malformed");
  return { available: true, value };
}

function containsSecret(value: unknown, fieldName?: string): boolean {
  if (typeof value === "string") {
    return WEBHOOK_SECRET_PATTERN.test(value)
      || (fieldName !== undefined && WEBHOOK_SECRET_FIELD_PATTERN.test(fieldName))
      || redactText(value, 4_096).redactionsApplied;
  }
  if (Array.isArray(value)) return value.some((item) => containsSecret(item));
  if (value !== null && typeof value === "object") {
    return Object.entries(value).some(([key, child]) => WEBHOOK_SECRET_FIELD_PATTERN.test(key) || redactText(key, 256).redactionsApplied || containsSecret(child, key));
  }
  return false;
}

/** Stable digest for diagnostics; never used as a transition or routing input. */
export function observerEnvelopeDigest(value: ObserverEventEnvelope): string {
  return createHash("sha256").update(serializeObserverEventEnvelope(value), "utf8").digest("hex");
}
