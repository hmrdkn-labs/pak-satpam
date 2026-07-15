import { z } from "zod";

export const TELEMETRY_SCHEMA_VERSION = "1.0" as const;
export const MAX_TELEMETRY_WINDOW_MS = 86_400_000;
export const MAX_TELEMETRY_ITEMS = 100;
export const MAX_TELEMETRY_SAMPLES = 1_440;

const LogicalIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/, "must be a logical identifier");
const UtcTimestampSchema = z
  .iso
  .datetime({ offset: true })
  .refine((value) => value.endsWith("Z"), "must be an RFC 3339 UTC timestamp");
const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/);

export const TelemetryCorrelationSchema = z
  .object({
    runId: LogicalIdSchema,
    jobId: LogicalIdSchema,
    commitSha: z.string().regex(/^[a-f0-9]{40}$/),
    serviceId: LogicalIdSchema,
    from: UtcTimestampSchema,
    to: UtcTimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    const durationMs = Date.parse(value.to) - Date.parse(value.from);
    if (durationMs <= 0 || durationMs > MAX_TELEMETRY_WINDOW_MS) {
      context.addIssue({ code: "custom", message: "window must be greater than zero and no more than 24 hours" });
    }
  });

export const TelemetryQueryInputSchema = z
  .object({
    queryId: LogicalIdSchema,
    correlation: TelemetryCorrelationSchema,
    limit: z.number().int().min(1).max(MAX_TELEMETRY_ITEMS).default(MAX_TELEMETRY_ITEMS),
  })
  .strict();

const WarningSchema = z.object({ code: LogicalIdSchema, message: z.string().min(1).max(512) }).strict();
const RequestedWindowSchema = z.object({ from: UtcTimestampSchema, to: UtcTimestampSchema }).strict();
const ProvenanceSchema = z
  .object({
    sourceId: LogicalIdSchema,
    queryId: LogicalIdSchema,
    correlationKey: z.string().min(1).max(512),
    requestedWindow: RequestedWindowSchema,
  })
  .strict();

const EnvelopeFields = {
  schemaVersion: z.literal(TELEMETRY_SCHEMA_VERSION),
  observedAt: UtcTimestampSchema,
  sourceId: LogicalIdSchema,
  freshness: z.enum(["fresh", "cached", "stale", "unknown"]),
  truncated: z.boolean(),
  redactionsApplied: z.boolean(),
  warnings: z.array(WarningSchema).max(20),
  provenance: ProvenanceSchema,
} as const;

const LogsDataSchema = z
  .object({
    available: z.boolean(),
    lineCount: z.number().int().min(0).max(MAX_TELEMETRY_ITEMS),
    contentDigest: DigestSchema,
  })
  .strict();
const MetricSampleSchema = z.object({ timestamp: UtcTimestampSchema, value: z.number().finite() }).strict();
const MetricSeriesSchema = z
  .object({
    seriesDigest: DigestSchema,
    samples: z.array(MetricSampleSchema).max(MAX_TELEMETRY_SAMPLES),
  })
  .strict();
const MetricsDataSchema = z
  .object({
    available: z.boolean(),
    series: z.array(MetricSeriesSchema).max(MAX_TELEMETRY_ITEMS),
  })
  .strict();
const TraceSpanSchema = z
  .object({
    spanDigest: DigestSchema,
    durationMs: z.number().finite().min(0).max(86_400_000),
    status: z.enum(["ok", "error", "unknown"]),
  })
  .strict();
const TracesDataSchema = z
  .object({
    available: z.boolean(),
    spans: z.array(TraceSpanSchema).max(MAX_TELEMETRY_ITEMS),
  })
  .strict();

function envelope<T extends z.ZodType>(data: T) {
  return z.object({ ...EnvelopeFields, data }).strict();
}

export const TelemetryLogsResultSchema = envelope(LogsDataSchema);
export const TelemetryMetricsResultSchema = envelope(MetricsDataSchema);
export const TelemetryTracesResultSchema = envelope(TracesDataSchema);

export const TelemetryForensicsInputSchema = z
  .object({
    repo: z.string().min(3).max(200).regex(/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/),
    workflow: z.string().min(1).max(200).regex(/^[A-Za-z0-9_./@-]+$/),
    runId: LogicalIdSchema,
    jobId: LogicalIdSchema,
    commitSha: z.string().regex(/^[a-f0-9]{40}$/),
    serviceId: LogicalIdSchema,
    from: UtcTimestampSchema,
    to: UtcTimestampSchema,
    logsQueryId: LogicalIdSchema,
    metricsQueryId: LogicalIdSchema,
    tracesQueryId: LogicalIdSchema,
    maxLines: z.number().int().min(1).max(200).default(80),
  })
  .strict()
  .superRefine((value, context) => {
    const durationMs = Date.parse(value.to) - Date.parse(value.from);
    if (durationMs <= 0 || durationMs > MAX_TELEMETRY_WINDOW_MS) {
      context.addIssue({ code: "custom", message: "window must be greater than zero and no more than 24 hours" });
    }
  });

const EvidenceStatusSchema = z.enum(["matched", "no-evidence", "unavailable"]);
const ForensicsDataSchema = z
  .object({
    correlationKey: z.string().min(1).max(512),
    commitMatch: z.enum(["matched", "mismatched", "unknown"]),
    causality: z.literal("not-established"),
    evidenceStatus: z
      .object({ logs: EvidenceStatusSchema, metrics: EvidenceStatusSchema, traces: EvidenceStatusSchema })
      .strict(),
    logs: TelemetryLogsResultSchema,
    metrics: TelemetryMetricsResultSchema,
    traces: TelemetryTracesResultSchema,
  })
  .strict();

export const TelemetryForensicsResultSchema = z
  .object({
    schemaVersion: z.literal(TELEMETRY_SCHEMA_VERSION),
    observedAt: UtcTimestampSchema,
    freshness: z.enum(["fresh", "cached", "stale", "unknown"]),
    truncated: z.boolean(),
    redactionsApplied: z.boolean(),
    warnings: z.array(WarningSchema).max(20),
    data: ForensicsDataSchema,
  })
  .strict();

export type TelemetryCorrelation = z.infer<typeof TelemetryCorrelationSchema>;
export type TelemetryQueryInput = z.input<typeof TelemetryQueryInputSchema>;
export type TelemetryLogsResult = z.infer<typeof TelemetryLogsResultSchema>;
export type TelemetryMetricsResult = z.infer<typeof TelemetryMetricsResultSchema>;
export type TelemetryTracesResult = z.infer<typeof TelemetryTracesResultSchema>;
export type TelemetryForensicsInput = z.input<typeof TelemetryForensicsInputSchema>;
export type TelemetryForensicsResult = z.infer<typeof TelemetryForensicsResultSchema>;
