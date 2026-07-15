import { z } from "zod";

export const SCHEMA_VERSION = "1.0" as const;

const MAX_SERVICES = 25;
const MAX_ALERTS = 100;
const MAX_SERIES = 50;
const MAX_SAMPLES_PER_SERIES = 1_440;
const MAX_TIME_RANGE_MS = 86_400_000;

export const LogicalIdSchema = z
  .string()
  .min(1)
  .max(64)
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/, "must be a logical identifier");

export const BoundedTextSchema = z
  .string()
  .max(1_024)
  .refine((value) => !/[<>]/.test(value), "must not contain markup");

export const UtcTimestampSchema = z
  .iso
  .datetime({ offset: true })
  .refine((value) => value.endsWith("Z"), "must be an RFC 3339 UTC timestamp");

const WarningSchema = z
  .object({
    code: LogicalIdSchema,
    message: BoundedTextSchema.max(512),
  })
  .strict();

export const ProviderClassSchema = z.enum([
  "fake",
  "grafana",
  "prometheus-compatible",
  "grafana-alertmanager",
  "composite",
]);
export const FreshnessSchema = z.enum(["fresh", "cached", "stale", "unknown"]);

export const CommonEvidenceFieldsSchema = z
  .object({
    schemaVersion: z.literal(SCHEMA_VERSION),
    observedAt: UtcTimestampSchema,
    providerClass: ProviderClassSchema,
    freshness: FreshnessSchema,
    truncated: z.boolean(),
    redactionsApplied: z.boolean(),
    warnings: z.array(WarningSchema).max(20),
  })
  .strict();

function evidenceEnvelope<TData extends z.ZodType>(data: TData) {
  return CommonEvidenceFieldsSchema.extend({ data }).strict();
}

const ServiceInputSchema = z
  .object({
    services: z.array(LogicalIdSchema).min(1).max(MAX_SERVICES),
  })
  .strict();

export const CapabilitiesInputSchema = z.object({}).strict();

export const HealthSnapshotInputSchema = ServiceInputSchema;

export const ActiveAlertsInputSchema = z
  .object({
    services: z.array(LogicalIdSchema).min(1).max(MAX_SERVICES).optional(),
    states: z.array(z.enum(["firing", "pending", "resolved"])).min(1).max(3).optional(),
    severities: z.array(z.enum(["critical", "warning", "info"])).min(1).max(3).optional(),
  })
  .strict();

export const QueryMetricsInputSchema = z
  .object({
    queryTemplate: LogicalIdSchema,
    at: UtcTimestampSchema.optional(),
    from: UtcTimestampSchema.optional(),
    to: UtcTimestampSchema.optional(),
    stepMs: z.number().int().min(1_000).max(3_600_000).optional(),
  })
  .strict()
  .superRefine((value, context) => {
    const hasRangeField = value.from !== undefined || value.to !== undefined || value.stepMs !== undefined;
    if (value.at !== undefined && hasRangeField) {
      context.addIssue({ code: "custom", message: "instant and range inputs cannot be combined" });
      return;
    }
    if (!hasRangeField) return;
    if (value.from === undefined || value.to === undefined || value.stepMs === undefined) {
      context.addIssue({ code: "custom", message: "range queries require from, to, and stepMs" });
      return;
    }
    const durationMs = Date.parse(value.to) - Date.parse(value.from);
    if (durationMs <= 0 || durationMs > MAX_TIME_RANGE_MS) {
      context.addIssue({ code: "custom", message: "range must be greater than zero and no more than 24 hours" });
    }
  });

const TimeRangeSchema = z
  .object({
    from: UtcTimestampSchema,
    to: UtcTimestampSchema,
  })
  .strict()
  .superRefine((value, context) => {
    const durationMs = Date.parse(value.to) - Date.parse(value.from);
    if (durationMs <= 0 || durationMs > MAX_TIME_RANGE_MS) {
      context.addIssue({ code: "custom", message: "range must be greater than zero and no more than 24 hours" });
    }
  });

const RenderOptionsSchema = z
  .object({
    theme: z.enum(["light", "dark"]).default("dark"),
  })
  .strict();

export const RenderPanelInputSchema = TimeRangeSchema.extend({
  dashboardId: LogicalIdSchema,
  panelId: LogicalIdSchema,
  width: z.number().int().min(32).max(1_600).default(1_600),
  height: z.number().int().min(32).max(900).default(900),
  theme: RenderOptionsSchema.shape.theme,
}).strict();

export const RenderDashboardInputSchema = TimeRangeSchema.extend({
  dashboardId: LogicalIdSchema,
  width: z.number().int().min(32).max(2_400).default(2_400),
  height: z.number().int().min(32).max(4_000).default(4_000),
  theme: RenderOptionsSchema.shape.theme,
}).strict();

export const IncidentContextInputSchema = z
  .object({
    alertId: LogicalIdSchema.optional(),
    serviceId: LogicalIdSchema.optional(),
    includeVisuals: z.enum(["none", "panels", "dashboard"]).default("none"),
  })
  .strict()
  .superRefine((value, context) => {
    if ((value.alertId === undefined) === (value.serviceId === undefined)) {
      context.addIssue({ code: "custom", message: "provide exactly one of alertId or serviceId" });
    }
  });

const CapabilitiesDataSchema = z
  .object({
    providerClasses: z.array(ProviderClassSchema).min(1).max(4),
    enabledTools: z.array(LogicalIdSchema).min(1).max(7),
    limits: z
      .object({
        maxServices: z.number().int().min(1).max(MAX_SERVICES),
        maxAlerts: z.number().int().min(1).max(MAX_ALERTS),
        maxSeries: z.number().int().min(1).max(MAX_SERIES),
        maxRenderWidth: z.number().int().min(1).max(2_400),
        maxRenderHeight: z.number().int().min(1).max(4_000),
      })
      .strict(),
    featureFlags: z.array(LogicalIdSchema).max(20),
  })
  .strict();

const HealthTargetSchema = z
  .object({
    serviceId: LogicalIdSchema,
    status: z.enum(["healthy", "degraded", "unhealthy", "unknown"]),
    summary: BoundedTextSchema.max(512),
    checkedAt: UtcTimestampSchema,
  })
  .strict();

const SafeAnnotationsSchema = z
  .object({
    summary: BoundedTextSchema.max(512).optional(),
    description: BoundedTextSchema.max(1_024).optional(),
    runbookRef: LogicalIdSchema.optional(),
  })
  .strict();

const AlertSchema = z
  .object({
    alertId: LogicalIdSchema,
    name: BoundedTextSchema.max(256),
    state: z.enum(["firing", "pending", "resolved"]),
    severity: z.enum(["critical", "warning", "info"]),
    startsAt: UtcTimestampSchema,
    serviceId: LogicalIdSchema,
    annotations: SafeAnnotationsSchema,
  })
  .strict();

const LabelsSchema = z
  .record(LogicalIdSchema, BoundedTextSchema.max(256))
  .refine((labels) => Object.keys(labels).length <= 20, "must contain at most 20 labels");

const MetricSampleSchema = z
  .object({
    timestamp: UtcTimestampSchema,
    value: z.number().finite(),
  })
  .strict();

const MetricSeriesSchema = z
  .object({
    name: LogicalIdSchema,
    labels: LabelsSchema,
    samples: z.array(MetricSampleSchema).min(1).max(MAX_SAMPLES_PER_SERIES),
  })
  .strict();

const MetricDataFields = {
    queryTemplate: LogicalIdSchema,
    series: z.array(MetricSeriesSchema).max(MAX_SERIES),
} as const;

const MetricDataSchema = z.discriminatedUnion("queryKind", [
  z.object({ ...MetricDataFields, queryKind: z.literal("instant") }).strict(),
  z
    .object({
      ...MetricDataFields,
      queryKind: z.literal("range"),
      from: UtcTimestampSchema,
      to: UtcTimestampSchema,
      stepMs: z.number().int().min(1_000).max(3_600_000),
    })
    .strict(),
]);

const DashboardReferenceSchema = z
  .object({
    dashboardId: LogicalIdSchema,
    title: BoundedTextSchema.max(256),
  })
  .strict();

const IncidentDataSchema = z
  .object({
    subject: z
      .object({
        alertId: LogicalIdSchema.optional(),
        serviceId: LogicalIdSchema.optional(),
      })
      .strict()
      .refine(
        (subject) => subject.alertId !== undefined || subject.serviceId !== undefined,
        "incident subjects require an alertId or serviceId",
      ),
    health: z.array(HealthTargetSchema).max(MAX_SERVICES),
    alerts: z.array(AlertSchema).max(MAX_ALERTS),
    dashboardRefs: z.array(DashboardReferenceSchema).max(5),
    visuals: z
      .object({
        requested: z.enum(["none", "panels", "dashboard"]),
        available: z.boolean(),
      })
      .strict(),
  })
  .strict();

const RenderIdentityFields = {
    dashboardId: LogicalIdSchema,
    panelId: LogicalIdSchema.optional(),
    requestedRange: TimeRangeSchema,
    width: z.number().int().min(1).max(2_400),
    height: z.number().int().min(1).max(4_000),
} as const;

const RenderDataSchema = z.discriminatedUnion("available", [
  z
    .object({
      ...RenderIdentityFields,
      available: z.literal(true),
      effectiveRange: TimeRangeSchema,
      rawByteSize: z.number().int().min(1).max(8 * 1_024 * 1_024),
      sha256: z.string().regex(/^[a-f0-9]{64}$/),
      renderDurationMs: z.number().int().min(0).max(30_000),
    })
    .strict(),
  z.object({ ...RenderIdentityFields, available: z.literal(false) }).strict(),
]);

export const CapabilitiesResultSchema = evidenceEnvelope(CapabilitiesDataSchema);
export const HealthSnapshotResultSchema = evidenceEnvelope(
  z.object({ targets: z.array(HealthTargetSchema).max(MAX_SERVICES) }).strict(),
);
export const ActiveAlertsResultSchema = evidenceEnvelope(
  z.object({ alerts: z.array(AlertSchema).max(MAX_ALERTS) }).strict(),
);
export const QueryMetricsResultSchema = evidenceEnvelope(MetricDataSchema);
export const IncidentContextResultSchema = evidenceEnvelope(IncidentDataSchema);
export const RenderPanelResultSchema = evidenceEnvelope(
  RenderDataSchema.superRefine((data, context) => {
    if (data.panelId === undefined) {
      context.addIssue({ code: "custom", message: "panel renders require panelId" });
    }
    if (
      data.width > 1_600 ||
      data.height > 900 ||
      (data.available && data.rawByteSize > 4 * 1_024 * 1_024)
    ) {
      context.addIssue({ code: "custom", message: "panel render exceeds its configured limit" });
    }
  }),
);
export const RenderDashboardResultSchema = evidenceEnvelope(
  RenderDataSchema.superRefine((data, context) => {
    if (data.panelId !== undefined) {
      context.addIssue({ code: "custom", message: "dashboard renders must not include panelId" });
    }
  }),
);

export type CommonEvidenceFields = z.infer<typeof CommonEvidenceFieldsSchema>;
export type CapabilitiesInput = Record<string, never>;
export type HealthSnapshotInput = z.infer<typeof HealthSnapshotInputSchema>;
export type ActiveAlertsInput = z.infer<typeof ActiveAlertsInputSchema>;
export type QueryMetricsInput = z.infer<typeof QueryMetricsInputSchema>;
export type IncidentContextInput = z.infer<typeof IncidentContextInputSchema>;
export type RenderPanelInput = z.infer<typeof RenderPanelInputSchema>;
export type RenderDashboardInput = z.infer<typeof RenderDashboardInputSchema>;
export type CapabilitiesResult = z.infer<typeof CapabilitiesResultSchema>;
export type HealthSnapshotResult = z.infer<typeof HealthSnapshotResultSchema>;
export type ActiveAlertsResult = z.infer<typeof ActiveAlertsResultSchema>;
export type QueryMetricsResult = z.infer<typeof QueryMetricsResultSchema>;
export type IncidentContextResult = z.infer<typeof IncidentContextResultSchema>;
export type RenderPanelResult = z.infer<typeof RenderPanelResultSchema>;
export type RenderDashboardResult = z.infer<typeof RenderDashboardResultSchema>;
