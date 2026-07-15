import { createHash } from "node:crypto";
import { z } from "zod";

import {
  TelemetryForensicsInputSchema,
  TelemetryForensicsResultSchema,
  TelemetryLogsResultSchema,
  TelemetryMetricsResultSchema,
  TelemetryTracesResultSchema,
  TELEMETRY_SCHEMA_VERSION,
  type TelemetryCorrelation,
  type TelemetryForensicsInput,
  type TelemetryForensicsResult,
  type TelemetryLogsResult,
  type TelemetryMetricsResult,
  type TelemetryTracesResult,
} from "../domain/telemetry-schemas.js";
import type { CILogEvidenceResult } from "../domain/ci-schemas.js";
import type { CIReadProvider } from "../providers/ci-provider.js";
import type { TelemetryEvidencePort } from "../providers/telemetry-evidence-provider.js";
import { buildTelemetryCorrelationKey } from "./correlation.js";

const DigestEmpty = createHash("sha256").update("").digest("hex");
const LogicalIdSchema = z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);

export interface TelemetryForensicsWorkerOptions {
  readonly ci: CIReadProvider;
  readonly telemetry: TelemetryEvidencePort;
  readonly ciSourceId: string;
  readonly metricsSourceId: string;
  readonly tracesSourceId: string;
  readonly clock?: () => Date;
}

/**
 * Read-only evidence coordinator. It aligns evidence on explicit dimensions
 * and reports coincidence only; it never turns a time-window match into cause.
 */
export class TelemetryForensicsWorker {
  readonly #options: TelemetryForensicsWorkerOptions;
  readonly #clock: () => Date;

  constructor(options: TelemetryForensicsWorkerOptions) {
    LogicalIdSchema.parse(options.ciSourceId);
    LogicalIdSchema.parse(options.metricsSourceId);
    LogicalIdSchema.parse(options.tracesSourceId);
    this.#options = options;
    this.#clock = options.clock ?? (() => new Date());
  }

  async collect(input: TelemetryForensicsInput): Promise<TelemetryForensicsResult> {
    const request = TelemetryForensicsInputSchema.parse(input);
    const correlation: TelemetryCorrelation = {
      runId: request.runId,
      jobId: request.jobId,
      commitSha: request.commitSha,
      serviceId: request.serviceId,
      from: request.from,
      to: request.to,
    };
    const correlationKey = buildTelemetryCorrelationKey(correlation);
    const queryInput = { correlation, limit: 100 } as const;
    const [status, ciLogs, metrics, traces] = await Promise.all([
      settle(() => this.#options.ci.getWorkflowStatus({ repo: request.repo, workflow: request.workflow, runId: request.runId })),
      settle(() => this.#options.ci.getLogEvidence({
        repo: request.repo,
        workflow: request.workflow,
        runId: request.runId,
        jobId: request.jobId,
        maxLines: request.maxLines,
      })),
      settle(() => this.#options.telemetry.queryMetrics({ ...queryInput, queryId: request.metricsQueryId })),
      settle(() => this.#options.telemetry.queryTraces({ ...queryInput, queryId: request.tracesQueryId })),
    ]);
    const logs = ciLogs.ok
      ? fromCILogEvidence(ciLogs.value, this.#options.ciSourceId, request.logsQueryId, correlation)
      : unavailableLogs(this.#options.ciSourceId, request.logsQueryId, correlation, this.#clock());
    const normalizedMetrics = metrics.ok ? metrics.value : unavailableMetrics(this.#options.metricsSourceId, correlation, request.metricsQueryId, this.#clock());
    const normalizedTraces = traces.ok ? traces.value : unavailableTraces(this.#options.tracesSourceId, correlation, request.tracesQueryId, this.#clock());
    const commitMatch = status.ok
      ? status.value.data.run.id === request.runId && status.value.data.run.sha === request.commitSha
        ? "matched"
        : "mismatched"
      : "unknown";
    const warnings = [
      ...(commitMatch === "mismatched" ? [{ code: "ci-correlation-mismatch", message: "CI run identity does not match the requested commit" }] : []),
      ...(!status.ok ? [{ code: "ci-evidence-unavailable", message: "CI run identity is unavailable" }] : []),
      ...(!ciLogs.ok ? [{ code: "ci-log-evidence-unavailable", message: "CI log evidence is unavailable" }] : []),
      ...(!metrics.ok ? [{ code: "metrics-evidence-unavailable", message: "Metrics evidence is unavailable" }] : []),
      ...(!traces.ok ? [{ code: "traces-evidence-unavailable", message: "Trace evidence is unavailable" }] : []),
    ];
    const result = {
      schemaVersion: TELEMETRY_SCHEMA_VERSION,
      observedAt: this.#clock().toISOString(),
      freshness: aggregateFreshness([logs, normalizedMetrics, normalizedTraces]),
      truncated: logs.truncated || normalizedMetrics.truncated || normalizedTraces.truncated,
      redactionsApplied: logs.redactionsApplied || normalizedMetrics.redactionsApplied || normalizedTraces.redactionsApplied,
      warnings,
      data: {
        correlationKey,
        commitMatch,
        causality: "not-established" as const,
        evidenceStatus: {
          logs: evidenceStatus(logs),
          metrics: evidenceStatus(normalizedMetrics),
          traces: evidenceStatus(normalizedTraces),
        },
        logs,
        metrics: normalizedMetrics,
        traces: normalizedTraces,
      },
    };
    return TelemetryForensicsResultSchema.parse(result);
  }
}

export { buildTelemetryCorrelationKey } from "./correlation.js";

function fromCILogEvidence(
  result: CILogEvidenceResult,
  sourceId: string,
  queryId: string,
  correlation: TelemetryCorrelation,
): TelemetryLogsResult {
  return TelemetryLogsResultSchema.parse({
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
    observedAt: result.observedAt,
    sourceId,
    freshness: result.freshness,
    truncated: result.truncated,
    redactionsApplied: result.redactionsApplied,
    warnings: result.warnings.length === 0 ? [] : [{ code: "ci-log-warning", message: "CI log evidence includes a provider warning" }],
    provenance: provenance(sourceId, queryId, correlation),
    data: {
      available: result.data.available,
      lineCount: result.data.lines.length,
      contentDigest: result.data.sha256,
    },
  });
}

function unavailableLogs(sourceId: string, queryId: string, correlation: TelemetryCorrelation, observedAt: Date): TelemetryLogsResult {
  return TelemetryLogsResultSchema.parse({
    ...baseUnknown(sourceId, queryId, correlation, observedAt),
    data: { available: false, lineCount: 0, contentDigest: DigestEmpty },
  });
}

function unavailableMetrics(sourceId: string, correlation: TelemetryCorrelation, queryId: string, observedAt: Date): TelemetryMetricsResult {
  return TelemetryMetricsResultSchema.parse({
    ...baseUnknown(sourceId, queryId, correlation, observedAt),
    data: { available: false, series: [] },
  });
}

function unavailableTraces(sourceId: string, correlation: TelemetryCorrelation, queryId: string, observedAt: Date): TelemetryTracesResult {
  return TelemetryTracesResultSchema.parse({
    ...baseUnknown(sourceId, queryId, correlation, observedAt),
    data: { available: false, spans: [] },
  });
}

function baseUnknown(sourceId: string, queryId: string, correlation: TelemetryCorrelation, observedAt: Date) {
  return {
    schemaVersion: TELEMETRY_SCHEMA_VERSION,
    observedAt: observedAt.toISOString(),
    sourceId,
    freshness: "unknown" as const,
    truncated: false,
    redactionsApplied: false,
    warnings: [{ code: "telemetry-unavailable", message: "Evidence source is unavailable" }],
    provenance: provenance(sourceId, queryId, correlation),
  };
}

function provenance(sourceId: string, queryId: string, correlation: TelemetryCorrelation) {
  return {
    sourceId,
    queryId,
    correlationKey: buildTelemetryCorrelationKey(correlation),
    requestedWindow: { from: correlation.from, to: correlation.to },
  };
}

function evidenceStatus(result: TelemetryLogsResult | TelemetryMetricsResult | TelemetryTracesResult): "matched" | "no-evidence" | "unavailable" {
  if (!result.data.available || result.freshness === "unknown") return "unavailable";
  if (("lineCount" in result.data && result.data.lineCount === 0) || ("series" in result.data && result.data.series.length === 0) || ("spans" in result.data && result.data.spans.length === 0)) return "no-evidence";
  return "matched";
}

function aggregateFreshness(results: readonly { freshness: "fresh" | "cached" | "stale" | "unknown" }[]): "fresh" | "cached" | "stale" | "unknown" {
  if (results.some((result) => result.freshness === "unknown")) return "unknown";
  if (results.some((result) => result.freshness === "stale")) return "stale";
  if (results.some((result) => result.freshness === "cached")) return "cached";
  return "fresh";
}

async function settle<T>(operation: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false }> {
  try {
    return { ok: true, value: await operation() };
  } catch {
    return { ok: false };
  }
}
