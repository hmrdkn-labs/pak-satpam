import { createHash } from "node:crypto";
import { z } from "zod";

import { redactText } from "../ci/redaction.js";
import {
  TelemetryLogsResultSchema,
  TelemetryMetricsResultSchema,
  TelemetryQueryInputSchema,
  TelemetryTracesResultSchema,
  TELEMETRY_SCHEMA_VERSION,
  MAX_TELEMETRY_ITEMS,
  MAX_TELEMETRY_SAMPLES,
  type TelemetryCorrelation,
  type TelemetryLogsResult,
  type TelemetryMetricsResult,
  type TelemetryQueryInput,
  type TelemetryTracesResult,
} from "../domain/telemetry-schemas.js";
import { buildTelemetryCorrelationKey } from "../telemetry/correlation.js";

const DEFAULT_TIMEOUT_MS = 5_000;
const DEFAULT_MAX_RESPONSE_BYTES = 1_024 * 1_024;
const LogicalIdSchema = z.string().min(1).max(64).regex(/^[A-Za-z0-9][A-Za-z0-9._:-]*$/);
const DigestEmpty = createHash("sha256").update("").digest("hex");

export type TelemetryQueryKind = "logs" | "metrics" | "traces";
type CorrelationField = keyof TelemetryCorrelation;

export interface TelemetryQueryDefinition {
  readonly kind: TelemetryQueryKind;
  /** Relative route owned by deployment configuration, never supplied by a caller. */
  readonly route: string;
  /** Static query text owned by deployment configuration. */
  readonly expression?: string;
  /** Optional backend parameter name for the static expression. */
  readonly queryParameter?: string;
  /** Backend parameter names for correlation dimensions. */
  readonly parameterMap?: Partial<Record<CorrelationField, string>>;
}

export interface TelemetryEvidencePort {
  queryLogs(input: TelemetryQueryInput): Promise<TelemetryLogsResult>;
  queryMetrics(input: TelemetryQueryInput): Promise<TelemetryMetricsResult>;
  queryTraces(input: TelemetryQueryInput): Promise<TelemetryTracesResult>;
}

export interface TelemetryHttpEvidenceAdapterOptions {
  readonly sourceId: string;
  readonly baseUrl: string;
  readonly fetch: typeof globalThis.fetch;
  readonly queries: Readonly<Record<string, TelemetryQueryDefinition>>;
  readonly token?: string;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly limits?: {
    readonly maxSeries?: number;
    readonly maxSamples?: number;
    readonly maxSpans?: number;
  };
}

export class TelemetryQueryError extends Error {
  constructor(readonly code: "unsupported" | "kind-mismatch" | "invalid-route" | "unavailable") {
    super(`Telemetry query ${code}`);
    this.name = "TelemetryQueryError";
  }
}

/**
 * Provider-neutral read adapter. Deployments inject routes and static queries;
 * callers can select only logical query IDs and bounded correlation windows.
 */
export class TelemetryHttpEvidenceAdapter implements TelemetryEvidencePort {
  readonly #options: TelemetryHttpEvidenceAdapterOptions;
  readonly #baseUrl: URL;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #maxSeries: number;
  readonly #maxSamples: number;
  readonly #maxSpans: number;

  constructor(options: TelemetryHttpEvidenceAdapterOptions) {
    LogicalIdSchema.parse(options.sourceId);
    this.#options = options;
    this.#baseUrl = normalizeBaseUrl(options.baseUrl);
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#maxResponseBytes = options.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
    this.#maxSeries = options.limits?.maxSeries ?? MAX_TELEMETRY_ITEMS;
    this.#maxSamples = options.limits?.maxSamples ?? MAX_TELEMETRY_SAMPLES;
    this.#maxSpans = options.limits?.maxSpans ?? MAX_TELEMETRY_ITEMS;
    if (!Number.isInteger(this.#timeoutMs) || this.#timeoutMs < 1 || this.#timeoutMs > 30_000) {
      throw new Error("timeoutMs must be between 1 and 30000");
    }
    if (!Number.isInteger(this.#maxResponseBytes) || this.#maxResponseBytes < 1 || this.#maxResponseBytes > 8 * 1_024 * 1_024) {
      throw new Error("maxResponseBytes must be between 1 and 8388608");
    }
    if (![this.#maxSeries, this.#maxSamples, this.#maxSpans].every((value) => Number.isInteger(value) && value >= 1 && value <= MAX_TELEMETRY_SAMPLES)) {
      throw new Error("telemetry limits are invalid");
    }
    for (const [queryId, query] of Object.entries(options.queries)) {
      LogicalIdSchema.parse(queryId);
      validateRoute(this.#baseUrl, query.route);
      if (query.expression !== undefined && (query.expression.length === 0 || query.expression.length > 4_096)) throw new Error("query expression is invalid");
    }
  }

  queryLogs(input: TelemetryQueryInput): Promise<TelemetryLogsResult> {
    return this.query<"logs", TelemetryLogsResult>("logs", input, (payload, limit, correlation) => normalizeLogs(payload, limit, correlation));
  }

  queryMetrics(input: TelemetryQueryInput): Promise<TelemetryMetricsResult> {
    return this.query<"metrics", TelemetryMetricsResult>("metrics", input, (payload, limit, correlation) => normalizeMetrics(payload, limit, this.#maxSeries, this.#maxSamples, correlation));
  }

  queryTraces(input: TelemetryQueryInput): Promise<TelemetryTracesResult> {
    return this.query<"traces", TelemetryTracesResult>("traces", input, (payload, limit, correlation) => normalizeTraces(payload, limit, this.#maxSpans, correlation));
  }

  private async query<TKind extends TelemetryQueryKind, TResult>(
    kind: TKind,
    input: TelemetryQueryInput,
    normalize: (payload: unknown, limit: number, correlation: TelemetryCorrelation) => Normalized<TKind>,
  ): Promise<TResult> {
    const request = TelemetryQueryInputSchema.parse(input);
    const definition = this.#options.queries[request.queryId];
    if (definition === undefined) throw new TelemetryQueryError("unsupported");
    if (definition.kind !== kind) throw new TelemetryQueryError("kind-mismatch");
    const observedAt = new Date().toISOString();
    const provenance = {
      sourceId: this.#options.sourceId,
      queryId: request.queryId,
      correlationKey: buildTelemetryCorrelationKey(request.correlation),
      requestedWindow: { from: request.correlation.from, to: request.correlation.to },
    };
    let payload: unknown;
    try {
      const response = await this.request(definition, request);
      if (!response.ok) return this.unavailable<TResult>(kind, observedAt, provenance);
      payload = JSON.parse(await readBoundedText(response, this.#maxResponseBytes));
    } catch {
      return this.unavailable<TResult>(kind, observedAt, provenance);
    }
    const normalized = normalize(payload, request.limit, request.correlation);
    return this.result<TResult>(observedAt, provenance, normalized);
  }

  private async request(definition: TelemetryQueryDefinition, input: TelemetryQueryInput): Promise<Response> {
    const url = configuredUrl(this.#baseUrl, definition.route);
    const parameterMap = {
      runId: "run_id",
      jobId: "job_id",
      commitSha: "commit",
      serviceId: "service",
      from: "from",
      to: "to",
      ...(definition.parameterMap ?? {}),
    } satisfies Partial<Record<CorrelationField, string>>;
    for (const field of ["runId", "jobId", "commitSha", "serviceId", "from", "to"] as const) {
      const parameter = parameterMap[field];
      if (parameter !== undefined) url.searchParams.set(parameter, input.correlation[field]);
    }
    if (definition.expression !== undefined) {
      url.searchParams.set(definition.queryParameter ?? "query", definition.expression);
    }
    url.searchParams.set("limit", String(input.limit));
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#timeoutMs);
    const token = this.#options.token?.trim();
    try {
      return await this.#options.fetch(url, {
        method: "GET",
        redirect: "error",
        headers: {
          Accept: "application/json",
          ...(token === undefined || token === ""
            ? {}
            : { Authorization: `Bearer ${token}` }),
        },
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }
  }

  private result<TResult>(
    observedAt: string,
    provenance: { sourceId: string; queryId: string; correlationKey: string; requestedWindow: { from: string; to: string } },
    normalized: Normalized<TelemetryQueryKind>,
  ): TResult {
    const base = {
      schemaVersion: TELEMETRY_SCHEMA_VERSION,
      observedAt,
      sourceId: this.#options.sourceId,
      freshness: normalized.data.available ? "fresh" as const : "unknown" as const,
      truncated: normalized.truncated,
      redactionsApplied: normalized.redactionsApplied,
      warnings: [
        ...(normalized.data.available ? [] : [{ code: "telemetry-unavailable", message: "Evidence source returned no usable evidence" }]),
        ...(normalized.truncated ? [{ code: "telemetry-truncated", message: "Evidence exceeded configured limits" }] : []),
      ],
      provenance,
      data: normalized.data,
    };
    if (normalized.kind === "logs") return TelemetryLogsResultSchema.parse(base) as TResult;
    if (normalized.kind === "metrics") return TelemetryMetricsResultSchema.parse(base) as TResult;
    return TelemetryTracesResultSchema.parse(base) as TResult;
  }

  private unavailable<TResult>(
    kind: TelemetryQueryKind,
    observedAt: string,
    provenance: { sourceId: string; queryId: string; correlationKey: string; requestedWindow: { from: string; to: string } },
  ): TResult {
    const base = {
      schemaVersion: TELEMETRY_SCHEMA_VERSION,
      observedAt,
      sourceId: this.#options.sourceId,
      freshness: "unknown",
      truncated: false,
      redactionsApplied: false,
      warnings: [{ code: "telemetry-unavailable", message: "Evidence source is unavailable" }],
      provenance,
    };
    if (kind === "logs") {
      return TelemetryLogsResultSchema.parse({ ...base, data: { available: false, lineCount: 0, contentDigest: DigestEmpty } }) as TResult;
    }
    if (kind === "metrics") return TelemetryMetricsResultSchema.parse({ ...base, data: { available: false, series: [] } }) as TResult;
    return TelemetryTracesResultSchema.parse({ ...base, data: { available: false, spans: [] } }) as TResult;
  }
}

type Normalized<K extends TelemetryQueryKind> = K extends "logs"
  ? { kind: "logs"; truncated: boolean; redactionsApplied: boolean; data: TelemetryLogsResult["data"] }
  : K extends "metrics"
    ? { kind: "metrics"; truncated: boolean; redactionsApplied: boolean; data: TelemetryMetricsResult["data"] }
    : { kind: "traces"; truncated: boolean; redactionsApplied: boolean; data: TelemetryTracesResult["data"] };

function normalizeLogs(payload: unknown, limit: number, correlation: TelemetryCorrelation): Normalized<"logs"> {
  const records = arrayField(payload, "logs") ?? arrayField(payload, "events");
  if (records === undefined) return unavailableNormalized("logs");
  const selected = records.slice(0, limit);
  let redactionsApplied = records.length > selected.length;
  const digests: string[] = [];
  for (const record of selected) {
    const timestamp = stringField(record, "timestamp") ?? stringField(record, "time");
    const message = stringField(record, "message") ?? stringField(record, "text");
    if (timestamp === undefined || !withinWindow(timestamp, correlation) || message === undefined) {
      redactionsApplied = true;
      continue;
    }
    const redacted = redactText(message, 1_024);
    redactionsApplied ||= redacted.redacted;
    digests.push(redacted.text);
  }
  return {
    kind: "logs",
    truncated: records.length > limit,
    redactionsApplied,
    data: {
      available: true,
      lineCount: digests.length,
      contentDigest: createHash("sha256").update(digests.join("\n")).digest("hex"),
    },
  };
}

function normalizeMetrics(payload: unknown, limit: number, maxSeries: number, maxSamples: number, correlation: TelemetryCorrelation): Normalized<"metrics"> {
  const records = arrayField(payload, "metrics") ?? arrayField(payload, "series");
  if (records === undefined) return unavailableNormalized("metrics");
  const selected = records.slice(0, Math.min(limit, maxSeries));
  let truncated = records.length > selected.length;
  let redactionsApplied = false;
  const series: TelemetryMetricsResult["data"]["series"] = [];
  for (const record of selected) {
    const samples = arrayField(record, "samples") ?? arrayField(record, "values") ?? [];
    const parsedSamples = samples.slice(0, maxSamples).flatMap((sample) => parseSample(sample)).filter((sample) => withinWindow(sample.timestamp, correlation));
    truncated ||= samples.length > maxSamples;
    const labels = recordField(record, "labels") ?? {};
    const name = stringField(record, "name") ?? stringField(record, "metric") ?? "metric";
    const labelText = JSON.stringify(labels);
    const redactedName = redactText(name, 256);
    const redactedLabels = redactText(labelText, 1_024);
    redactionsApplied ||= redactedName.redacted || redactedLabels.redacted;
    if (parsedSamples.length === 0) {
      redactionsApplied = true;
      continue;
    }
    series.push({
      seriesDigest: createHash("sha256").update(`${redactedName.text}|${redactedLabels.text}`).digest("hex"),
      samples: parsedSamples,
    });
  }
  return { kind: "metrics", truncated, redactionsApplied, data: { available: true, series } };
}

function normalizeTraces(payload: unknown, limit: number, maxSpans: number, correlation: TelemetryCorrelation): Normalized<"traces"> {
  const records = arrayField(payload, "spans") ?? arrayField(payload, "traces");
  if (records === undefined) return unavailableNormalized("traces");
  const selected = records.slice(0, Math.min(limit, maxSpans));
  let redactionsApplied = records.length > selected.length;
  const spans: TelemetryTracesResult["data"]["spans"] = [];
  for (const record of selected) {
    const traceId = stringField(record, "traceId") ?? stringField(record, "trace_id") ?? "trace";
    const spanId = stringField(record, "spanId") ?? stringField(record, "span_id") ?? "span";
    const service = stringField(record, "service") ?? "service";
    const operation = stringField(record, "operation") ?? stringField(record, "name") ?? "operation";
    const timestamp = stringField(record, "timestamp") ?? stringField(record, "startTime") ?? stringField(record, "start_time");
    const statusValue = stringField(record, "status");
    const status = statusValue === "ok" ? "ok" : statusValue === "error" ? "error" : "unknown";
    const duration = Number(recordField(record, "durationMs") ?? recordField(record, "duration_ms"));
    if (!Number.isFinite(duration) || duration < 0) {
      redactionsApplied = true;
      continue;
    }
    if (timestamp !== undefined && !withinWindow(timestamp, correlation)) {
      redactionsApplied = true;
      continue;
    }
    for (const value of [traceId, spanId, service, operation]) redactionsApplied ||= redactText(value, 256).redacted;
    spans.push({
      spanDigest: createHash("sha256").update(`${traceId}|${spanId}|${service}|${operation}`).digest("hex"),
      durationMs: Math.min(duration, 86_400_000),
      status,
    });
  }
  return { kind: "traces", truncated: records.length > selected.length, redactionsApplied, data: { available: true, spans } };
}

function parseSample(value: unknown): Array<{ timestamp: string; value: number }> {
  if (Array.isArray(value) && value.length === 2) {
    const numericTimestamp = Number(value[0]);
    const date = Number.isFinite(numericTimestamp) ? new Date(numericTimestamp * 1_000) : undefined;
    const timestamp = typeof value[0] === "string" ? value[0] : date !== undefined && Number.isFinite(date.getTime()) ? date.toISOString() : "";
    const numeric = Number(value[1]);
    return validTimestamp(timestamp) && Number.isFinite(numeric) ? [{ timestamp, value: numeric }] : [];
  }
  const record = recordField(value, "timestamp") === undefined ? undefined : value;
  const timestamp = stringField(record, "timestamp");
  const numeric = Number(recordField(record, "value"));
  return timestamp !== undefined && validTimestamp(timestamp) && Number.isFinite(numeric) ? [{ timestamp, value: numeric }] : [];
}

function unavailableNormalized(kind: "logs"): Normalized<"logs">;
function unavailableNormalized(kind: "metrics"): Normalized<"metrics">;
function unavailableNormalized(kind: "traces"): Normalized<"traces">;
function unavailableNormalized(kind: "logs" | "metrics" | "traces"): Normalized<TelemetryQueryKind> {
  if (kind === "logs") return {
    kind,
    truncated: false,
    redactionsApplied: false,
    data: { available: false, lineCount: 0, contentDigest: DigestEmpty },
  };
  if (kind === "metrics") return { kind, truncated: false, redactionsApplied: false, data: { available: false, series: [] } };
  return { kind, truncated: false, redactionsApplied: false, data: { available: false, spans: [] } };
}

function arrayField(value: unknown, key: string): unknown[] | undefined {
  const direct = recordField(value, key);
  if (Array.isArray(direct)) return direct;
  const data = recordField(value, "data");
  const nested = recordField(data, key);
  return Array.isArray(nested) ? nested : undefined;
}

function recordField(value: unknown, key: string): unknown {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>)[key] : undefined;
}

function stringField(value: unknown, key: string): string | undefined {
  const field = recordField(value, key);
  return typeof field === "string" ? field : undefined;
}

function validTimestamp(value: string): boolean {
  return z.iso.datetime({ offset: true }).safeParse(value).success && value.endsWith("Z");
}

function withinWindow(timestamp: string, correlation: TelemetryCorrelation): boolean {
  return validTimestamp(timestamp) && Date.parse(timestamp) >= Date.parse(correlation.from) && Date.parse(timestamp) <= Date.parse(correlation.to);
}

function normalizeBaseUrl(value: string): URL {
  const url = new URL(value);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
    throw new Error("baseUrl must be an absolute HTTP(S) URL without credentials, query, or fragment");
  }
  if (!url.pathname.endsWith("/")) url.pathname = `${url.pathname}/`;
  return url;
}

function validateRoute(baseUrl: URL, route: string): void {
  configuredUrl(baseUrl, route);
}

function configuredUrl(baseUrl: URL, route: string): URL {
  if (!route.startsWith("/") || route.includes("..") || route.includes("#")) throw new TelemetryQueryError("invalid-route");
  const basePath = baseUrl.pathname.replace(/\/+$/, "");
  const relative = route.replace(/^\/+/, "");
  const url = new URL(`${basePath}/${relative}`, baseUrl.origin);
  if (url.origin !== baseUrl.origin || !url.pathname.startsWith(`${basePath}/`)) throw new TelemetryQueryError("invalid-route");
  return url;
}

async function readBoundedText(response: Response, maxBytes: number): Promise<string> {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > maxBytes) throw new TelemetryQueryError("unavailable");
  if (response.body === null) throw new TelemetryQueryError("unavailable");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        throw new TelemetryQueryError("unavailable");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}
