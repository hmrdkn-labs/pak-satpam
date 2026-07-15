import {
  ActiveAlertsInputSchema,
  ActiveAlertsResultSchema,
  CapabilitiesInputSchema,
  CapabilitiesResultSchema,
  HealthSnapshotInputSchema,
  HealthSnapshotResultSchema,
  IncidentContextInputSchema,
  IncidentContextResultSchema,
  QueryMetricsInputSchema,
  QueryMetricsResultSchema,
  SCHEMA_VERSION,
  type ActiveAlertsInput,
  type ActiveAlertsResult,
  type CapabilitiesInput,
  type CapabilitiesResult,
  type HealthSnapshotInput,
  type HealthSnapshotResult,
  type IncidentContextInput,
  type IncidentContextResult,
  type QueryMetricsInput,
  type QueryMetricsResult,
} from "../domain/tool-schemas.js";
import type { Clock, ObservabilityProvider } from "./observability-provider.js";

const MAX_ALERTS = 100;
const MAX_SERIES = 50;
const MAX_SAMPLES_PER_SERIES = 1_440;
const DEFAULT_TIMEOUT_MS = 5_000;
const VMALERT_ALERTS_PATH = "/api/v1/alerts";
const GRAFANA_ALERTMANAGER_ALERTS_PATH = "/api/alertmanager/grafana/api/v2/alerts";

export interface VictoriaMetricsQueryTemplate {
  /** Static PromQL owned by the deployment configuration. */
  readonly expression: string;
  /** Metric labels allowed to leave the provider boundary. */
  readonly labelKeys?: readonly string[];
}

export interface NumericMatch {
  readonly operator: "eq" | "gt" | "gte" | "lt" | "lte";
  readonly value: number;
}

export interface ServiceHealthMapping {
  readonly queryTemplate: string;
  readonly healthyWhen: NumericMatch;
  readonly degradedWhen?: NumericMatch;
  readonly summary: string;
}

export interface VictoriaMetricsProviderOptions {
  readonly baseUrl: string;
  /** vmalert or Grafana's embedded Alertmanager read-only API. */
  readonly alertsBaseUrl: string;
  readonly alertsProvider?: "vmalert" | "grafana-alertmanager";
  /** Optional bearer token; private internal VictoriaMetrics deployments need none. */
  readonly token?: string;
  readonly fetch: typeof globalThis.fetch;
  readonly queryTemplates: Readonly<Record<string, VictoriaMetricsQueryTemplate>>;
  readonly serviceHealth: Readonly<Record<string, ServiceHealthMapping>>;
  readonly visualsEnabled?: boolean;
  readonly dashboardRefs?: readonly { readonly dashboardId: string; readonly title: string }[];
  readonly clock?: Clock;
  readonly timeoutMs?: number;
}

type JsonRecord = Record<string, unknown>;

interface ParsedMetrics {
  readonly series: Array<{ name: string; labels: Record<string, string>; samples: Array<{ timestamp: string; value: number }> }>;
  readonly truncated: boolean;
  readonly redactionsApplied: boolean;
}

/**
 * Read-only adapter for VictoriaMetrics and Prometheus-compatible HTTP APIs.
 * URLs and PromQL expressions are configured once; tool inputs select only named entries.
 */
export class VictoriaMetricsProvider implements ObservabilityProvider {
  readonly #options: VictoriaMetricsProviderOptions;
  private readonly baseUrl: URL;
  private readonly alertsUrl: URL;
  private readonly providerClass: "grafana" | "prometheus-compatible";
  private readonly clock: Clock;
  private readonly timeoutMs: number;

  constructor(options: VictoriaMetricsProviderOptions) {
    this.#options = options;
    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.providerClass = options.alertsProvider === "grafana-alertmanager" ? "grafana" : "prometheus-compatible";
    this.alertsUrl = normalizeEndpointUrl(
      options.alertsBaseUrl,
      this.providerClass === "grafana" ? GRAFANA_ALERTMANAGER_ALERTS_PATH : VMALERT_ALERTS_PATH,
    );
    this.clock = options.clock ?? (() => new Date());
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs < 1 || this.timeoutMs > 30_000) {
      throw new Error("timeoutMs must be between 1 and 30000");
    }
  }

  async capabilities(input: CapabilitiesInput): Promise<CapabilitiesResult> {
    CapabilitiesInputSchema.parse(input);
    return CapabilitiesResultSchema.parse({
      ...this.evidence(),
      data: {
        providerClasses: [this.providerClass],
        enabledTools: [
          "observability.capabilities",
          "observability.health_snapshot",
          "observability.active_alerts",
          "observability.query_metrics",
          "observability.incident_context",
          ...(this.#options.visualsEnabled
            ? ["observability.render_panel", "observability.render_dashboard"]
            : []),
        ],
        limits: {
          maxServices: 25,
          maxAlerts: MAX_ALERTS,
          maxSeries: MAX_SERIES,
          maxRenderWidth: this.#options.visualsEnabled ? 2_400 : 1,
          maxRenderHeight: this.#options.visualsEnabled ? 4_000 : 1,
        },
        featureFlags: [
          "named-query-templates",
          this.#options.alertsProvider === "grafana-alertmanager" ? "grafana-alertmanager-alerts" : "vmalert-alerts",
          ...(this.#options.visualsEnabled ? ["grafana-visuals"] : []),
        ],
      },
    });
  }

  async healthSnapshot(input: HealthSnapshotInput): Promise<HealthSnapshotResult> {
    const request = HealthSnapshotInputSchema.parse(input);
    const checkedAt = this.now();
    let unavailable = false;
    const targets = await Promise.all(
      request.services.map(async (serviceId) => {
        const mapping = this.#options.serviceHealth[serviceId];
        const template = mapping === undefined ? undefined : this.#options.queryTemplates[mapping.queryTemplate];
        if (mapping === undefined || template === undefined) {
          return unknownHealth(serviceId, checkedAt);
        }
        const payload = await this.requestJson(this.baseUrl, "api/v1/query", { query: template.expression });
        const parsed = payload === undefined ? undefined : parseMetrics(payload, new Set(template.labelKeys ?? []));
        const value = parsed?.series[0]?.samples[0]?.value;
        if (value === undefined) {
          unavailable ||= payload === undefined || parsed === undefined;
          return unknownHealth(serviceId, checkedAt);
        }
        return {
          serviceId,
          status: healthStatus(value, mapping),
          summary: safeText(mapping.summary, 512) ?? "Configured health check",
          checkedAt,
        };
      }),
    );
    return HealthSnapshotResultSchema.parse({
      ...this.evidence(checkedAt, unavailable ? "unknown" : "fresh", unavailable ? [unavailableWarning()] : []),
      data: { targets },
    });
  }

  async activeAlerts(input: ActiveAlertsInput): Promise<ActiveAlertsResult> {
    const request = ActiveAlertsInputSchema.parse(input);
    const observedAt = this.now();
    const grafanaAlertmanager = this.#options.alertsProvider === "grafana-alertmanager";
    const payload = await this.requestJson(this.alertsUrl);
    if (payload === undefined) {
      return ActiveAlertsResultSchema.parse({
        ...this.evidence(observedAt, "unknown", [unavailableWarning()]),
        data: { alerts: [] },
      });
    }
    const rawAlerts = alertsFrom(payload, grafanaAlertmanager);
    if (rawAlerts === undefined) {
      return ActiveAlertsResultSchema.parse({
        ...this.evidence(observedAt, "unknown", [unavailableWarning()]),
        data: { alerts: [] },
      });
    }
    const truncated = rawAlerts.length > MAX_ALERTS;
    const alerts = rawAlerts.slice(0, MAX_ALERTS).flatMap((alert, index) => normalizeAlert(alert, index, observedAt, grafanaAlertmanager));
    const filtered = alerts.filter((alert) =>
      (request.services === undefined || request.services.includes(alert.serviceId)) &&
      (request.states === undefined || request.states.includes(alert.state)) &&
      (request.severities === undefined || request.severities.includes(alert.severity)),
    );
    return ActiveAlertsResultSchema.parse({
      ...this.evidence(observedAt),
      truncated,
      data: { alerts: filtered },
    });
  }

  async queryMetrics(input: QueryMetricsInput): Promise<QueryMetricsResult> {
    const request = QueryMetricsInputSchema.parse(input);
    const template = this.#options.queryTemplates[request.queryTemplate];
    if (template === undefined) {
      throw new Error("Unknown query template");
    }
    const observedAt = this.now();
    const isRange = request.from !== undefined;
    const payload = await this.requestJson(
      this.baseUrl,
      isRange ? "api/v1/query_range" : "api/v1/query",
      isRange
        ? {
            query: template.expression,
            start: request.from as string,
            end: request.to as string,
            step: `${String(request.stepMs)}ms`,
          }
        : { query: template.expression, ...(request.at === undefined ? {} : { time: request.at }) },
    );
    if (payload === undefined) {
      return this.unavailableQuery(request, observedAt, isRange);
    }
    const parsed = parseMetrics(payload, new Set(template.labelKeys ?? []));
    if (parsed === undefined) {
      return this.unavailableQuery(request, observedAt, isRange);
    }
    return QueryMetricsResultSchema.parse({
      ...this.evidence(observedAt, "fresh"),
      truncated: parsed.truncated,
      redactionsApplied: parsed.redactionsApplied,
      data: {
        queryTemplate: request.queryTemplate,
        queryKind: isRange ? "range" : "instant",
        ...(isRange ? { from: request.from, to: request.to, stepMs: request.stepMs } : {}),
        series: parsed.series,
      },
    });
  }

  async incidentContext(input: IncidentContextInput): Promise<IncidentContextResult> {
    const request = IncidentContextInputSchema.parse(input);
    const serviceId = request.serviceId ?? "unknown";
    const [health, alertResult] = await Promise.all([
      this.healthSnapshot({ services: [serviceId] }),
      this.activeAlerts({}),
    ]);
    const alert = request.alertId === undefined ? undefined : alertResult.data.alerts.find((item) => item.alertId === request.alertId);
    const subjectServiceId = request.serviceId ?? alert?.serviceId ?? "unknown";
    const unavailable = health.freshness === "unknown" || alertResult.freshness === "unknown";
    const warnings = request.includeVisuals === "none"
      ? (unavailable ? [unavailableWarning()] : [])
      : [
          ...(unavailable ? [unavailableWarning()] : []),
          { code: "visuals-unavailable", message: "Visual evidence is not configured" },
        ];
    return IncidentContextResultSchema.parse({
      ...this.evidence(this.now(), unavailable ? "unknown" : "fresh", warnings),
      data: {
        subject: request.alertId === undefined ? { serviceId: subjectServiceId } : { alertId: request.alertId, serviceId: subjectServiceId },
        health: health.data.targets,
        alerts: alert === undefined ? [] : [alert],
        dashboardRefs: [...(this.#options.dashboardRefs ?? [])].slice(0, 5),
        visuals: { requested: request.includeVisuals, available: false },
      },
    });
  }

  private async requestJson(
    baseUrl: URL,
    path?: string,
    parameters: Record<string, string> = {},
  ): Promise<unknown | undefined> {
    const url = path === undefined ? new URL(baseUrl.toString()) : new URL(path, baseUrl);
    if (url.origin !== baseUrl.origin) return undefined;
    for (const [key, value] of Object.entries(parameters)) url.searchParams.set(key, value);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.#options.fetch(url, {
        method: "GET",
        redirect: "error",
        headers: this.requestHeaders(),
        signal: controller.signal,
      });
      if (!response.ok) return undefined;
      return await response.json();
    } catch {
      return undefined;
    } finally {
      clearTimeout(timeout);
    }
  }

  private unavailableQuery(request: QueryMetricsInput, observedAt: string, isRange: boolean): QueryMetricsResult {
    return QueryMetricsResultSchema.parse({
      ...this.evidence(observedAt, "unknown", [unavailableWarning()]),
      data: {
        queryTemplate: request.queryTemplate,
        queryKind: isRange ? "range" : "instant",
        ...(isRange ? { from: request.from, to: request.to, stepMs: request.stepMs } : {}),
        series: [],
      },
    });
  }

  private requestHeaders(): Record<string, string> {
    const token = this.#options.token?.trim();
    return {
      Accept: "application/json",
      ...(token === undefined || token.length === 0 ? {} : { Authorization: `Bearer ${token}` }),
    };
  }

  private evidence(
    observedAt = this.now(),
    freshness: "fresh" | "unknown" = "fresh",
    warnings: Array<{ code: string; message: string }> = [],
  ) {
    return {
      schemaVersion: SCHEMA_VERSION,
      observedAt,
      providerClass: this.providerClass,
      freshness,
      truncated: false,
      redactionsApplied: false,
      warnings,
    };
  }

  private now(): string {
    return this.clock().toISOString();
  }
}

function normalizeBaseUrl(value: string): URL {
  const url = new URL(value);
  if ((url.protocol !== "http:" && url.protocol !== "https:") || url.username || url.password || url.search || url.hash) {
    throw new Error("baseUrl must be an absolute HTTP(S) URL without credentials, query, or fragment");
  }
  if (!url.pathname.endsWith("/")) url.pathname = `${url.pathname}/`;
  return url;
}

function normalizeEndpointUrl(value: string, endpointPath: string): URL {
  const url = normalizeBaseUrl(value);
  const basePath = url.pathname.replace(/\/+$/, "");
  url.pathname = basePath === "" || basePath === endpointPath
    ? endpointPath
    : `${basePath}${endpointPath}`;
  return url;
}

function parseMetrics(payload: unknown, allowedLabelKeys: ReadonlySet<string>): ParsedMetrics | undefined {
  const root = record(payload);
  const data = root === undefined ? undefined : record(root.data);
  const resultType = data === undefined ? undefined : data.resultType;
  const rawSeries = data === undefined ? undefined : data.result;
  if (root?.status !== "success" || (resultType !== "vector" && resultType !== "matrix") || !Array.isArray(rawSeries)) {
    return undefined;
  }

  let truncated = rawSeries.length > MAX_SERIES;
  let redactionsApplied = false;
  const series: ParsedMetrics["series"] = [];
  for (const raw of rawSeries.slice(0, MAX_SERIES)) {
    const item = record(raw);
    const metric = item === undefined ? undefined : record(item.metric);
    if (item === undefined || metric === undefined) continue;
    const labels = allowedLabels(metric, allowedLabelKeys);
    redactionsApplied ||= labels.redacted;
    const rawSamples = resultType === "vector" ? [item.value] : item.values;
    if (!Array.isArray(rawSamples)) continue;
    truncated ||= rawSamples.length > MAX_SAMPLES_PER_SERIES;
    const samples = rawSamples.slice(0, MAX_SAMPLES_PER_SERIES).flatMap(parseSample);
    if (samples.length === 0) continue;
    series.push({
      name: metricName(metric.__name__) ?? "metric",
      labels: labels.value,
      samples,
    });
  }
  return { series, truncated, redactionsApplied };
}

function allowedLabels(metric: JsonRecord, allowed: ReadonlySet<string>): { value: Record<string, string>; redacted: boolean } {
  const value: Record<string, string> = {};
  let redacted = false;
  for (const [key, rawValue] of Object.entries(metric)) {
    if (key === "__name__") continue;
    if (!allowed.has(key) || !logicalId(key) || typeof rawValue !== "string" || safeText(rawValue, 256) === undefined) {
      redacted = true;
      continue;
    }
    value[key] = rawValue;
  }
  return { value, redacted };
}

function parseSample(raw: unknown): Array<{ timestamp: string; value: number }> {
  if (!Array.isArray(raw) || raw.length !== 2) return [];
  const seconds = Number(raw[0]);
  const value = Number(raw[1]);
  if (!Number.isFinite(seconds) || !Number.isFinite(value)) return [];
  const date = new Date(seconds * 1_000);
  if (Number.isNaN(date.getTime())) return [];
  return [{ timestamp: date.toISOString(), value }];
}

function alertsFrom(payload: unknown, grafanaAlertmanager: boolean): unknown[] | undefined {
  if (grafanaAlertmanager) return Array.isArray(payload) ? payload : undefined;
  const root = record(payload);
  const data = root === undefined ? undefined : record(root.data);
  if (root?.status !== "success" || data === undefined || !Array.isArray(data.alerts)) return undefined;
  return data.alerts;
}

function normalizeAlert(raw: unknown, index: number, observedAt: string, grafanaAlertmanager: boolean): Array<{
  alertId: string;
  name: string;
  state: "firing" | "pending" | "resolved";
  severity: "critical" | "warning" | "info";
  startsAt: string;
  serviceId: string;
  annotations: Record<string, string>;
}> {
  const item = record(raw);
  const labels = item === undefined ? undefined : record(item.labels);
  const annotations = item === undefined ? undefined : record(item.annotations);
  const status = item === undefined ? undefined : record(item.status);
  if (item === undefined) return [];
  const name = safeText(item.name, 256) ?? safeText(labels?.alertname, 256) ?? `Alert ${index + 1}`;
  const alertId = slugId(safeText(item.fingerprint, 256) ?? safeText(labels?.alertname, 256) ?? name, `alert-${index + 1}`);
  const serviceId = logicalId(labels?.service) ? String(labels?.service) : "unknown";
  const summary = safeText(annotations?.summary, 512);
  const description = safeText(annotations?.description, 1_024);
  const runbookRef = logicalId(annotations?.runbookRef) ? String(annotations?.runbookRef) : undefined;
  return [{
    alertId,
    name,
    state: grafanaAlertmanager ? grafanaAlertState(status?.state) : alertState(item.state),
    severity: alertSeverity(labels?.severity),
    startsAt: timestamp(grafanaAlertmanager ? item.startsAt : item.activeAt) ?? timestamp(item.startsAt) ?? observedAt,
    serviceId,
    annotations: {
      ...(summary === undefined ? {} : { summary }),
      ...(description === undefined ? {} : { description }),
      ...(runbookRef === undefined ? {} : { runbookRef }),
    },
  }];
}

function unknownHealth(serviceId: string, checkedAt: string) {
  return { serviceId, status: "unknown" as const, summary: "Health check unavailable", checkedAt };
}

function healthStatus(value: number, mapping: ServiceHealthMapping): "healthy" | "degraded" | "unhealthy" {
  if (matches(value, mapping.healthyWhen)) return "healthy";
  if (mapping.degradedWhen !== undefined && matches(value, mapping.degradedWhen)) return "degraded";
  return "unhealthy";
}

function grafanaAlertState(value: unknown): "firing" | "pending" | "resolved" {
  if (value === "suppressed" || value === "unprocessed") return "pending";
  return value === "active" ? "firing" : "resolved";
}

function alertState(value: unknown): "firing" | "pending" | "resolved" {
  if (value === "pending") return "pending";
  if (value === "resolved" || value === "inactive") return "resolved";
  return "firing";
}

function alertSeverity(value: unknown): "critical" | "warning" | "info" {
  if (value === "critical" || value === "warning" || value === "info") return value;
  return "info";
}

function matches(value: number, rule: NumericMatch): boolean {
  if (rule.operator === "eq") return value === rule.value;
  if (rule.operator === "gt") return value > rule.value;
  if (rule.operator === "gte") return value >= rule.value;
  if (rule.operator === "lt") return value < rule.value;
  return value <= rule.value;
}

function unavailableWarning() {
  return { code: "provider-unavailable", message: "Observability provider is unavailable" };
}

function record(value: unknown): JsonRecord | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value) ? value as JsonRecord : undefined;
}

function safeText(value: unknown, maxLength: number): string | undefined {
  return typeof value === "string" && value.length <= maxLength && !/[<>]/.test(value) ? value : undefined;
}

function logicalId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(value) && value.length <= 64;
}

function metricName(value: unknown): string | undefined {
  return logicalId(value) ? value : undefined;
}

function slugId(value: string, fallback: string): string {
  const slug = value.toLowerCase().replace(/[^a-z0-9._:-]+/g, "-").replace(/^-+|-+$/g, "");
  return logicalId(slug) ? slug : fallback;
}

function timestamp(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}
