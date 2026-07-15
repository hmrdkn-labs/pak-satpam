import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import {
  TelemetryHttpEvidenceAdapter,
  TelemetryQueryError,
  type TelemetryEvidencePort,
} from "../src/providers/telemetry-evidence-provider.js";
import {
  TelemetryForensicsWorker,
  buildTelemetryCorrelationKey,
} from "../src/telemetry/forensics-worker.js";
import type { CILogEvidenceResult } from "../src/domain/ci-schemas.js";
import type { CIReadProvider } from "../src/providers/ci-provider.js";
import type {
  TelemetryLogsResult,
  TelemetryMetricsResult,
  TelemetryTracesResult,
} from "../src/domain/telemetry-schemas.js";

const NOW = new Date("2026-07-10T00:00:00.000Z");
const WINDOW = {
  from: "2026-07-09T23:00:00.000Z",
  to: "2026-07-10T00:00:00.000Z",
};
const CORRELATION = {
  runId: "101",
  jobId: "job-9",
  commitSha: "a".repeat(40),
  serviceId: "api",
  ...WINDOW,
};

function response(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json" },
    ...init,
  });
}

function ciProvider(logs: CILogEvidenceResult): CIReadProvider {
  return {
    getWorkflowStatus: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "ci-source",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: {
        run: {
          id: "101",
          repository: "owner/repo",
          workflow: "build.yml",
          status: "completed",
          conclusion: "failure",
          runAttempt: 1,
          event: "push",
          ref: "main",
          sha: CORRELATION.commitSha,
          createdAt: NOW.toISOString(),
          updatedAt: NOW.toISOString(),
        },
      },
    }),
    getLogEvidence: vi.fn().mockResolvedValue(logs),
    getFailedJobAnalysis: vi.fn(),
    getRemediationPlan: vi.fn(),
  };
}

function ciLogEvidence(): CILogEvidenceResult {
  return {
    schemaVersion: "1.0",
    observedAt: NOW.toISOString(),
    providerClass: "ci-source",
    freshness: "fresh",
    truncated: false,
    redactionsApplied: true,
    warnings: [],
    data: {
      runId: CORRELATION.runId,
      jobId: CORRELATION.jobId,
      jobName: "build",
      available: true,
      lines: [{ sequence: 1, text: "sanitized" }],
      sha256: createHash("sha256").update("sanitized").digest("hex"),
    },
  };
}

function logsResult(): TelemetryLogsResult {
  return {
    schemaVersion: "1.0",
    observedAt: NOW.toISOString(),
    sourceId: "ci-source",
    freshness: "fresh",
    truncated: false,
    redactionsApplied: true,
    warnings: [],
    provenance: {
      queryId: "ci-log",
      sourceId: "ci-source",
      correlationKey: buildTelemetryCorrelationKey(CORRELATION),
      requestedWindow: WINDOW,
    },
    data: {
      available: true,
      lineCount: 1,
      contentDigest: createHash("sha256").update("sanitized").digest("hex"),
    },
  };
}

function metricResult(): TelemetryMetricsResult {
  return {
    schemaVersion: "1.0",
    observedAt: NOW.toISOString(),
    sourceId: "metrics-source",
    freshness: "fresh",
    truncated: false,
    redactionsApplied: false,
    warnings: [],
    provenance: {
      queryId: "request-rate",
      sourceId: "metrics-source",
      correlationKey: buildTelemetryCorrelationKey(CORRELATION),
      requestedWindow: WINDOW,
    },
    data: {
      available: true,
      series: [{ seriesDigest: "a".repeat(64), samples: [{ timestamp: WINDOW.to, value: 4 }] }],
    },
  };
}

function traceResult(): TelemetryTracesResult {
  return {
    schemaVersion: "1.0",
    observedAt: NOW.toISOString(),
    sourceId: "traces-source",
    freshness: "fresh",
    truncated: false,
    redactionsApplied: false,
    warnings: [],
    provenance: {
      queryId: "request-traces",
      sourceId: "traces-source",
      correlationKey: buildTelemetryCorrelationKey(CORRELATION),
      requestedWindow: WINDOW,
    },
    data: {
      available: true,
      spans: [{ spanDigest: "b".repeat(64), durationMs: 12, status: "ok" }],
    },
  };
}

describe("telemetry evidence adapter", () => {
  it("uses only named queries, bounded windows, and configured routes", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({
        logs: [
          { timestamp: WINDOW.to, message: "Authorization: Bearer ghp_secret-value" },
          { timestamp: WINDOW.to, message: "second" },
        ],
      }),
    );
    const adapter = new TelemetryHttpEvidenceAdapter({
      sourceId: "logs-source",
      baseUrl: "https://telemetry.example/private",
      fetch,
      queries: {
        "failed-job": { kind: "logs", route: "/search/logs", expression: "failed-job" },
      },
    });

    const result = await adapter.queryLogs({ queryId: "failed-job", correlation: CORRELATION, limit: 1 });

    expect(result.data).toMatchObject({ available: true, lineCount: 1 });
    expect(result.redactionsApplied).toBe(true);
    expect(JSON.stringify(result)).not.toContain("ghp_secret-value");
    const requestUrl = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(requestUrl.pathname).toBe("/private/search/logs");
    expect(requestUrl.searchParams.get("query")).toBe("failed-job");
    expect(requestUrl.searchParams.get("from")).toBe(WINDOW.from);
    expect(requestUrl.searchParams.get("service")).toBe("api");
  });

  it("rejects unknown queries and invalid windows before I/O", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const adapter = new TelemetryHttpEvidenceAdapter({
      sourceId: "telemetry-source",
      baseUrl: "https://telemetry.example",
      fetch,
      queries: { known: { kind: "metrics", route: "/metrics", expression: "known" } },
    });

    await expect(adapter.queryMetrics({ queryId: "arbitrary-promql", correlation: CORRELATION })).rejects.toThrow(
      TelemetryQueryError,
    );
    await expect(
      adapter.queryMetrics({
        queryId: "known",
        correlation: { ...CORRELATION, from: "2026-07-01T00:00:00.000Z", to: WINDOW.to },
      }),
    ).rejects.toThrow("window");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bounds and redacts metrics and traces without returning labels or IDs", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        response({
          metrics: [
            {
              name: "http_requests_total",
              labels: { service: "api", instance: "secret.internal" },
              samples: Array.from({ length: 101 }, (_, index) => ({ timestamp: WINDOW.to, value: index })),
            },
          ],
        }),
      )
      .mockResolvedValueOnce(
        response({
          spans: [
            {
              traceId: "trace-secret",
              spanId: "span-secret",
              service: "api",
              operation: "GET /health",
              durationMs: 12,
              status: "ok",
            },
          ],
        }),
      );
    const adapter = new TelemetryHttpEvidenceAdapter({
      sourceId: "telemetry-source",
      baseUrl: "https://telemetry.example",
      fetch,
      queries: {
        metrics: { kind: "metrics", route: "/metrics", expression: "metrics" },
        traces: { kind: "traces", route: "/traces", expression: "traces" },
      },
      limits: { maxSamples: 10, maxSeries: 1, maxSpans: 1 },
    });

    const metrics = await adapter.queryMetrics({ queryId: "metrics", correlation: CORRELATION });
    const traces = await adapter.queryTraces({ queryId: "traces", correlation: CORRELATION });

    expect(metrics.truncated).toBe(true);
    expect(metrics.data.series[0]?.samples).toHaveLength(10);
    expect(JSON.stringify(metrics)).not.toContain("secret.internal");
    expect(JSON.stringify(traces)).not.toContain("trace-secret");
    expect(JSON.stringify(traces)).not.toContain("span-secret");
  });

  it("returns unknown evidence when the source is unavailable", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockRejectedValue(new Error("secret upstream failure"));
    const adapter = new TelemetryHttpEvidenceAdapter({
      sourceId: "telemetry-source",
      baseUrl: "https://telemetry.example",
      fetch,
      queries: { logs: { kind: "logs", route: "/logs", expression: "logs" } },
    });

    const result = await adapter.queryLogs({ queryId: "logs", correlation: CORRELATION });

    expect(result.freshness).toBe("unknown");
    expect(result.data.available).toBe(false);
    expect(JSON.stringify(result)).not.toContain("secret upstream failure");
  });
});

describe("telemetry forensics worker", () => {
  it("correlates CI logs, metrics, and traces by exact dimensions without causal claims", async () => {
    const telemetry: TelemetryEvidencePort = {
      queryLogs: vi.fn().mockResolvedValue(logsResult()),
      queryMetrics: vi.fn().mockResolvedValue(metricResult()),
      queryTraces: vi.fn().mockResolvedValue(traceResult()),
    };
    const worker = new TelemetryForensicsWorker({
      ci: ciProvider(ciLogEvidence()),
      telemetry,
      ciSourceId: "ci-source",
      metricsSourceId: "metrics-source",
      tracesSourceId: "traces-source",
      clock: () => NOW,
    });

    const result = await worker.collect({
      repo: "owner/repo",
      workflow: "build.yml",
      runId: CORRELATION.runId,
      jobId: CORRELATION.jobId,
      commitSha: CORRELATION.commitSha,
      serviceId: CORRELATION.serviceId,
      ...WINDOW,
      logsQueryId: "ci-log",
      metricsQueryId: "request-rate",
      tracesQueryId: "request-traces",
    });

    expect(result.data.correlationKey).toBe(buildTelemetryCorrelationKey(CORRELATION));
    expect(result.data.causality).toBe("not-established");
    expect(result.data.commitMatch).toBe("matched");
    expect(result.data.logs.data).toEqual(expect.not.objectContaining({ lines: expect.anything() }));
    expect(result.data.metrics.data.series).toHaveLength(1);
    expect(result.data.traces.data.spans).toHaveLength(1);
    expect(telemetry.queryMetrics).toHaveBeenCalledWith(expect.objectContaining({
      correlation: CORRELATION,
      queryId: "request-rate",
    }));
  });

  it("does not infer a match when CI status is unavailable", async () => {
    const provider = ciProvider(ciLogEvidence());
    vi.mocked(provider.getWorkflowStatus).mockRejectedValue(new Error("private CI failure"));
    const telemetry: TelemetryEvidencePort = {
      queryLogs: vi.fn().mockRejectedValue(new Error("logs unavailable")),
      queryMetrics: vi.fn().mockResolvedValue(metricResult()),
      queryTraces: vi.fn().mockResolvedValue(traceResult()),
    };
    const worker = new TelemetryForensicsWorker({
      ci: provider,
      telemetry,
      ciSourceId: "ci-source",
      metricsSourceId: "metrics-source",
      tracesSourceId: "traces-source",
      clock: () => NOW,
    });

    const result = await worker.collect({
      repo: "owner/repo",
      workflow: "build.yml",
      runId: CORRELATION.runId,
      jobId: CORRELATION.jobId,
      commitSha: CORRELATION.commitSha,
      serviceId: CORRELATION.serviceId,
      ...WINDOW,
      logsQueryId: "ci-log",
      metricsQueryId: "request-rate",
      tracesQueryId: "request-traces",
    });

    expect(result.data.commitMatch).toBe("unknown");
    expect(result.data.logs.freshness).toBe("fresh");
    expect(result.data.causality).toBe("not-established");
    expect(JSON.stringify(result)).not.toContain("private CI failure");
  });
});
