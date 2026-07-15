import { describe, expect, it, vi } from "vitest";
import {
  GrafanaVisualProvider,
  VisualProviderError,
} from "../src/providers/grafana-visual-provider.js";
import { VictoriaMetricsProvider } from "../src/providers/victoriametrics-provider.js";

const FIXED_NOW = new Date("2026-07-10T00:00:00.000Z");
const RANGE = {
  from: "2026-07-09T23:00:00.000Z",
  to: "2026-07-10T00:00:00.000Z",
  stepMs: 60_000,
};

function response(body: unknown, init: ResponseInit = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "content-type": "application/json", ...init.headers },
    ...init,
  });
}

function victoria(fetch: typeof globalThis.fetch, token?: string): VictoriaMetricsProvider {
  return new VictoriaMetricsProvider({
    baseUrl: "https://metrics.internal/",
    alertsBaseUrl: "https://vmalert.internal/",
    ...(token === undefined ? {} : { token }),
    fetch,
    clock: () => FIXED_NOW,
    queryTemplates: {
      "request-rate": {
        expression: 'sum(rate(http_requests_total{service="api"}[5m]))',
        labelKeys: ["service", "environment"],
      },
      "api-up": { expression: 'up{job="api"}', labelKeys: ["service"] },
    },
    serviceHealth: {
      api: {
        queryTemplate: "api-up",
        healthyWhen: { operator: "eq", value: 1 },
        summary: "API availability check",
      },
    },
  });
}

describe("VictoriaMetricsProvider", () => {
  it("uses only named query allowlist expressions and redacts unapproved labels", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({
        status: "success",
        data: {
          resultType: "matrix",
          result: [
            {
              metric: {
                __name__: "http_requests_total",
                service: "api",
                environment: "production",
                instance: "node-a.internal",
              },
              values: [
                ["1783638000", "42"],
                ["1783638060", "43"],
              ],
            },
          ],
        },
      }),
    );
    const provider = victoria(fetch);

    await expect(provider.queryMetrics({ queryTemplate: "request-rate", ...RANGE })).resolves.toMatchObject({
      freshness: "fresh",
      redactionsApplied: true,
      data: {
        queryTemplate: "request-rate",
        queryKind: "range",
        series: [
          {
            name: "http_requests_total",
            labels: { service: "api", environment: "production" },
            samples: [{ value: 42 }, { value: 43 }],
          },
        ],
      },
    });

    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(String(url)).toContain("/api/v1/query_range?");
    expect(new URL(String(url)).searchParams.get("query")).toBe('sum(rate(http_requests_total{service="api"}[5m]))');
    expect(new URL(String(url)).searchParams.get("step")).toBe("60000ms");
    expect(String(url)).not.toContain("node-a.internal");
    expect(init?.method).toBe("GET");
    expect(init?.redirect).toBe("error");
    expect(init?.headers).toEqual({ Accept: "application/json" });
  });

  it("refuses unknown named queries without making a request", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const provider = victoria(fetch);

    await expect(provider.queryMetrics({ queryTemplate: "attacker-expression" })).rejects.toThrow(
      "Unknown query template",
    );
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bounds Prometheus-compatible matrix series and sample counts", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        response({
          status: "success",
          data: {
            resultType: "matrix",
            result: Array.from({ length: 51 }, (_, index) => ({
              metric: { __name__: "request_rate", service: `api-${index}` },
              values: [["1783638000", "1"]],
            })),
          },
        }),
      )
      .mockResolvedValueOnce(
        response({
          status: "success",
          data: {
            resultType: "matrix",
            result: [
              {
                metric: { __name__: "request_rate", service: "api" },
                values: Array.from({ length: 1_441 }, (_, index) => [String(1783638000 + index), "1"]),
              },
            ],
          },
        }),
      );
    const provider = victoria(fetch);

    const seriesBounded = await provider.queryMetrics({ queryTemplate: "request-rate", ...RANGE });
    expect(seriesBounded.truncated).toBe(true);
    expect(seriesBounded.data.series).toHaveLength(50);
    const sampleBounded = await provider.queryMetrics({ queryTemplate: "request-rate", ...RANGE });
    expect(sampleBounded.truncated).toBe(true);
    expect(sampleBounded.data.series[0]?.samples).toHaveLength(1_440);
  });

  it("normalizes vmalert alerts and filters them without leaking upstream details", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({
        status: "success",
        data: {
          alerts: [
            {
              id: "ignored-external-id",
              name: "API latency high",
              state: "firing",
              activeAt: "2026-07-09T23:30:00.000Z",
              labels: { alertname: "API latency high", service: "api", severity: "critical" },
              annotations: {
                summary: "Latency elevated",
                description: "Sensitive <markup> is discarded",
                runbook: "https://secret.internal/runbook",
              },
            },
          ],
        },
      }),
    );
    const provider = victoria(fetch);

    await expect(provider.activeAlerts({ services: ["api"], severities: ["critical"] })).resolves.toMatchObject({
      data: {
        alerts: [
          {
            alertId: "api-latency-high",
            serviceId: "api",
            severity: "critical",
            annotations: { summary: "Latency elevated" },
          },
        ],
      },
    });
    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://vmalert.internal/api/v1/alerts");
  });

  it("accepts a full vmalert alerts endpoint without duplicating its path", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({ status: "success", data: { alerts: [] } }),
    );
    const provider = new VictoriaMetricsProvider({
      baseUrl: "https://metrics.internal",
      alertsBaseUrl: "https://vmalert.internal/api/v1/alerts",
      fetch,
      queryTemplates: {},
      serviceHealth: {},
    });

    await provider.activeAlerts({});

    const requestUrl = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(requestUrl.origin).toBe("https://vmalert.internal");
    expect(requestUrl.pathname).toBe("/api/v1/alerts");
  });

  it("preserves a reverse-proxy prefix for metrics and vmalert endpoint joins", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(response({ status: "success", data: { resultType: "vector", result: [] } }))
      .mockResolvedValueOnce(response({ status: "success", data: { alerts: [] } }));
    const provider = new VictoriaMetricsProvider({
      baseUrl: "https://metrics.internal/prometheus/",
      alertsBaseUrl: "https://metrics.internal/alerts/api/v1/alerts",
      fetch,
      queryTemplates: { "api-up": { expression: "up", labelKeys: [] } },
      serviceHealth: {},
    });

    await provider.queryMetrics({ queryTemplate: "api-up" });
    await provider.activeAlerts({});

    expect(new URL(String(fetch.mock.calls[0]?.[0])).pathname).toBe("/prometheus/api/v1/query");
    expect(new URL(String(fetch.mock.calls[1]?.[0])).pathname).toBe("/alerts/api/v1/alerts");
  });

  it("returns schema-valid unknown evidence on timeout without exposing upstream errors", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockImplementation((_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new Error("victoria-secret-token upstream exploded")));
      }),
    );
    const provider = new VictoriaMetricsProvider({
      baseUrl: "https://metrics.internal/",
      alertsBaseUrl: "https://vmalert.internal/",
      token: "victoria-secret-token",
      fetch,
      clock: () => FIXED_NOW,
      timeoutMs: 1,
      queryTemplates: { "api-up": { expression: 'up{job="api"}', labelKeys: ["service"] } },
      serviceHealth: {
        api: {
          queryTemplate: "api-up",
          healthyWhen: { operator: "eq", value: 1 },
          summary: "API availability check",
        },
      },
    });

    const result = await provider.healthSnapshot({ services: ["api"] });
    expect(result).toMatchObject({
      freshness: "unknown",
      data: { targets: [{ serviceId: "api", status: "unknown" }] },
    });
    expect(JSON.stringify(result)).not.toContain("victoria-secret-token");
    expect(JSON.stringify(result)).not.toContain("upstream exploded");
  });

  it("converts unavailable metric responses into generic unknown evidence", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      response({ error: "victoria-secret-token detailed upstream failure" }, { status: 500 }),
    );
    const provider = victoria(fetch);

    const result = await provider.queryMetrics({ queryTemplate: "request-rate" });
    expect(result).toMatchObject({ freshness: "unknown", data: { series: [] } });
    expect(JSON.stringify(result)).not.toContain("victoria-secret-token");
    expect(JSON.stringify(result)).not.toContain("detailed upstream failure");
  });
});

describe("GrafanaVisualProvider", () => {
  it("renders only allowlisted panel routes with time, dimensions, and theme parameters", async () => {
    const png = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 0, 1]);
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response(png, { headers: { "content-type": "image/png" } }),
    );
    const provider = new GrafanaVisualProvider({
      baseUrl: "https://grafana.internal/grafana/",
      token: "grafana-secret-token",
      fetch,
      panels: { "service-overview:request-rate": "/render/d-solo/service-overview/requests?panelId=7" },
      dashboards: { "service-overview": "/render/d/service-overview" },
    });

    await expect(
      provider.renderPanel({
        dashboardId: "service-overview",
        panelId: "request-rate",
        from: RANGE.from,
        to: RANGE.to,
        width: 800,
        height: 450,
        theme: "light",
      }),
    ).resolves.toMatchObject({ mimeType: "image/png", rawByteSize: png.byteLength, data: png });

    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(String(url)).toContain("/grafana/render/d-solo/service-overview/requests?");
    expect(String(url)).toContain("from=2026-07-09T23%3A00%3A00.000Z");
    expect(String(url)).toContain("to=2026-07-10T00%3A00%3A00.000Z");
    expect(String(url)).toContain("width=800");
    expect(String(url)).toContain("height=450");
    expect(String(url)).toContain("theme=light");
    expect(new URL(String(url)).searchParams.get("panelId")).toBe("7");
    expect(init?.headers).toMatchObject({ Authorization: "Bearer grafana-secret-token" });
    expect(init?.redirect).toBe("error");
  });

  it("fails closed when an allowlisted visual route points outside the configured origin", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const provider = new GrafanaVisualProvider({
      baseUrl: "https://grafana.internal/grafana",
      token: "grafana-secret-token",
      fetch,
      panels: { "service-overview:request-rate": "https://attacker.invalid/render/d-solo/service-overview/requests" },
      dashboards: {},
    });

    await expect(provider.renderPanel({
      dashboardId: "service-overview",
      panelId: "request-rate",
      from: RANGE.from,
      to: RANGE.to,
      width: 800,
      height: 450,
      theme: "dark",
    })).rejects.toThrow("Visual route is not allowlisted");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("refuses non-allowlisted routes and rejects non-PNG or oversized bodies without secret leakage", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        new Response("grafana-secret-token detail", { headers: { "content-type": "text/html" } }),
      )
      .mockResolvedValueOnce(
        new Response(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 0]), { headers: { "content-type": "image/png" } }),
      );
    const provider = new GrafanaVisualProvider({
      baseUrl: "https://grafana.internal/",
      token: "grafana-secret-token",
      fetch,
      maxBytes: 8,
      panels: {},
      dashboards: { "service-overview": "/render/d/service-overview" },
    });

    await expect(
      provider.renderPanel({
        dashboardId: "service-overview",
        panelId: "unknown-panel",
        from: RANGE.from,
        to: RANGE.to,
        width: 800,
        height: 450,
        theme: "dark",
      }),
    ).rejects.toThrow("Visual route is not allowlisted");
    expect(fetch).not.toHaveBeenCalled();

    const nonPng = provider.renderDashboard({
      dashboardId: "service-overview",
      from: RANGE.from,
      to: RANGE.to,
      width: 800,
      height: 450,
      theme: "dark",
    });
    await expect(nonPng).rejects.toBeInstanceOf(VisualProviderError);
    await expect(nonPng).rejects.not.toThrow("grafana-secret-token");
    await expect(
      provider.renderDashboard({
        dashboardId: "service-overview",
        from: RANGE.from,
        to: RANGE.to,
        width: 800,
        height: 450,
        theme: "dark",
      }),
    ).rejects.toThrow("Visual evidence is unavailable");
  });

  it("cancels a chunked Grafana response as soon as it exceeds the byte limit", async () => {
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]));
        controller.enqueue(new Uint8Array([0]));
      },
      cancel() {
        cancelled = true;
      },
    });
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response(body, { headers: { "content-type": "image/png" } }),
    );
    const provider = new GrafanaVisualProvider({
      baseUrl: "https://grafana.internal/",
      token: "grafana-secret-token",
      fetch,
      maxBytes: 8,
      panels: {},
      dashboards: { "service-overview": "/render/d/service-overview" },
    });

    await expect(
      provider.renderDashboard({
        dashboardId: "service-overview",
        from: RANGE.from,
        to: RANGE.to,
        width: 800,
        height: 450,
        theme: "dark",
      }),
    ).rejects.toThrow("Visual evidence is unavailable");
    expect(cancelled).toBe(true);
  });
});
