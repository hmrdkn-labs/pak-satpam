import { describe, expect, it, vi } from "vitest";
import { VictoriaMetricsProvider } from "../src/providers/victoriametrics-provider.js";

const NOW = new Date("2026-07-10T00:00:00.000Z");

describe("Grafana embedded Alertmanager adapter", () => {
  it.each([
    "https://grafana.example",
    "https://grafana.example/api/alertmanager/grafana/api/v2/alerts",
    "https://grafana.example/api/alertmanager/grafana/api/v2/alerts/",
  ])("uses the v2 read-only endpoint for origin and full-endpoint configuration: %s", async (alertsBaseUrl) => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify([
      {
        fingerprint: "abc123",
        labels: { alertname: "BackendDown", service: "backend", severity: "critical" },
        annotations: { summary: "Backend unavailable", description: "probe failed" },
        startsAt: "2026-07-09T23:59:00Z",
        status: { state: "active" },
      },
    ]), { headers: { "content-type": "application/json" } }));
    const provider = new VictoriaMetricsProvider({
      baseUrl: "https://prometheus.example",
      alertsBaseUrl,
      alertsProvider: "grafana-alertmanager",
      fetch,
      clock: () => NOW,
      queryTemplates: {},
      serviceHealth: {},
    });

    const result = await provider.activeAlerts({ services: ["backend"] });

    expect(result.providerClass).toBe("grafana");
    expect(result.data.alerts).toEqual([expect.objectContaining({
      alertId: "abc123",
      name: "BackendDown",
      state: "firing",
      severity: "critical",
      serviceId: "backend",
      startsAt: "2026-07-09T23:59:00.000Z",
    })]);
    const requestUrl = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(requestUrl.origin).toBe("https://grafana.example");
    expect(requestUrl.pathname).toBe("/api/alertmanager/grafana/api/v2/alerts");
    expect(requestUrl.pathname).not.toContain("api/alertmanager/grafana/api/v2/alerts/api/");
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: "GET", redirect: "error" });
  });

  it("reports the configured Grafana provider class in capabilities", async () => {
    const provider = new VictoriaMetricsProvider({
      baseUrl: "https://prometheus.example",
      alertsBaseUrl: "https://grafana.example/api/alertmanager/grafana/api/v2/alerts",
      alertsProvider: "grafana-alertmanager",
      fetch: vi.fn<typeof globalThis.fetch>(),
      queryTemplates: {},
      serviceHealth: {},
    });

    await expect(provider.capabilities({})).resolves.toMatchObject({
      providerClass: "grafana",
      data: { providerClasses: ["grafana"] },
    });
  });

  it.each([
    "ftp://grafana.example",
    "https://user:password@grafana.example",
    "https://grafana.example/api/alertmanager/grafana/api/v2/alerts?next=https://evil.example",
    "https://grafana.example/api/alertmanager/grafana/api/v2/alerts#https://evil.example",
  ])("rejects unsafe alert URL configuration: %s", (alertsBaseUrl) => {
    expect(() => new VictoriaMetricsProvider({
      baseUrl: "https://prometheus.example",
      alertsBaseUrl,
      alertsProvider: "grafana-alertmanager",
      fetch: vi.fn<typeof globalThis.fetch>(),
      queryTemplates: {},
      serviceHealth: {},
    })).toThrow();
  });
});
