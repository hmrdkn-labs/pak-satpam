import { describe, expect, it, vi } from "vitest";
import { VictoriaMetricsProvider } from "../src/providers/victoriametrics-provider.js";

const NOW = new Date("2026-07-10T00:00:00.000Z");

describe("Grafana embedded Alertmanager adapter", () => {
  it("uses the v2 read-only endpoint and normalizes Grafana alert objects", async () => {
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
      alertsBaseUrl: "https://grafana.example/api/alertmanager/grafana",
      alertsProvider: "grafana-alertmanager",
      fetch,
      clock: () => NOW,
      queryTemplates: {},
      serviceHealth: {},
    });

    const result = await provider.activeAlerts({ services: ["backend"] });

    expect(result.providerClass).toBe("grafana-alertmanager");
    expect(result.data.alerts).toEqual([expect.objectContaining({
      alertId: "abc123",
      name: "BackendDown",
      state: "firing",
      severity: "critical",
      serviceId: "backend",
      startsAt: "2026-07-09T23:59:00.000Z",
    })]);
    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://grafana.example/api/alertmanager/grafana/api/v2/alerts");
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: "GET", redirect: "error" });
  });
});
