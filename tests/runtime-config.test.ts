import { generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { loadRuntimeConfiguration } from "../src/runtime/load-runtime-configuration.js";

const FIXED_NOW = new Date("2026-07-10T00:00:00.000Z");

describe("private runtime configuration", () => {
  let directory: string;
  let configPath: string;
  let grafanaTokenPath: string;
  let mcpTokenPath: string;

  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "observability-agent-mcp-runtime-"));
    configPath = join(directory, "provider-config.yml");
    grafanaTokenPath = join(directory, "grafana-token");
    mcpTokenPath = join(directory, "mcp-token");
    writeFileSync(grafanaTokenPath, "grafana-test-token-123456\n", { mode: 0o600 });
    writeFileSync(mcpTokenPath, "mcp-test-token-123456789\n", { mode: 0o600 });
    writeFileSync(configPath, VALID_CONFIG, { mode: 0o600 });
  });

  afterEach(() => rmSync(directory, { recursive: true, force: true }));

  it("builds bounded production providers and visual policy without embedding secrets", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response(
        JSON.stringify({ status: "success", data: { resultType: "vector", result: [] } }),
        { headers: { "content-type": "application/json" } },
      ),
    );
    const runtime = loadRuntimeConfiguration({
      configPath,
      grafanaTokenPath,
      mcpTokenPath,
      fetch,
      clock: () => FIXED_NOW,
    });

    await runtime.provider.queryMetrics({ queryTemplate: "homelab-node-up" });
    const capabilities = await runtime.provider.capabilities({});

    expect(runtime.bearerToken).toBe("mcp-test-token-123456789");
    expect(runtime.visualAllowlist).toEqual({
      dashboards: {
        "homelab-overview": {
          panels: ["scrape-health", "host-memory"],
        },
      },
    });
    const requestUrl = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(requestUrl.origin).toBe("http://victoriametrics:8428");
    expect(fetch.mock.calls[0]?.[1]?.headers).toEqual({ Accept: "application/json" });
    expect(requestUrl.searchParams.get("query")).toBe('up{job="homelab-node"}');
    expect(capabilities.data.enabledTools).toEqual(
      expect.arrayContaining([
        "observability.render_panel",
        "observability.render_dashboard",
      ]),
    );
    expect(JSON.stringify(runtime)).not.toContain("grafana-test-token-123456");
  });

  it("rejects unknown configuration and insecure secret file permissions", () => {
    writeFileSync(configPath, `${VALID_CONFIG}\nunknown_root: true\n`);
    expect(() =>
      loadRuntimeConfiguration({
        configPath,
        grafanaTokenPath,
        mcpTokenPath,
        fetch,
      }),
    ).toThrow("Invalid runtime configuration");

    writeFileSync(configPath, VALID_CONFIG);
    chmodSync(mcpTokenPath, 0o644);
    expect(() =>
      loadRuntimeConfiguration({
        configPath,
        grafanaTokenPath,
        mcpTokenPath,
        fetch,
      }),
    ).toThrow("Secret file permissions are too broad");
  });

  it("loads the optional CI module only from private credential files", () => {
    const appIdPath = join(directory, "github-app-id");
    const installationIdPath = join(directory, "github-installation-id");
    const privateKeyPath = join(directory, "github-private-key.pem");
    const approvalKeyPath = join(directory, "approval-key");
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    writeFileSync(appIdPath, "123\n", { mode: 0o600 });
    writeFileSync(installationIdPath, "456\n", { mode: 0o600 });
    writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs1", format: "pem" }), { mode: 0o600 });
    writeFileSync(approvalKeyPath, "a".repeat(32), { mode: 0o600 });
    writeFileSync(configPath, `${VALID_CONFIG}\nci:\n  enabled: true\n  allowlist:\n    - repo: owner/repo\n      workflows: [goal14-controlled-fixture.yml]\n  github:\n    api_base_url: https://api.github.com\n    app:\n      app_id_file: ${appIdPath}\n      pem_key_file: ${privateKeyPath}\n      installations:\n        - owner: owner\n          installation_id_file: ${installationIdPath}\n  approval:\n    key_file: ${approvalKeyPath}\n    replay_file: ${join(directory, "replay.jsonl")}\n    audit_file: ${join(directory, "audit.jsonl")}\n  max_freshness_seconds: 300\n`);

    const runtime = loadRuntimeConfiguration({
      configPath,
      grafanaTokenPath,
      mcpTokenPath,
      fetch,
      clock: () => FIXED_NOW,
    });
    expect(runtime.ci).toBeDefined();
    expect(runtime.ci?.enableRerunTool).toBe(false);
  });

  it("loads the read-only Jenkins provider and Grafana Alertmanager option", async () => {
    const approvalKeyPath = join(directory, "approval-key");
    writeFileSync(approvalKeyPath, "a".repeat(32), { mode: 0o600 });
    writeFileSync(configPath, `${VALID_CONFIG.replace("type: vmalert", "type: grafana-alertmanager").replace("base_url: http://vmalert:8880", "base_url: https://grafana:3000")}
ci:
  enabled: true
  provider: jenkins
  allowlist:
    - repo: academytools/planpal-infra-6
      workflows: [planpal-infra-6]
  jenkins:
    enable_rerun_tool: true
    base_url: https://jenkins.local
  approval:
    key_file: ${approvalKeyPath}
    replay_file: ${join(directory, "replay.jsonl")}
    audit_file: ${join(directory, "audit.jsonl")}
`);
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify([{ labels: { alertname: "Test", service: "infra", severity: "info" }, annotations: {}, startsAt: "2026-07-10T00:00:00Z", status: { state: "active" } }])))
      .mockResolvedValueOnce(new Response(JSON.stringify({ number: 1, result: "SUCCESS", building: false, timestamp: FIXED_NOW.getTime() })));
    const runtime = loadRuntimeConfiguration({ configPath, grafanaTokenPath, mcpTokenPath, fetch, clock: () => FIXED_NOW });
    await runtime.provider.activeAlerts({});
    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://grafana:3000/api/v2/alerts");
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({
      headers: { Authorization: "Bearer grafana-test-token-123456" },
    });
    expect(runtime.ci?.enableRerunTool).toBe(true);
    expect(runtime.ci?.provider.constructor.name).toBe("JenkinsProvider");
  });

  it("keeps runtime CI reads on Actions read and reruns on a separate write token", async () => {
    const appIdPath = join(directory, "github-app-id");
    const installationIdPath = join(directory, "github-installation-id");
    const privateKeyPath = join(directory, "github-private-key.pem");
    const approvalKeyPath = join(directory, "approval-key");
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    writeFileSync(appIdPath, "123\n", { mode: 0o600 });
    writeFileSync(installationIdPath, "456\n", { mode: 0o600 });
    writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs1", format: "pem" }), { mode: 0o600 });
    writeFileSync(approvalKeyPath, "a".repeat(32), { mode: 0o600 });
    writeFileSync(configPath, `${VALID_CONFIG}\nci:\n  enabled: true\n  allowlist:\n    - repo: owner/repo\n      workflows: [ci.yml]\n  github:\n    api_base_url: https://api.github.com\n    app:\n      app_id_file: ${appIdPath}\n      pem_key_file: ${privateKeyPath}\n      installations:\n        - owner: owner\n          installation_id_file: ${installationIdPath}\n  approval:\n    key_file: ${approvalKeyPath}\n    replay_file: ${join(directory, "replay.jsonl")}\n    audit_file: ${join(directory, "audit.jsonl")}\n`);
    const ciFetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "read-token-123456789", expires_at: "2026-07-10T01:00:00Z" })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 101, status: "completed", conclusion: "failure", run_attempt: 1, event: "workflow_dispatch", head_branch: "main", head_sha: "a".repeat(40), created_at: "2026-07-10T00:00:00Z", updated_at: "2026-07-10T00:00:00Z" })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "write-token-123456789", expires_at: "2026-07-10T01:00:00Z" })))
      .mockResolvedValueOnce(new Response(null, { status: 201 }));

    const runtime = loadRuntimeConfiguration({ configPath, grafanaTokenPath, mcpTokenPath, fetch: ciFetch, clock: () => FIXED_NOW });
    await runtime.ci?.provider.getWorkflowStatus({ repo: "owner/repo", workflow: "ci.yml", runId: "101" });
    await runtime.ci?.provider.rerunFailedWorkflow({ repo: "owner/repo", workflow: "ci.yml", runId: "101", runAttempt: 1, headSha: "a".repeat(40) });

    expect(JSON.parse(String(ciFetch.mock.calls[0]?.[1]?.body))).toMatchObject({ permissions: { actions: "read" } });
    expect(JSON.parse(String(ciFetch.mock.calls[2]?.[1]?.body))).toMatchObject({ permissions: { actions: "write" } });
  });

  it("rejects contradictory legacy and mapped GitHub App installation modes", () => {
    const appIdPath = join(directory, "github-app-id");
    const installationIdPath = join(directory, "github-installation-id");
    const privateKeyPath = join(directory, "github-private-key.pem");
    const approvalKeyPath = join(directory, "approval-key");
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    writeFileSync(appIdPath, "123\n", { mode: 0o600 });
    writeFileSync(installationIdPath, "456\n", { mode: 0o600 });
    writeFileSync(privateKeyPath, privateKey.export({ type: "pkcs1", format: "pem" }), { mode: 0o600 });
    writeFileSync(approvalKeyPath, "a".repeat(32), { mode: 0o600 });
    writeFileSync(configPath, `${VALID_CONFIG}\nci:\n  enabled: true\n  allowlist:\n    - repo: owner/repo\n      workflows: [ci.yml]\n  github:\n    app:\n      app_id_file: ${appIdPath}\n      installation_id_file: ${installationIdPath}\n      pem_key_file: ${privateKeyPath}\n      installations:\n        - owner: owner\n          installation_id_file: ${installationIdPath}\n  approval:\n    key_file: ${approvalKeyPath}\n    replay_file: ${join(directory, "replay.jsonl")}\n    audit_file: ${join(directory, "audit.jsonl")}\n`);

    expect(() => loadRuntimeConfiguration({ configPath, grafanaTokenPath, mcpTokenPath, fetch })).toThrow("Invalid runtime configuration");
  });
});

const fetch = vi.fn<typeof globalThis.fetch>();

const VALID_CONFIG = `
version: 1
providers:
  metrics:
    type: prometheus-compatible
    base_url: http://victoriametrics:8428
  alerts:
    type: vmalert
    base_url: http://vmalert:8880
  grafana:
    type: grafana
    base_url: http://grafana:3000
policy:
  named_queries:
    homelab-node-up:
      expression: up{job="homelab-node"}
      label_keys: [job, host, role, site, environment]
    homelab-memory-used:
      expression: 1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes
      label_keys: [job, host, site, environment]
  service_health:
    homelab-node:
      query_template: homelab-node-up
      healthy_when: { operator: eq, value: 1 }
      summary: Homelab node exporter availability
  dashboards:
    homelab-overview:
      uid: homelab-overview
      slug: homelab-overview
      title: Homelab Overview
      panels:
        scrape-health: { id: 1 }
        host-memory: { id: 2 }
`;
