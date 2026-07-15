import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { CallToolResultSchema } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it, vi } from "vitest";
import { ApprovalTokenService, InMemoryApprovalAuditStore } from "../src/ci/approval.js";
import { createCIAllowlist } from "../src/ci/policy.js";
import type { CIService } from "../src/ci/service.js";
import { GitHubActionsProvider } from "../src/providers/github-actions-provider.js";
import { createCIServer, createObservabilityServer } from "../src/server/create-server.js";
import { FakeObservabilityProvider } from "../src/providers/fake-provider.js";

const NOW = new Date("2026-07-10T00:00:00.000Z");
const INPUT = {
  repo: "owner/repo",
  workflow: "goal14-controlled-fixture.yml",
  runId: "101",
};
const ACTION_BINDING = { ...INPUT, runAttempt: 1, headSha: "a".repeat(40) };

function ci(fetch: typeof globalThis.fetch, forensics?: CIService["forensics"]): CIService {
  return {
    provider: new GitHubActionsProvider({ token: "github-token-for-header", fetch, clock: () => NOW }),
    policy: createCIAllowlist({
      "owner/repo": ["goal14-controlled-fixture.yml"],
    }),
    runtimeMetadata: {
      name: "github-test",
      type: "github",
      capabilities: { read: true, rerun: true },
      approvalRequired: true,
    } as const,
    approval: new ApprovalTokenService({
      key: Buffer.from("c".repeat(32)),
      clock: () => NOW,
      audit: new InMemoryApprovalAuditStore(),
    }),
    ...(forensics === undefined ? {} : { forensics }),
  };
}

async function connectedServer(fetch: typeof globalThis.fetch) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createObservabilityServer({
    provider: new FakeObservabilityProvider(() => NOW),
    clock: () => NOW,
    ci: ci(fetch),
  });
  const client = new Client({ name: "goal14-test", version: "1.0.0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  return { client, server };
}

describe("CI MCP contract", () => {
  it("preserves the twelve-tool combined surface without forensics", async () => {
    const fetch = viFetch([
      new Response(JSON.stringify({ workflow_runs: [] }), { headers: { "content-type": "application/json" } }),
    ]);
    const { client, server } = await connectedServer(fetch);
    const result = await client.listTools();
    expect(result.tools.map((tool) => tool.name)).toEqual([
      "observability.capabilities",
      "observability.health_snapshot",
      "observability.active_alerts",
      "observability.query_metrics",
      "observability.render_panel",
      "observability.render_dashboard",
      "observability.incident_context",
      "ci.workflow_status",
      "ci.failed_job_analysis",
      "ci.log_evidence",
      "ci.remediation_plan",
      "ci.rerun_failed_workflow",
    ]);
    expect(result.tools.find((tool) => tool.name === "ci.rerun_failed_workflow")?.annotations).toMatchObject({
      readOnlyHint: false,
      destructiveHint: true,
      idempotentHint: false,
    });
    await client.close();
    await server.close();
  });

  it("exposes exactly the CI tools from the CI-only server", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createCIServer({ ci: ci(viFetch([])), clock: () => NOW });
    const client = new Client({ name: "goal18-ci-only-test", version: "1.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const result = await client.listTools();

    expect(result.tools.map((tool) => tool.name)).toEqual([
      "ci.workflow_status",
      "ci.failed_job_analysis",
      "ci.log_evidence",
      "ci.remediation_plan",
      "ci.rerun_failed_workflow",
    ]);
    expect(result.tools.every((tool) => tool.name.startsWith("ci."))).toBe(true);
    await client.close();
    await server.close();
  });

  it("enforces allowlists and returns sanitized status, analysis, logs, and plan", async () => {
    const fetch = viFetch([
      new Response(
        JSON.stringify({
          workflow_runs: [
            {
              id: 101,
              status: "completed",
              conclusion: "failure",
              run_attempt: 1,
              event: "workflow_dispatch",
              head_branch: "main",
              head_sha: "a".repeat(40),
              created_at: "2026-07-10T00:00:00Z",
              updated_at: "2026-07-10T00:00:00Z",
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      ),
      new Response(
        JSON.stringify({
          id: 101,
          status: "completed",
          conclusion: "failure",
          run_attempt: 1,
          event: "workflow_dispatch",
          head_branch: "main",
          head_sha: "a".repeat(40),
          created_at: "2026-07-10T00:00:00Z",
          updated_at: "2026-07-10T00:00:00Z",
        }),
        { headers: { "content-type": "application/json" } },
      ),
      new Response(JSON.stringify({ jobs: [{ id: 9, name: "test", status: "completed", conclusion: "failure", steps: [] }] }), {
        headers: { "content-type": "application/json" },
      }),
      new Response("test failed\n", { headers: { "content-type": "text/plain" } }),
      new Response(
        JSON.stringify({
          id: 101,
          status: "completed",
          conclusion: "failure",
          run_attempt: 1,
          event: "workflow_dispatch",
          head_branch: "main",
          head_sha: "a".repeat(40),
          created_at: "2026-07-10T00:00:00Z",
          updated_at: "2026-07-10T00:00:00Z",
        }),
        { headers: { "content-type": "application/json" } },
      ),
      new Response(JSON.stringify({ jobs: [{ id: 9, name: "test", status: "completed", conclusion: "failure", steps: [] }] }), {
        headers: { "content-type": "application/json" },
      }),
    ]);
    const { client, server } = await connectedServer(fetch);
    const denied = await client.callTool({
      name: "ci.workflow_status",
      arguments: { repo: "owner/other", workflow: "ci.yml" },
    });
    expect(JSON.stringify(denied)).toContain("ci_policy_denied");

    for (const [name, arguments_] of [
      ["ci.workflow_status", { repo: INPUT.repo, workflow: INPUT.workflow }],
      ["ci.failed_job_analysis", INPUT],
      ["ci.log_evidence", { ...INPUT, jobId: "9", maxLines: 20 }],
      ["ci.remediation_plan", INPUT],
    ] as const) {
      const result = CallToolResultSchema.parse(await client.callTool({ name, arguments: arguments_ }));
      expect(result.isError, name).not.toBe(true);
      expect(JSON.stringify(result)).not.toContain("secret");
      expect(JSON.stringify(result)).toContain('"providerClass":"github-test"');
    }
    await client.close();
    await server.close();
  });

  it("registers failure analysis plus optional SCM and telemetry only with forensics", async () => {
    const configured = ci(viFetch([]), {
      scm: { getChangeEvidence: vi.fn() },
      telemetry: { getTelemetryCorrelation: vi.fn() },
    });
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createCIServer({ ci: configured, clock: () => NOW });
    const client = new Client({ name: "goal19-forensics-test", version: "1.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const result = await client.listTools();

    expect(result.tools.map((tool) => tool.name)).toEqual([
      "ci.workflow_status",
      "ci.failed_job_analysis",
      "ci.log_evidence",
      "ci.remediation_plan",
      "ci.failure_analysis",
      "ci.scm_change_evidence",
      "ci.telemetry_correlation",
      "ci.rerun_failed_workflow",
    ]);
    expect(result.tools.filter((tool) => tool.name.includes("scm") || tool.name.includes("telemetry") || tool.name.includes("failure_analysis")).every((tool) => tool.annotations?.readOnlyHint === true)).toBe(true);
    await client.close();
    await server.close();
  });

  it("requires a valid approval and reruns only failed or cancelled allowlisted runs", async () => {
    const fetch = viFetch([
      new Response(JSON.stringify({ id: 101, status: "completed", conclusion: "failure", run_attempt: 1, event: "workflow_dispatch", head_branch: "main", head_sha: "a".repeat(40), created_at: "2026-07-10T00:00:00Z", updated_at: "2026-07-10T00:00:00Z" }), { headers: { "content-type": "application/json" } }),
      new Response(null, { status: 201 }),
    ]);
    const configured = ci(fetch);
    const { client, server } = await (async () => {
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const server = createObservabilityServer({ provider: new FakeObservabilityProvider(() => NOW), clock: () => NOW, ci: configured });
      const client = new Client({ name: "goal14-rerun-test", version: "1.0.0" });
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      return { client, server };
    })();
    const token = configured.approval!.issue({ ...ACTION_BINDING, requestId: "rerun-1", ttlSeconds: 60 });
    const result = await client.callTool({
      name: "ci.rerun_failed_workflow",
      arguments: { ...ACTION_BINDING, requestId: "rerun-1", approvalToken: token },
    });
    expect(result.isError).not.toBe(true);
    expect(JSON.stringify(result)).toContain('"accepted":true');
    const replay = await client.callTool({
      name: "ci.rerun_failed_workflow",
      arguments: { ...ACTION_BINDING, requestId: "rerun-1", approvalToken: token },
    });
    expect(JSON.stringify(replay)).toContain("approval_replay");
    await client.close();
    await server.close();
  });
});

function viFetch(responses: Response[]) {
  return ((async () => responses.shift() ?? new Response("unavailable", { status: 503 })) as unknown) as typeof globalThis.fetch;
}
