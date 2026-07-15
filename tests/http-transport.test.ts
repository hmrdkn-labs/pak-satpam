import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { createObservabilityHttpApp } from "../src/http/create-http-app.js";
import { ApprovalTokenService, InMemoryApprovalAuditStore } from "../src/ci/approval.js";
import { createCIAllowlist } from "../src/ci/policy.js";
import { GitHubActionsProvider } from "../src/providers/github-actions-provider.js";
import { FakeObservabilityProvider } from "../src/providers/fake-provider.js";

const TEST_CREDENTIAL = "goal11-test-bearer-token";
const FIXED_NOW = new Date("2026-07-10T00:00:00.000Z");

describe("private Streamable HTTP transport", () => {
  let server: Server;
  let baseUrl: URL;

  beforeEach(async () => {
    const app = createObservabilityHttpApp({
      provider: new FakeObservabilityProvider(() => FIXED_NOW),
      bearerToken: TEST_CREDENTIAL,
      host: "127.0.0.1",
      allowedHosts: ["127.0.0.1"],
      clock: () => FIXED_NOW,
    });
    server = createServer(app);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address() as AddressInfo;
    baseUrl = new URL(`http://127.0.0.1:${address.port}`);
  });

  afterEach(async () => {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  });

  it("serves MCP tools with bearer authentication", async () => {
    const transport = new StreamableHTTPClientTransport(new URL("/mcp", baseUrl), {
      requestInit: { headers: { Authorization: `Bearer ${TEST_CREDENTIAL}` } },
    });
    const client = new Client({ name: "goal11-http-test", version: "1.0.0" });

    await client.connect(transport as unknown as Transport);
    const tools = await client.listTools();
    const health = await client.callTool({
      name: "observability.health_snapshot",
      arguments: { services: ["api"] },
    });
    await client.close();

    expect(tools.tools).toHaveLength(7);
    expect(health).not.toMatchObject({ isError: true });
  });

  it("serves exactly the five CI tools at /mcp/ci and no observability tools", async () => {
    const app = createObservabilityHttpApp({
      provider: new FakeObservabilityProvider(() => FIXED_NOW),
      ci: {
        provider: new GitHubActionsProvider({ token: "github-token-for-http-test", fetch: globalThis.fetch, clock: () => FIXED_NOW }),
        policy: createCIAllowlist({ "owner/repo": ["ci.yml"] }),
        runtimeMetadata: { name: "github-http-test", type: "github", capabilities: { read: true, rerun: true }, approvalRequired: true },
        approval: new ApprovalTokenService({ key: Buffer.from("c".repeat(32)), clock: () => FIXED_NOW, audit: new InMemoryApprovalAuditStore() }),
      },
      bearerToken: TEST_CREDENTIAL,
      host: "127.0.0.1",
      allowedHosts: ["127.0.0.1"],
      clock: () => FIXED_NOW,
    });
    const ciServer = createServer(app);
    await new Promise<void>((resolve) => ciServer.listen(0, "127.0.0.1", resolve));
    const address = ciServer.address() as AddressInfo;
    const ciBaseUrl = new URL(`http://127.0.0.1:${address.port}`);
    const transport = new StreamableHTTPClientTransport(new URL("/mcp/ci", ciBaseUrl), {
      requestInit: { headers: { Authorization: `Bearer ${TEST_CREDENTIAL}` } },
    });
    const client = new Client({ name: "goal18-http-ci-test", version: "1.0.0" });

    await client.connect(transport as unknown as Transport);
    const tools = await client.listTools();

    expect(tools.tools.map((tool) => tool.name)).toEqual([
      "ci.workflow_status",
      "ci.failed_job_analysis",
      "ci.log_evidence",
      "ci.remediation_plan",
      "ci.rerun_failed_workflow",
    ]);
    expect(tools.tools.every((tool) => tool.name.startsWith("ci."))).toBe(true);
    await client.close();
    await new Promise<void>((resolve, reject) => ciServer.close((error) => (error ? reject(error) : resolve())));
  });

  it("serves only the CI endpoint when observability is not configured", async () => {
    const app = createObservabilityHttpApp({
      ci: {
        provider: new GitHubActionsProvider({ token: "github-token-for-http-test", fetch: globalThis.fetch, clock: () => FIXED_NOW }),
        policy: createCIAllowlist({ "owner/repo": ["ci.yml"] }),
        runtimeMetadata: { name: "github-http-test", type: "github", capabilities: { read: true, rerun: true }, approvalRequired: true },
        approval: new ApprovalTokenService({ key: Buffer.from("c".repeat(32)), clock: () => FIXED_NOW, audit: new InMemoryApprovalAuditStore() }),
      },
      bearerToken: TEST_CREDENTIAL,
      host: "127.0.0.1",
      allowedHosts: ["127.0.0.1"],
      clock: () => FIXED_NOW,
    });
    const ciOnlyServer = createServer(app);
    await new Promise<void>((resolve) => ciOnlyServer.listen(0, "127.0.0.1", resolve));
    const address = ciOnlyServer.address() as AddressInfo;
    const ciOnlyBaseUrl = new URL(`http://127.0.0.1:${address.port}`);

    const ciResponse = await fetch(new URL("/mcp/ci", ciOnlyBaseUrl), {
      method: "POST",
      headers: { Authorization: `Bearer ${TEST_CREDENTIAL}`, "Content-Type": "application/json", Accept: "application/json, text/event-stream", Host: "127.0.0.1" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });
    const observabilityResponse = await fetch(new URL("/mcp", ciOnlyBaseUrl), {
      method: "POST",
      headers: { Authorization: `Bearer ${TEST_CREDENTIAL}`, "Content-Type": "application/json", Host: "127.0.0.1" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    expect(ciResponse.status).toBe(200);
    expect(observabilityResponse.status).toBe(404);
    await new Promise<void>((resolve, reject) => ciOnlyServer.close((error) => (error ? reject(error) : resolve())));
  });

  it("keeps health metadata public to the private network but protects MCP", async () => {
    const health = await fetch(new URL("/healthz", baseUrl));
    const unauthorized = await fetch(new URL("/mcp", baseUrl), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toEqual({ status: "ok" });
    expect(unauthorized.status).toBe(401);
    expect(unauthorized.headers.get("www-authenticate")).toBe("Bearer");
    expect(await unauthorized.text()).not.toContain(TEST_CREDENTIAL);
  });

  it("fails closed for /mcp/ci when CI is disabled", async () => {
    const response = await fetch(new URL("/mcp/ci", baseUrl), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_CREDENTIAL}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    expect(response.status).toBe(404);
  });

  it("rejects untrusted Host headers before MCP handling", async () => {
    const response = await fetch(new URL("/mcp", baseUrl), {
      method: "POST",
      headers: {
        Authorization: `Bearer ${TEST_CREDENTIAL}`,
        "Content-Type": "application/json",
        Host: "attacker.invalid",
      },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }),
    });

    expect(response.status).toBe(406);
  });
});
