import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it } from "vitest";

import { ApprovalTokenService, InMemoryApprovalAuditStore } from "../src/ci/approval.js";
import { createCIAllowlist } from "../src/ci/policy.js";
import type { CIService } from "../src/ci/service.js";
import { BitbucketProvider } from "../src/providers/bitbucket-provider.js";
import { GitHubActionsProvider } from "../src/providers/github-actions-provider.js";
import { JenkinsProvider } from "../src/providers/jenkins-provider.js";
import type { ForensicsProviderSet } from "../src/providers/ci-provider.js";
import { createCIServer } from "../src/server/create-server.js";

const NOW = new Date("2026-07-10T00:00:00.000Z");

describe("runtime CI capabilities", () => {
  it("fails closed when capability metadata is absent or mismatched", async () => {
    const absent = await listTools({ provider: jenkinsProvider() });
    expect(absent).toEqual([]);

    const mismatched = await listTools({
      provider: jenkinsProvider(),
      runtimeMetadata: {
        name: "github-prod",
        type: "github",
        capabilities: { read: true, rerun: true },
        approvalRequired: true,
      },
      approval: approval(),
    });
    expect(mismatched).toEqual([]);
  });

  it("fails closed before MCP registration when a read provider is missing a required port", async () => {
    const malformed = {
      ciProviderType: "jenkins",
      getWorkflowStatus: async () => { throw new Error("unreachable"); },
      getFailedJobAnalysis: async () => { throw new Error("unreachable"); },
      getLogEvidence: async () => { throw new Error("unreachable"); },
    } as unknown as CIService["provider"];

    expect(await listTools({
      provider: malformed,
      runtimeMetadata: {
        name: "jenkins-prod",
        type: "jenkins",
        capabilities: { read: true, rerun: false },
        approvalRequired: false,
      },
    })).toEqual([]);
  });

  it("registers four read tools for a named read-only Jenkins provider without approval", async () => {
    const tools = await listTools({
      provider: jenkinsProvider(),
      runtimeMetadata: {
        name: "jenkins-prod",
        type: "jenkins",
        capabilities: { read: true, rerun: false },
        approvalRequired: false,
      },
    });

    expect(tools.map((tool) => tool.name)).toEqual([
      "ci.workflow_status",
      "ci.failed_job_analysis",
      "ci.log_evidence",
      "ci.remediation_plan",
    ]);
    expect(tools.every((tool) => tool.description?.includes("jenkins-prod"))).toBe(true);
    expect(tools.some((tool) => tool.description?.includes("GitHub"))).toBe(false);
  });

  it("registers rerun only for a real GitHub provider with declared capability and approval", async () => {
    const tools = await listTools({
      provider: new GitHubActionsProvider({ token: "github-token-for-runtime-test", fetch: globalThis.fetch }),
      runtimeMetadata: {
        name: "github-prod",
        type: "github",
        capabilities: { read: true, rerun: true },
        approvalRequired: true,
      },
      approval: approval(),
    });

    expect(tools.map((tool) => tool.name)).toEqual([
      "ci.workflow_status",
      "ci.failed_job_analysis",
      "ci.log_evidence",
      "ci.remediation_plan",
      "ci.rerun_failed_workflow",
    ]);
    expect(tools.find((tool) => tool.name === "ci.rerun_failed_workflow")?.description).toContain("github-prod");
  });

  it("keeps Bitbucket read-only when no approval service is configured", async () => {
    const tools = await listTools({
      provider: new BitbucketProvider({
        baseUrl: "https://bitbucket.example",
        token: "bitbucket-token-for-runtime-test",
        username: "runtime-test",
        fetch: globalThis.fetch,
      }),
      runtimeMetadata: {
        name: "bitbucket-prod",
        type: "bitbucket",
        capabilities: { read: true, rerun: false },
        approvalRequired: false,
      },
    });

    expect(tools).toHaveLength(4);
    expect(tools.map((tool) => tool.name)).not.toContain("ci.rerun_failed_workflow");
  });

  it("fails closed for a partial forensics provider set", async () => {
    const tools = await listTools({
      provider: jenkinsProvider(),
      runtimeMetadata: {
        name: "jenkins-prod",
        type: "jenkins",
        capabilities: { read: true, rerun: false },
        approvalRequired: false,
      },
      forensics: {
        scm: {} as NonNullable<ForensicsProviderSet["scm"]>,
        telemetry: { getTelemetryCorrelation: async () => { throw new Error("unreachable"); } },
      },
    });

    expect(tools.map((tool) => tool.name)).toEqual([
      "ci.workflow_status",
      "ci.failed_job_analysis",
      "ci.log_evidence",
      "ci.remediation_plan",
    ]);
  });
});

async function listTools(input: Pick<CIService, "provider" | "runtimeMetadata" | "approval" | "forensics">): Promise<readonly { name: string; description?: string | undefined }[]> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createCIServer({
    ci: {
      provider: input.provider,
      policy: createCIAllowlist({ "owner/repo": ["ci.yml"] }),
      ...(input.approval === undefined ? {} : { approval: input.approval }),
      ...(input.runtimeMetadata === undefined ? {} : { runtimeMetadata: input.runtimeMetadata }),
      ...(input.forensics === undefined ? {} : { forensics: input.forensics }),
    },
    clock: () => NOW,
  });
  const client = new Client({ name: "runtime-capability-test", version: "1.0.0" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  let tools: Awaited<ReturnType<typeof client.listTools>>;
  try {
    tools = await client.listTools();
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes("Method not found")) throw error;
    tools = { tools: [] };
  }
  await client.close();
  await server.close();
  return tools.tools;
}

function approval(): ApprovalTokenService {
  return new ApprovalTokenService({
    key: Buffer.from("c".repeat(32)),
    clock: () => NOW,
    audit: new InMemoryApprovalAuditStore(),
  });
}

function jenkinsProvider(): JenkinsProvider {
  return new JenkinsProvider({ baseUrl: "https://jenkins.example", fetch: globalThis.fetch, clock: () => NOW });
}
