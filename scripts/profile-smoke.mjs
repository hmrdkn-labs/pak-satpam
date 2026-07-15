#!/usr/bin/env node
import assert from "node:assert/strict";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { ApprovalTokenService, InMemoryApprovalAuditStore } from "../dist/ci/approval.js";
import { createCIAllowlist } from "../dist/ci/policy.js";
import { GitHubActionsProvider } from "../dist/providers/github-actions-provider.js";
import { FakeObservabilityProvider } from "../dist/providers/fake-provider.js";
import { createCIServer, createObservabilityServer } from "../dist/server/create-server.js";
import { assertProfileToolSurface } from "./assert-tool-surface.mjs";

const now = new Date("2026-07-10T00:00:00.000Z");
const ci = {
  provider: new GitHubActionsProvider({ token: "profile-smoke-token", fetch: globalThis.fetch, clock: () => now }),
  policy: createCIAllowlist({ "owner/repo": ["ci.yml"] }),
  runtimeMetadata: { name: "github-profile-smoke", type: "github", capabilities: { read: true, rerun: true }, approvalRequired: true },
  approval: new ApprovalTokenService({ key: Buffer.from("c".repeat(32)), clock: () => now, audit: new InMemoryApprovalAuditStore() }),
};

await assertProfile("ci-only", createCIServer({ ci, clock: () => now }));
await assertProfile("combined", createObservabilityServer({ provider: new FakeObservabilityProvider(() => now), ci, clock: () => now }));
process.stdout.write("profile_tool_surface=ok ci-only=5 combined=12\n");

async function assertProfile(profile, server) {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: `profile-smoke-${profile}`, version: "1.0.0" });
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.listTools();
    assertProfileToolSurface(result.tools, profile);
  } finally {
    await client.close();
    await server.close();
  }
}
