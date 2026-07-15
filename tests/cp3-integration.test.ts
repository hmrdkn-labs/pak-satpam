import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { describe, expect, it, vi } from "vitest";

import {
  assembleFailureAnalysis,
  buildAgentNotificationPayload,
  makeUnavailableFailureAnalysis,
} from "../src/ci/forensics.js";
import { createCIAllowlist } from "../src/ci/policy.js";
import type { CIProvider, CIProviderRuntimeType } from "../src/providers/ci-provider.js";
import type { CIWorkflowRun } from "../src/domain/ci-schemas.js";
import { createCIServer } from "../src/server/create-server.js";
import { InMemoryObserverStateStore } from "../src/observer/state.js";
import { ObserverRuntime, outcomeForRun } from "../src/observer/runtime.js";
import type { ObserverConfig, ObserverProvider } from "../src/observer/index.js";

const NOW = new Date("2026-07-15T00:00:00.000Z");
const SHA = "a".repeat(40);

function run(id: string, conclusion: CIWorkflowRun["conclusion"] = "failure", updatedAt = NOW.toISOString()): CIWorkflowRun {
  return {
    id,
    repository: "owner/repo",
    workflow: "ci.yml",
    status: "completed",
    conclusion,
    runAttempt: 1,
    event: "push",
    ref: "main",
    sha: SHA,
    createdAt: updatedAt,
    updatedAt,
  };
}

function ciProvider(type: CIProviderRuntimeType = "github", conclusion: CIWorkflowRun["conclusion"] = "failure"): CIProvider {
  return {
    ciProviderType: type,
    getWorkflowStatus: vi.fn(async (input) => ({
      schemaVersion: "1.0" as const,
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh" as const,
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: { run: run(input.runId ?? "1", conclusion) },
    })),
    listWorkflowRuns: vi.fn(),
    getFailedJobAnalysis: vi.fn(async (input) => ({
      schemaVersion: "1.0" as const,
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh" as const,
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: {
        run: run(input.runId),
        failedJobs: [{ id: "job-1", name: "unit tests", status: "completed" as const, conclusion: "failure" as const, category: "test" as const, failedSteps: ["vitest"] }],
        categorySummary: { build: 0, test: 1, lint: 0, dependency: 0, deployment: 0, "infrastructure-connectivity": 0, permission: 0, unknown: 0 },
      },
    })),
    getLogEvidence: vi.fn(async (input) => ({
      schemaVersion: "1.0" as const,
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh" as const,
      truncated: false,
      redactionsApplied: true,
      warnings: [],
      data: { runId: input.runId, jobId: input.jobId, jobName: "unit tests", available: true, lines: [{ sequence: 1, text: "failure" }], sha256: "a".repeat(64) },
    })),
    getRemediationPlan: vi.fn(async (input) => ({
      schemaVersion: "1.0" as const,
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh" as const,
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: { runId: input.runId, dryRun: true as const, actions: [{ category: "test" as const, title: "inspect test", steps: ["Inspect the failing test"], runbook: "docs/ci-cd-runbook.md#test" }] },
    })),
    rerunFailedWorkflow: vi.fn(),
  };
}

function scmEvidence(changes: number) {
  return {
    schemaVersion: "1.0" as const,
    observedAt: NOW.toISOString(),
    providerClass: "github",
    freshness: "fresh" as const,
    truncated: changes > 1,
    redactionsApplied: false,
    warnings: [],
    data: {
      available: true as const,
      changes: Array.from({ length: changes }, (_, index) => ({
        path: `src/check-${index}.ts`,
        changeType: "modified" as const,
        additions: 1,
        deletions: 0,
        hunks: [{ header: "@@", lines: ["+safe", "+bounded"] }],
      })),
    },
  };
}

function telemetryEvidence(signals: number) {
  return {
    schemaVersion: "1.0" as const,
    observedAt: NOW.toISOString(),
    providerClass: "prometheus",
    freshness: "fresh" as const,
    truncated: signals > 1,
    redactionsApplied: true,
    warnings: [],
    data: {
      available: true as const,
      signals: Array.from({ length: signals }, (_, index) => ({
        id: `error-rate-${index}`,
        kind: "metric" as const,
        state: index === 0 ? "degraded" as const : "normal" as const,
        summary: "Error rate elevated",
        observedAt: NOW.toISOString(),
      })),
    },
  };
}

describe("Goal 19 CP3 integration", () => {
  it("passes bounded budgets through CI, SCM, and telemetry and keeps correlation non-causal", async () => {
    const provider = ciProvider();
    const scm = { getChangeEvidence: vi.fn().mockResolvedValue(scmEvidence(2)) };
    const telemetry = { getTelemetryCorrelation: vi.fn().mockResolvedValue(telemetryEvidence(2)) };
    const analysis = await assembleFailureAnalysis({
      provider,
      evidence: { scm, telemetry },
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "1", maxChanges: 1, maxHunkLines: 1, maxSignals: 1, maxLogLines: 1 },
      clock: () => NOW,
    });

    expect(scm.getChangeEvidence).toHaveBeenCalledWith(expect.objectContaining({ maxChanges: 1, maxHunkLines: 1 }));
    expect(telemetry.getTelemetryCorrelation).toHaveBeenCalledWith(expect.objectContaining({ maxSignals: 1 }));
    expect(analysis.data.scmChanges).toHaveLength(1);
    expect(analysis.data.telemetrySignals).toHaveLength(1);
    expect(analysis.data.correlations.every((item) => item.confidence < 1)).toBe(true);
    expect(analysis.data.correlations.map((item) => item.source)).toEqual(["scm", "telemetry"]);
    expect(JSON.stringify(analysis)).not.toContain("caus");
  });

  it("isolates malformed or unavailable SCM and telemetry without leaking provider details", async () => {
    const analysis = await assembleFailureAnalysis({
      provider: ciProvider(),
      evidence: {
        scm: { getChangeEvidence: vi.fn().mockRejectedValue(new Error("scm secret")) },
        telemetry: { getTelemetryCorrelation: vi.fn().mockResolvedValue({ malformed: "telemetry secret" }) },
      },
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "1" },
      clock: () => NOW,
    });

    expect(analysis.data.correlations).toEqual([]);
    expect(analysis.data.provenance).toEqual(expect.arrayContaining([
      expect.objectContaining({ source: "scm", unavailable: true }),
      expect.objectContaining({ source: "telemetry", unavailable: true }),
    ]));
    expect(JSON.stringify(analysis)).not.toContain("secret");
  });

  it("creates one bounded deduplication identity for the same reconciled failure", () => {
    const analysis = makeUnavailableFailureAnalysis({ run: { ...run("7"), status: "completed" }, observedAt: NOW, providerClass: "github-actions", code: "unavailable" });
    const first = buildAgentNotificationPayload({ analysis, eventId: "owner/repo:ci.yml:7:1", source: "poll", maxBytes: 2_000 });
    const second = buildAgentNotificationPayload({ analysis, eventId: "owner/repo:ci.yml:7:1", source: "poll", maxBytes: 2_000 });

    expect(first).toEqual(second);
    expect(first.dedupeKey).toBe(first.eventId);
    expect(Buffer.byteLength(JSON.stringify(first), "utf8")).toBeLessThanOrEqual(2_000);
  });

  it("keeps stale events suppressed and duplicate pages to one notification", async () => {
    const staleRun = run("8", "failure", new Date(NOW.getTime() - 61_000).toISOString());
    expect(outcomeForRun(staleRun, NOW, 60_000)).toBe("stale");
    const provider = ciProvider("github", "success") as ObserverProvider;
    provider.listWorkflowRuns = vi.fn().mockResolvedValue({ runs: [run("9", "success"), run("9", "success")], hasMore: false });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const config: ObserverConfig = {
      allowlist: [{ repo: "owner/repo", workflows: ["ci.yml"] }],
      stateFile: "",
      hmacKey: new Uint8Array(32),
      pollIntervalMs: 30_000,
      overlapMs: 1_000,
      staleAfterMs: 60_000,
      pageSize: 100,
      maxPages: 1,
      maxFailedJobs: 1,
      maxLogLines: 1,
      maxPayloadBytes: 8_000,
      leaseMs: 30_000,
      deliveryAttempts: 1,
      deliveryBackoffMs: 10,
      deliveryTimeoutMs: 1_000,
    };
    const runtime = new ObserverRuntime({ config, provider, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 1 });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, observed: [] });
    expect(deliver).toHaveBeenCalledTimes(1);
  });

  it("registers only declared read capabilities and isolates a Jenkins runtime from GitHub rerun", async () => {
    const provider = ciProvider("jenkins");
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createCIServer({
      ci: {
        provider,
        policy: createCIAllowlist({ "owner/repo": ["ci.yml"] }),
        runtimeMetadata: { name: "jenkins-prod", type: "jenkins", capabilities: { read: true, rerun: false }, approvalRequired: false },
        forensics: { scm: { getChangeEvidence: vi.fn() }, telemetry: { getTelemetryCorrelation: vi.fn() } },
      },
      clock: () => NOW,
    });
    const client = new Client({ name: "cp3-integration", version: "1.0.0" });
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const tools = await client.listTools();

    expect(tools.tools.map((tool) => tool.name)).toEqual([
      "ci.workflow_status", "ci.failed_job_analysis", "ci.log_evidence", "ci.remediation_plan", "ci.failure_analysis", "ci.scm_change_evidence", "ci.telemetry_correlation",
    ]);
    expect(tools.tools.some((tool) => tool.name === "ci.rerun_failed_workflow")).toBe(false);
    await client.close();
    await server.close();
  });
});
