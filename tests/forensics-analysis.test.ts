import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";

import {
  assembleFailureAnalysis,
  buildAgentNotificationPayload,
  type ForensicsProviderSet,
} from "../src/ci/forensics.js";
import type { CIProvider } from "../src/providers/ci-provider.js";
import type { CIWorkflowRun } from "../src/domain/ci-schemas.js";

const NOW = new Date("2026-07-15T00:00:00.000Z");
const SHA = "a".repeat(40);

function run(conclusion: CIWorkflowRun["conclusion"] = "failure"): CIWorkflowRun {
  return {
    id: "101",
    repository: "owner/repo",
    workflow: "ci.yml",
    status: "completed",
    conclusion,
    runAttempt: 1,
    event: "push",
    ref: "main",
    sha: SHA,
    createdAt: NOW.toISOString(),
    updatedAt: NOW.toISOString(),
  };
}

function ciProvider(): CIProvider {
  return {
    matchesWorkflow: (allowlistEntry, workflow) => workflow === allowlistEntry,
    getWorkflowStatus: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: { run: run() },
    }),
    getFailedJobAnalysis: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: true,
      warnings: [],
      data: {
        run: run(),
        failedJobs: [{
          id: "job-1",
          name: "unit tests",
          status: "completed",
          conclusion: "failure",
          category: "test",
          failedSteps: ["vitest"],
        }],
        categorySummary: { build: 0, test: 1, lint: 0, dependency: 0, deployment: 0, "infrastructure-connectivity": 0, permission: 0, unknown: 0 },
      },
    }),
    getLogEvidence: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: true,
      warnings: [],
      data: {
        runId: "101",
        jobId: "job-1",
        jobName: "unit tests",
        available: true,
        lines: [{ sequence: 1, text: "npm test failed token=super-secret" }],
        sha256: createHash("sha256").update("redacted").digest("hex"),
      },
    }),
    getRemediationPlan: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: {
        runId: "101",
        dryRun: true,
        actions: [{ category: "test", title: "test remediation review", steps: ["Inspect the failing test"], runbook: "docs/ci-cd-runbook.md#test" }],
      },
    }),
    rerunFailedWorkflow: vi.fn(),
  };
}

const evidence: ForensicsProviderSet = {
  scm: {
    getChangeEvidence: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "github",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: {
        available: true,
        changes: [{
          path: "src/check.ts",
          changeType: "modified",
          additions: 3,
          deletions: 1,
          hunks: [{ header: "@@ -1 +1 @@", lines: ["+expect(value).toBe(true)"] }],
        }],
      },
    }),
  },
  telemetry: {
    getTelemetryCorrelation: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "prometheus",
      freshness: "fresh",
      truncated: true,
      redactionsApplied: false,
      warnings: [],
      data: {
        available: true,
        signals: [{ id: "error-rate", kind: "metric", state: "degraded", summary: "Error rate elevated", observedAt: NOW.toISOString() }],
      },
    }),
  },
};

describe("provider-neutral CI forensics", () => {
  it("assembles facts, deterministic classifications, correlations, locations, and dry-run suggestions", async () => {
    const result = await assembleFailureAnalysis({
      provider: ciProvider(),
      evidence,
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "101", maxLogLines: 10 },
      clock: () => NOW,
    });

    expect(result.data.classifications).toEqual(expect.arrayContaining([
      expect.objectContaining({ category: "test", confidence: 1 }),
    ]));
    expect(result.data.observedFacts).toEqual(expect.arrayContaining([
      expect.objectContaining({ source: "ci", subject: "workflow.conclusion", value: "failure" }),
    ]));
    expect(result.data.correlations).toEqual(expect.arrayContaining([
      expect.objectContaining({ source: "telemetry", kind: "metric" }),
    ]));
    expect(result.data.likelyLocations).toEqual([
      expect.objectContaining({
        path: "src/check.ts",
        category: "test",
        confidenceClass: "high",
        uncertainty: expect.stringContaining("does not identify"),
        evidenceRefs: ["scm-change-src-check.ts"],
      }),
    ]);
    expect(result.data.suggestions).toEqual([
      expect.objectContaining({ dryRun: true, runbook: "docs/ci-cd-runbook.md#test" }),
    ]);
    expect(JSON.stringify(result)).not.toContain("super-secret");
    expect(JSON.stringify(result)).not.toContain("npm test failed");
    expect(result.truncated).toBe(true);
    expect(result.data.provenance).toEqual(expect.arrayContaining([
      expect.objectContaining({ source: "scm", provider: "github", truncated: false, reason: "available" }),
      expect.objectContaining({ source: "telemetry", provider: "prometheus", truncated: true, reason: "available" }),
    ]));
    expect(result.data.evidenceDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(result.data.budget).toMatchObject({
      maxFiles: 10,
      maxHunks: 20,
      maxLines: 22,
      maxBytes: expect.any(Number),
      maxProviderRequests: 16,
      timeWindow: { from: expect.any(String), to: expect.any(String) },
    });
    expect(result.data.ciEvidence[0]).not.toHaveProperty("lines");
  });

  it("uses an aggregate public budget and produces the same digest independent of provider order", async () => {
    const budget = {
      maxFiles: 1,
      maxHunks: 1,
      maxLines: 2,
      maxBytes: 8_192,
      maxProviderRequests: 6,
      timeWindow: { from: "2026-07-14T00:00:00.000Z", to: NOW.toISOString() },
    };
    const first = await assembleFailureAnalysis({
      provider: ciProvider(),
      evidence,
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "101", budget },
      clock: () => NOW,
    });
    const originalScm = await evidence.scm!.getChangeEvidence({ repo: "owner/repo", workflow: "ci.yml", runId: "101", headSha: SHA, maxChanges: 10, maxHunkLines: 12 });
    if (!originalScm.data.available) throw new Error("test fixture must provide SCM evidence");
    const reversedEvidence: ForensicsProviderSet = {
      scm: { getChangeEvidence: vi.fn().mockResolvedValue({
        ...originalScm,
        data: { available: true, changes: [...originalScm.data.changes].reverse() },
      }) },
      telemetry: evidence.telemetry!,
    };
    const second = await assembleFailureAnalysis({
      provider: ciProvider(),
      evidence: reversedEvidence,
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "101", budget },
      clock: () => NOW,
    });

    expect(first.data.budget).toMatchObject({ maxFiles: 1, maxHunks: 1, maxLines: 2, maxProviderRequests: 6 });
    expect(first.data.budget.usedFiles).toBeLessThanOrEqual(1);
    expect(first.data.budget.usedHunks).toBeLessThanOrEqual(1);
    expect(first.data.budget.usedLines).toBeLessThanOrEqual(2);
    expect(first.data.budget.usedBytes).toBeLessThanOrEqual(8_192);
    expect(first.data.budget.usedProviderRequests).toBeLessThanOrEqual(6);
    expect(first.data.evidenceDigest).toBe(second.data.evidenceDigest);
  });

  it("correlates paths, named metrics, active alerts, and log or trace references without causality", async () => {
    const result = await assembleFailureAnalysis({
      provider: ciProvider(),
      evidence: {
        scm: evidence.scm!,
        telemetry: { getTelemetryCorrelation: vi.fn().mockResolvedValue({
          schemaVersion: "1.0",
          observedAt: NOW.toISOString(),
          providerClass: "prometheus",
          freshness: "fresh",
          truncated: false,
          redactionsApplied: false,
          warnings: [],
          data: { available: true, signals: [
            { id: "request-rate", kind: "metric", state: "degraded", summary: "Request rate changed", observedAt: NOW.toISOString() },
            { id: "api-alert", kind: "alert", state: "error", summary: "API alert active", observedAt: NOW.toISOString() },
            { id: "failure-log", kind: "log", state: "error", summary: "Failure log reference", reference: "log-ref-1", observedAt: NOW.toISOString() },
            { id: "failure-trace", kind: "trace", state: "error", summary: "Failure trace reference", reference: "trace-ref-1", observedAt: NOW.toISOString() },
          ] },
        }) },
      },
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "101" },
      clock: () => NOW,
    });

    expect(result.data.correlations.map((item) => item.kind)).toEqual([
      "changed-path", "metric", "active-alert", "log-reference", "trace-reference",
    ]);
    expect(result.data.correlations.every((item) => item.causality === "not-established")).toBe(true);
    expect(result.data.correlations.every((item) => !/caus(?:e|ed|al)/i.test(item.summary))).toBe(true);
  });

  it("keeps unavailable optional evidence explicit and does not guess correlations", async () => {
    const unavailable: ForensicsProviderSet = {
      scm: { getChangeEvidence: vi.fn().mockRejectedValue(new Error("SCM credential secret")) },
      telemetry: { getTelemetryCorrelation: vi.fn().mockRejectedValue(new Error("telemetry secret")) },
    };
    const result = await assembleFailureAnalysis({
      provider: ciProvider(),
      evidence: unavailable,
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "101" },
      clock: () => NOW,
    });

    expect(result.data.correlations).toEqual([]);
    expect(result.data.provenance).toEqual(expect.arrayContaining([
      expect.objectContaining({ source: "scm", unavailable: true, reason: "provider-request-failed" }),
      expect.objectContaining({ source: "telemetry", unavailable: true, reason: "provider-request-failed" }),
    ]));
    expect(result.warnings).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "scm-unavailable" }),
      expect.objectContaining({ code: "telemetry-unavailable" }),
    ]));
    expect(JSON.stringify(result)).not.toContain("secret");
  });

  it("builds one bounded deduplication-ready agent notification payload", async () => {
    const analysis = await assembleFailureAnalysis({
      provider: ciProvider(),
      evidence,
      input: { repo: "owner/repo", workflow: "ci.yml", runId: "101" },
      clock: () => NOW,
    });
    const payload = buildAgentNotificationPayload({
      analysis,
      eventId: "owner/repo:ci.yml:101:1",
      source: "webhook",
      maxBytes: 2_000,
    });

    expect(payload.dedupeKey).toBe("owner/repo:ci.yml:101:1");
    expect(payload.type).toBe("ci.failure.analysis");
    expect(payload.truncated).toBe(true);
    expect(Buffer.byteLength(JSON.stringify(payload), "utf8")).toBeLessThanOrEqual(2_000);
    expect(payload.analysis).toHaveProperty("data.observedFacts");
    expect(JSON.stringify(payload)).not.toContain("super-secret");
  });
});
