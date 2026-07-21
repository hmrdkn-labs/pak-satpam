import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, statSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import {
  InMemoryObserverMetrics,
  ObserverRuntime,
  type ObserverProvider,
} from "../src/observer/runtime.js";
import {
  FileObserverStateStore,
  InMemoryObserverStateStore,
} from "../src/observer/state.js";
import { HermesDelivery, signHermesPayload } from "../src/observer/delivery.js";
import type { ObserverConfig } from "../src/observer/config.js";
import type { CIWorkflowRun } from "../src/domain/ci-schemas.js";
import {
  ANALYSIS_ACTION_PORTS,
  ANALYSIS_RERUN_BOUNDARY,
  ANALYSIS_TOOL_SURFACE,
  boundAnalysisInput,
  runBoundedRecommendationAnalysis,
} from "../src/observer/analysis-policy.js";
import {
  EventCorrelationSchema,
  ObserverEventEnvelopeSchema,
  createObserverEventEnvelope,
  observerEnvelopeDigest,
  observerReplayKey,
  serializeObserverEventEnvelope,
} from "../src/observer/event-envelope.js";

const NOW = new Date("2026-07-14T00:00:00.000Z");
const SHA = "a".repeat(40);

const policyBaseInput = {
  event: { repository: "owner/repo", workflow: "build.yml", runId: "101", commitSha: "a".repeat(40) },
  diff: [{ path: "src/check.ts", changeType: "modified" as const, additions: 2, deletions: 1, hunkCount: 1 }],
  logs: ["Authorization: Bearer ghp_super-secret", "failure observed"],
  metrics: [{ name: "http_requests_total", state: "error", value: 3, sampleCount: 4 }],
  traces: [{ spanDigest: "b".repeat(64), durationMs: 12, status: "error" as const }],
};

const envelopeBase = {
  eventId: "owner/repo:ci.yml:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:failure",
  observedAt: "2026-07-14T00:00:00.000Z",
  source: "poll" as const,
  repo: "owner/repo",
  workflow: "ci.yml",
  runId: "101",
  runAttempt: 1,
  terminalConclusion: "failure",
  outcome: "failure",
  notification: "failure" as const,
  severity: "red" as const,
  threadId: "owner/repo:ci.yml",
  freshness: "fresh" as const,
  updatedAt: "2026-07-14T00:00:00.000Z",
};

function run(id: string, conclusion: CIWorkflowRun["conclusion"], updatedAt = NOW.toISOString()): CIWorkflowRun {
  return {
    id,
    repository: "owner/repo",
    workflow: "ci.yml",
    status: "completed",
    conclusion,
    runAttempt: 1,
    event: "workflow_dispatch",
    ref: "main",
    sha: SHA,
    createdAt: updatedAt,
    updatedAt,
  };
}

function config(overrides: Partial<ObserverConfig> = {}): ObserverConfig {
  return {
    allowlist: [{ repo: "owner/repo", workflows: ["ci.yml"] }],
    stateFile: "/tmp/observer-state.json",
    hermesUrl: "https://hermes.example/ci-events",
    hmacKey: Buffer.from("hmac-key-that-is-at-least-32-bytes-long"),
    pollIntervalMs: 30_000,
    overlapMs: 5 * 60_000,
    staleAfterMs: 10 * 60_000,
    pageSize: 100,
    maxPages: 2,
    maxFailedJobs: 2,
    maxLogLines: 3,
    maxPayloadBytes: 32_000,
    leaseMs: 30_000,
    deliveryAttempts: 3,
    deliveryBackoffMs: 10,
    deliveryTimeoutMs: 1_000,
    ...overrides,
  };
}

function provider(overrides: Partial<ObserverProvider> = {}): ObserverProvider {
  return {
    matchesWorkflow: (allowlistEntry, workflow) => workflow === allowlistEntry,
    listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [], hasMore: false }),
    getWorkflowStatus: vi.fn(),
    getFailedJobAnalysis: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: {
        run: run("1", "failure"),
        failedJobs: [{ id: "9", name: "test", status: "completed", conclusion: "failure", category: "test", failedSteps: ["unit"] }],
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
      data: { runId: "1", jobId: "9", jobName: "test", available: true, lines: [{ sequence: 1, text: "token=[REDACTED]" }], sha256: createHash("sha256").update("token=[REDACTED]").digest("hex") },
    }),
    getRemediationPlan: vi.fn().mockResolvedValue({
      schemaVersion: "1.0",
      observedAt: NOW.toISOString(),
      providerClass: "github-actions",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: { runId: "1", dryRun: true, actions: [{ category: "test", title: "test remediation review", steps: ["Inspect the bounded failure"], runbook: "docs/ci-cd-runbook.md#test" }] },
    }),
    rerunFailedWorkflow: vi.fn(),
    ...overrides,
  };
}

describe("portable observer runtime", () => {
  it("uses state transitions for red failures and one green recovery", async () => {
    const source = {
      listTerminalRuns: vi.fn()
        .mockResolvedValueOnce({ runs: [run("90", "failure")], hasMore: false })
        .mockResolvedValueOnce({ runs: [], hasMore: false })
        .mockResolvedValueOnce({ runs: [run("91", "success")], hasMore: false })
        .mockResolvedValueOnce({ runs: [], hasMore: false })
        .mockResolvedValueOnce({ runs: [run("92", "success")], hasMore: false })
        .mockResolvedValueOnce({ runs: [], hasMore: false }),
    };
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({
      config: config({ maxPages: 1 }),
      provider: provider(),
      source,
      state: new InMemoryObserverStateStore(),
      deliver,
      clock: () => NOW,
    });

    await runtime.pollOnce();
    await runtime.pollOnce();
    await runtime.pollOnce();

    expect(deliver).toHaveBeenCalledTimes(3);
    expect(deliver.mock.calls.map((call) => call[2])).toEqual(["success", "analysis", "success"]);
    expect(JSON.parse(String(deliver.mock.calls[0]?.[0]))).toMatchObject({
      notification: "failure",
      severity: "red",
      eventId: `owner/repo:ci.yml:${SHA}:failure`,
      threadId: "owner/repo:ci.yml",
    });
    expect(JSON.parse(String(deliver.mock.calls[1]?.[0]))).toMatchObject({ type: "ci.failure.analysis" });
    expect(JSON.parse(String(deliver.mock.calls[2]?.[0]))).toMatchObject({
      notification: "recovery",
      severity: "green",
      eventId: `owner/repo:ci.yml:${SHA}:success`,
      threadId: "owner/repo:ci.yml",
    });
  });

  it("does not repeat an analysis attempt after analysis delivery failure", async () => {
    let now = NOW;
    const state = new InMemoryObserverStateStore();
    const source = {
      listTerminalRuns: vi.fn()
        .mockResolvedValueOnce({ runs: [run("93", "failure")], hasMore: false })
        .mockResolvedValueOnce({ runs: [], hasMore: false })
        .mockResolvedValue({ runs: [run("93", "failure")], hasMore: false }),
    };
    const ci = provider({ getFailedJobAnalysis: vi.fn() });
    const deliver = vi.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("analysis transport unavailable"));
    const runtime = new ObserverRuntime({ config: config({ maxPages: 1 }), provider: ci, source, state, deliver, clock: () => now });

    await runtime.pollOnce();
    now = new Date("2026-07-14T00:00:00.010Z");
    await runtime.pollOnce();

    expect(ci.getFailedJobAnalysis).toHaveBeenCalledTimes(1);
    expect(deliver).toHaveBeenCalledTimes(2);
    expect(Object.values(state.load().targets)[0]?.seen[`owner/repo:ci.yml:${SHA}:failure`]).toMatchObject({
      analysisAttempted: true,
      analysisDelivery: "pending",
    });
  });

  it("deduplicates webhook and poll notifications by SHA and conclusion", async () => {
    const candidate = run("94", "failure");
    const source = {
      listTerminalRuns: vi.fn().mockResolvedValue({ runs: [candidate], hasMore: false }),
      webhookVerifier: { verify: vi.fn().mockResolvedValue([candidate]) },
    };
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config(), provider: provider(), source, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await runtime.ingestWebhook({ headers: {}, body: "signed" });
    await runtime.pollOnce();

    expect(deliver.mock.calls.map((call) => call[1])).toEqual([
      `owner/repo:ci.yml:${SHA}:failure:status`,
      `owner/repo:ci.yml:${SHA}:failure:analysis`,
    ]);
  });

  it("observes multiple terminal runs, rescans newest pages, and deduplicates deliveries", async () => {
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockResolvedValue({ runs: [run("2", "success"), run("1", "failure")], hasMore: false }),
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({
      config: config(),
      provider: ci,
      state: new InMemoryObserverStateStore(),
      deliver,
      clock: () => NOW,
      metrics: new InMemoryObserverMetrics(),
    });

    const first = await runtime.pollOnce();
    const second = await runtime.pollOnce();

    expect(first.observed).toEqual(expect.arrayContaining([
      expect.objectContaining({ runId: "1", outcome: "failure" }),
      expect.objectContaining({ runId: "2", outcome: "success" }),
    ]));
    expect(deliver).toHaveBeenCalledTimes(3);
    expect(ci.listWorkflowRuns).toHaveBeenNthCalledWith(1, expect.objectContaining({
      page: 1,
      perPage: 100,
    }));
    expect(ci.listWorkflowRuns).toHaveBeenNthCalledWith(2, expect.objectContaining({ page: 1, createdAfter: expect.any(String) }));
    expect(second.delivered).toBe(0);
    expect(ci.rerunFailedWorkflow).not.toHaveBeenCalled();
  });

  it.each([
    ["success", "success"],
    ["failure", "failure"],
    ["cancelled", "cancelled"],
    ["timed_out", "timed_out"],
    ["action_required", "action_required"],
    ["skipped", "skipped"],
    ["neutral", "neutral"],
  ] as const)("maps %s terminal conclusions", async (conclusion, outcome) => {
    const runtime = new ObserverRuntime({
      config: config(),
      provider: provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("1", conclusion)], hasMore: false }) }),
      state: new InMemoryObserverStateStore(),
      deliver: vi.fn().mockResolvedValue(undefined),
      clock: () => NOW,
    });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ observed: [expect.objectContaining({ outcome })] });
  });

  it("marks old runs stale and maps provider failures without leaking error text", async () => {
    const secret = "provider-secret-must-not-escape";
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockResolvedValueOnce({ runs: [run("1", "success", "2026-07-13T23:00:00.000Z")], hasMore: false })
        .mockResolvedValueOnce({ runs: [], hasMore: false })
        .mockRejectedValueOnce(Object.assign(new Error(secret), { code: "malformed" })),
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    const stale = await runtime.pollOnce();
    const malformed = await runtime.pollOnce();

    expect(stale.observed[0]).toMatchObject({ outcome: "stale" });
    expect(malformed.errors).toEqual([{ repo: "owner/repo", workflow: "ci.yml", outcome: "malformed" }]);
    expect(JSON.stringify(malformed)).not.toContain(secret);
  });

  it("retrieves bounded analysis, evidence, and remediation for failures", async () => {
    const ci = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("1", "failure")], hasMore: false }) });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config({ maxFailedJobs: 1, maxLogLines: 3 }), provider: ci, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await runtime.pollOnce();

    expect(ci.getFailedJobAnalysis).toHaveBeenCalledWith({ repo: "owner/repo", workflow: "ci.yml", runId: "1" });
    expect(ci.getLogEvidence).toHaveBeenCalledWith({ repo: "owner/repo", workflow: "ci.yml", runId: "1", jobId: "9", maxLines: 3 });
    expect(ci.getRemediationPlan).toHaveBeenCalledWith({ repo: "owner/repo", workflow: "ci.yml", runId: "1" });
    expect(deliver.mock.calls[0]?.[2]).toBe("success");
    expect(deliver.mock.calls[1]?.[2]).toBe("analysis");
    expect(JSON.stringify(deliver.mock.calls[1]?.[0])).not.toContain("provider-secret");
    expect(JSON.stringify(deliver.mock.calls[1]?.[0])).not.toContain("token=[REDACTED]");
    expect(JSON.stringify(deliver.mock.calls[1]?.[0])).not.toContain('"failedSteps"');
    expect(String(deliver.mock.calls[1]?.[0])).toContain('"ciEvidence"');
    expect(String(deliver.mock.calls[1]?.[0])).toContain('"runbook":"docs/ci-cd-runbook.md#test"');
  });

  it("delivers one bounded failure analysis notification", async () => {
    const ci = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("50", "failure")], hasMore: false }) });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 2 });
    expect(deliver.mock.calls.map((call) => call[2])).toEqual(["success", "analysis"]);
    expect(deliver.mock.calls.map((call) => call[1])).toEqual([`owner/repo:ci.yml:${SHA}:failure:status`, `owner/repo:ci.yml:${SHA}:failure:analysis`]);
    expect(JSON.parse(String(deliver.mock.calls[0]?.[0])).type).toBe("ci.run.observed");
    expect(JSON.parse(String(deliver.mock.calls[0]?.[0])).outcome).toBe("failure");
    expect(JSON.parse(String(deliver.mock.calls[1]?.[0])).type).toBe("ci.failure.analysis");
    expect(JSON.parse(String(deliver.mock.calls[1]?.[0])).analysis).toBeDefined();
  });

  it("does not repeat an analysis attempt after a failed analysis route", async () => {
    const state = new InMemoryObserverStateStore();
    let now = NOW;
    const ci = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("51", "failure")], hasMore: false }) });
    const deliver = vi.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error("analysis transport secret"));
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state, deliver, clock: () => now });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 1 });
    const recordAfterFailure = Object.values(state.load().targets)[0]?.seen[`owner/repo:ci.yml:${SHA}:failure`];
    expect(recordAfterFailure).toMatchObject({ delivery: "delivered", statusDelivery: "delivered", analysisAttempted: true, analysisDelivery: "pending" });
    expect(state.load().targets["owner/repo\u001fci.yml"]).toMatchObject({ deliveryBackoffUntil: "2026-07-14T00:00:00.010Z" });
    now = new Date("2026-07-14T00:00:00.010Z");
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0 });
    expect(deliver.mock.calls.map((call) => call[2])).toEqual(["success", "analysis"]);
    expect(deliver.mock.calls.map((call) => call[1])).toEqual([`owner/repo:ci.yml:${SHA}:failure:status`, `owner/repo:ci.yml:${SHA}:failure:analysis`]);
  });

  it("recovers both route delivery records after an observer restart", async () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-critical-restart-"));
    const statePath = join(directory, "state.json");
    try {
      const firstDelivery = vi.fn().mockResolvedValue(undefined);
      const first = new ObserverRuntime({
        config: config({ stateFile: statePath }),
        provider: provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("52", "failure")], hasMore: false }) }),
        state: new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }),
        deliver: firstDelivery,
        clock: () => NOW,
      });
      await first.pollOnce();
      expect(firstDelivery).toHaveBeenCalledTimes(2);
      expect(Object.values(new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }).load().targets)[0]?.seen[`owner/repo:ci.yml:${SHA}:failure`]).toMatchObject({ statusDelivery: "delivered", analysisDelivery: "delivered", analysisAttempted: true });

      const secondDelivery = vi.fn().mockResolvedValue(undefined);
      const second = new ObserverRuntime({
        config: config({ stateFile: statePath }),
        provider: provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("52", "failure")], hasMore: false }) }),
        state: new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }),
        deliver: secondDelivery,
        clock: () => NOW,
      });
      await second.pollOnce();
      expect(secondDelivery).not.toHaveBeenCalled();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("persists webhook analysis dedupe identity across a restart before polling", async () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-webhook-restart-"));
    const statePath = join(directory, "state.json");
    const candidate = run("86", "failure");
    const eventId = `owner/repo:ci.yml:${SHA}:failure`;
    try {
      const firstDelivery = vi.fn().mockResolvedValue(undefined);
      const first = new ObserverRuntime({
        config: config({ stateFile: statePath }),
        provider: provider(),
        source: {
          listTerminalRuns: vi.fn(),
          webhookVerifier: { verify: vi.fn().mockResolvedValue([candidate]) },
        },
        state: new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }),
        deliver: firstDelivery,
        clock: () => NOW,
      });

      await expect(first.ingestWebhook({ headers: {}, body: "signed" })).resolves.toMatchObject({ accepted: true, delivered: 2 });
      expect(firstDelivery.mock.calls.map((call) => call[1])).toEqual([`${eventId}:status`, `${eventId}:analysis`]);
      const statusEnvelope = JSON.parse(String(firstDelivery.mock.calls[0]?.[0])) as Record<string, unknown>;
      expect(statusEnvelope).toMatchObject({ eventId, dedupeKey: eventId, replayKey: "owner/repo:ci.yml:86:1", identity: { dedupeKey: eventId, replayKey: "owner/repo:ci.yml:86:1" } });
      expect(Object.values(new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }).load().targets)[0]?.seen[eventId]).toMatchObject({ statusDelivery: "delivered", analysisDelivery: "delivered", analysisAttempted: true });

      const secondDelivery = vi.fn().mockResolvedValue(undefined);
      const second = new ObserverRuntime({
        config: config({ stateFile: statePath }),
        provider: provider(),
        source: { listTerminalRuns: vi.fn().mockResolvedValue({ runs: [candidate], hasMore: false }) },
        state: new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }),
        deliver: secondDelivery,
        clock: () => NOW,
      });

      await expect(second.pollOnce()).resolves.toMatchObject({ delivered: 0, observed: [] });
      expect(secondDelivery).not.toHaveBeenCalled();
      expect(Object.values(new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }).load().targets)[0]?.seen[eventId]).toMatchObject({ statusDelivery: "delivered", analysisDelivery: "delivered", analysisAttempted: true });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("reads legacy run-id state without duplicating a delivered failure", async () => {
    const state = new InMemoryObserverStateStore();
    state.save({
      version: 1,
      updatedAt: NOW.toISOString(),
      targets: {
        "owner/repo\u001fci.yml": {
          page: 1,
          seen: {
            "owner/repo:ci.yml:95:1": {
              outcome: "failure",
              observedAt: NOW.toISOString(),
              delivery: "delivered",
              statusDelivery: "delivered",
              analysisDelivery: "delivered",
            },
          },
        },
      },
    });
    const deliver = vi.fn();
    const runtime = new ObserverRuntime({
      config: config(),
      provider: provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("95", "failure")], hasMore: false }) }),
      state,
      deliver,
      clock: () => NOW,
    });

    await runtime.pollOnce();

    expect(deliver).not.toHaveBeenCalled();
    expect(Object.values(state.load().targets)[0]?.seen[`owner/repo:ci.yml:${SHA}:failure`]).toMatchObject({ statusDelivery: "delivered", analysisAttempted: true });
  });

  it("silences successful runs unless they recover a delivered failure", async () => {
    const ci = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("53", "success")], hasMore: false }) });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0 });
    expect(deliver).not.toHaveBeenCalled();
    expect(ci.getFailedJobAnalysis).not.toHaveBeenCalled();
  });

  it("records stale runs without delivering status or analysis", async () => {
    const stale = run("54", "failure", new Date(NOW.getTime() - 11 * 60_000).toISOString());
    const ci = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [stale], hasMore: false }) });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const state = new InMemoryObserverStateStore();
    const metrics = new InMemoryObserverMetrics();
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state, deliver, clock: () => NOW, metrics });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, observed: [{ runId: "54", outcome: "stale" }] });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, observed: [] });

    expect(deliver).not.toHaveBeenCalled();
    expect(ci.getFailedJobAnalysis).not.toHaveBeenCalled();
    expect(ci.getLogEvidence).not.toHaveBeenCalled();
    expect(ci.getRemediationPlan).not.toHaveBeenCalled();
    expect(Object.values(state.load().targets)[0]?.seen[`owner/repo:ci.yml:${SHA}:failure`]).toMatchObject({
      delivery: "suppressed",
      statusDelivery: "suppressed",
      analysisDelivery: "suppressed",
    });
    expect(metrics.snapshot()).toMatchObject({ suppressed: 1, deliveries: 0 });
  });

  it("enforces exact repository/workflow allowlists", async () => {
    const ci = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [], hasMore: false }) });
    const runtime = new ObserverRuntime({
      config: config({ allowlist: [{ repo: "owner/other", workflows: ["allowed.yml"] }] }),
      provider: ci,
      state: new InMemoryObserverStateStore(),
      deliver: vi.fn(),
      clock: () => NOW,
    });
    await runtime.pollOnce();
    expect(ci.listWorkflowRuns).toHaveBeenCalledWith(expect.objectContaining({ repo: "owner/other", workflow: "allowed.yml" }));
    expect(ci.listWorkflowRuns).not.toHaveBeenCalledWith(expect.objectContaining({ repo: "owner/repo", workflow: "../ci.yml" }));
  });

  it("deduplicates the same run when overlapping provider pages repeat it", async () => {
    const duplicate = run("77", "success");
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockResolvedValueOnce({ runs: [duplicate], hasMore: true, nextPage: 2 })
        .mockResolvedValueOnce({ runs: [duplicate], hasMore: false }),
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config({ maxPages: 2 }), provider: ci, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await runtime.pollOnce();

    expect(deliver).toHaveBeenCalledTimes(0);
  });

  it("reconciles a verified webhook with polling using one provider-neutral event identity", async () => {
    const candidate = run("81", "success");
    const listTerminalRuns = vi.fn().mockResolvedValue({ runs: [candidate], hasMore: false });
    const verify = vi.fn().mockResolvedValue([candidate]);
    const source = {
      providerClass: "jenkins",
      listTerminalRuns,
      webhookVerifier: { verify },
    };
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({
      config: config(),
      provider: provider(),
      source,
      state: new InMemoryObserverStateStore(),
      deliver,
      clock: () => NOW,
    });

    const webhook = await runtime.ingestWebhook({ headers: { "x-provider-signature": "verified-by-adapter" }, body: "provider payload" });
    const poll = await runtime.pollOnce();

    expect(verify).toHaveBeenCalledWith({ headers: { "x-provider-signature": "verified-by-adapter" }, body: "provider payload" });
    expect(webhook).toMatchObject({ accepted: true, delivered: 0, observed: [{ runId: "81", outcome: "success" }] });
    expect(poll).toMatchObject({ delivered: 0, observed: [] });
    expect(deliver).toHaveBeenCalledTimes(0);
    expect(deliver).not.toHaveBeenCalled();
  });

  it("deduplicates both status and analysis across webhook then poll", async () => {
    const candidate = run("85", "failure");
    const source = {
      listTerminalRuns: vi.fn().mockResolvedValue({ runs: [candidate], hasMore: false }),
      webhookVerifier: { verify: vi.fn().mockResolvedValue([candidate]) },
    };
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config(), provider: provider(), source, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await expect(runtime.ingestWebhook({ headers: {}, body: "signed" })).resolves.toMatchObject({ accepted: true, delivered: 2 });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, observed: [] });
    expect(deliver.mock.calls.map((call) => call[2])).toEqual(["success", "analysis"]);
  });

  it("does not redeliver a webhook after polling has settled the same run", async () => {
    const candidate = run("84", "success");
    const state = new InMemoryObserverStateStore();
    const deliver = vi.fn().mockResolvedValue(undefined);
    const source = {
      listTerminalRuns: vi.fn().mockResolvedValue({ runs: [candidate], hasMore: false }),
      webhookVerifier: { verify: vi.fn().mockResolvedValue([candidate]) },
    };
    const runtime = new ObserverRuntime({ config: config(), provider: provider(), source, state, deliver, clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0 });
    await expect(runtime.ingestWebhook({ headers: {}, body: "duplicate" })).resolves.toMatchObject({ accepted: true, delivered: 0, observed: [] });
    expect(deliver).toHaveBeenCalledTimes(0);
  });

  it("does not call provider analysis or delivery for stale webhook runs", async () => {
    const stale = run("82", "failure", new Date(NOW.getTime() - 11 * 60_000).toISOString());
    const ci = provider({ listWorkflowRuns: vi.fn(), getFailedJobAnalysis: vi.fn(), getLogEvidence: vi.fn(), getRemediationPlan: vi.fn() });
    const source = {
      listTerminalRuns: vi.fn(),
      webhookVerifier: { verify: vi.fn().mockResolvedValue([stale]) },
    };
    const deliver = vi.fn();
    const runtime = new ObserverRuntime({ config: config(), provider: ci, source, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await expect(runtime.ingestWebhook({ headers: {}, body: "stale" })).resolves.toMatchObject({ accepted: true, delivered: 0, observed: [{ outcome: "stale" }] });
    expect(source.listTerminalRuns).not.toHaveBeenCalled();
    expect(ci.getFailedJobAnalysis).not.toHaveBeenCalled();
    expect(ci.getLogEvidence).not.toHaveBeenCalled();
    expect(ci.getRemediationPlan).not.toHaveBeenCalled();
    expect(deliver).not.toHaveBeenCalled();
  });

  it("fails closed when a provider webhook verifier rejects the payload", async () => {
    const source = {
      listTerminalRuns: vi.fn(),
      webhookVerifier: { verify: vi.fn().mockRejectedValue(new Error("signature detail must not escape")) },
    };
    const ci = provider({ getFailedJobAnalysis: vi.fn(), getLogEvidence: vi.fn(), getRemediationPlan: vi.fn() });
    const deliver = vi.fn();
    const runtime = new ObserverRuntime({ config: config(), provider: ci, source, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await expect(runtime.ingestWebhook({ headers: {}, body: "untrusted" })).resolves.toMatchObject({ accepted: false, errors: [{ repo: "unknown", workflow: "unknown", outcome: "malformed" }] });
    expect(source.listTerminalRuns).not.toHaveBeenCalled();
    expect(deliver).not.toHaveBeenCalled();
  });

  it("persists delivery backoff so a failed sink is not retried on every poll", async () => {
    let now = NOW;
    const listWorkflowRuns = vi.fn().mockResolvedValue({ runs: [run("83", "failure")], hasMore: false });
    const ci = provider({ listWorkflowRuns });
    const deliver = vi.fn().mockRejectedValue(new Error("sink unavailable"));
    const state = new InMemoryObserverStateStore();
    const runtime = new ObserverRuntime({ config: config({ deliveryAttempts: 1, deliveryBackoffMs: 100 }), provider: ci, state, deliver, clock: () => now });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, errors: [] });
    const callsAfterFailure = listWorkflowRuns.mock.calls.length;
    expect(Object.values(state.load().targets)[0]).toMatchObject({ deliveryBackoffMs: 100, deliveryBackoffUntil: "2026-07-14T00:00:00.100Z" });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, errors: [{ outcome: "unavailable" }] });
    expect(listWorkflowRuns).toHaveBeenCalledTimes(callsAfterFailure);
    now = new Date("2026-07-14T00:00:00.100Z");
    await runtime.pollOnce();
    expect(listWorkflowRuns.mock.calls.length).toBeGreaterThan(callsAfterFailure);
  });
});

describe("Goal 23 bounded recommendation policy", () => {
  it("passes only bounded, redacted evidence and the exact five-tool surface", () => {
    const input = boundAnalysisInput({ ...policyBaseInput, logs: Array.from({ length: 200 }, () => "x".repeat(2_000)) }, { maxBytes: 4_096, maxLogLines: 3 });
    expect(input.allowedTools).toEqual([...ANALYSIS_TOOL_SURFACE]);
    expect(input.logs).toHaveLength(3);
    expect(JSON.stringify(input)).not.toContain("ghp_super-secret");
    expect(Buffer.byteLength(JSON.stringify(input))).toBeLessThanOrEqual(4_096);
    expect(input).not.toHaveProperty("labels");
    expect(input).not.toHaveProperty("traceId", "span-secret");
  });

  it("invokes one callback and strips adversarial authority fields", async () => {
    const callback = vi.fn(async (_input, context) => {
      expect(context.actionPorts).toEqual([]);
      expect(context.rerun.available).toBe(false);
      expect(context).not.toHaveProperty("provider");
      expect(context).not.toHaveProperty("invoke");
      return {
        recommendations: [{ title: "Inspect the failing test", rationale: "Evidence is non-causal", steps: ["Review the runbook"], evidenceRefs: ["ci-status"] }],
        status: "success",
        deploy: true,
        rollback: true,
        rerun: true,
      };
    });
    const result = await runBoundedRecommendationAnalysis({ input: policyBaseInput, callback });
    expect(callback).toHaveBeenCalledTimes(1);
    expect(callback.mock.calls[0]?.[1]).toMatchObject({
      allowedTools: ["ci.workflow_status", "ci.failed_job_analysis", "ci.log_evidence", "ci.remediation_plan", "ci.rerun_failed_workflow"],
      actionPorts: ANALYSIS_ACTION_PORTS,
      rerun: ANALYSIS_RERUN_BOUNDARY,
    });
    expect(callback.mock.calls[0]?.[1]).not.toHaveProperty("provider");
    expect(result).toEqual(expect.objectContaining({ available: true, reason: "available" }));
    expect(result).not.toHaveProperty("status");
    expect(result).not.toHaveProperty("deploy");
    expect(result).not.toHaveProperty("rollback");
    expect(result).not.toHaveProperty("rerun");
  });

  it("returns deterministic timeout and unavailable fallbacks", async () => {
    const timeout = await runBoundedRecommendationAnalysis({
      input: policyBaseInput,
      limits: { timeoutMs: 25 },
      callback: async (_input, context) => new Promise((_resolve, reject) => {
        context.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true });
      }),
    });
    expect(timeout).toEqual({ available: false, reason: "timeout" });
    expect(await runBoundedRecommendationAnalysis({ input: policyBaseInput })).toEqual({ available: false, reason: "unavailable" });
  });

  it("settles immediately when the external signal aborts an ignoring callback", async () => {
    const controller = new AbortController();
    let started!: () => void;
    const callbackStarted = new Promise<void>((resolve) => { started = resolve; });
    const analysis = runBoundedRecommendationAnalysis({
      input: policyBaseInput,
      limits: { timeoutMs: 5_000 },
      signal: controller.signal,
      callback: async () => {
        started();
        return new Promise<never>(() => {});
      },
    });
    await callbackStarted;
    controller.abort();
    await expect(analysis).resolves.toEqual({ available: false, reason: "aborted" });
  });

  it("re-bounds schema-valid input against the requested byte and count limits", async () => {
    const prebounded = boundAnalysisInput({ ...policyBaseInput, logs: Array.from({ length: 100 }, () => "x".repeat(512)) }, { maxBytes: 64 * 1024, maxLogLines: 100 });
    const callback = vi.fn(async (input) => {
      expect(input.logs).toHaveLength(3);
      expect(Buffer.byteLength(JSON.stringify(input), "utf8")).toBeLessThanOrEqual(4_096);
      return { title: "bounded", steps: [], evidenceRefs: [] };
    });
    await expect(runBoundedRecommendationAnalysis({ input: prebounded, callback, limits: { maxBytes: 4_096, maxLogLines: 3 } })).resolves.toMatchObject({ available: true });
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it("enforces maxBytes when scalar event metadata alone exceeds the requested bound", async () => {
    const prebounded = boundAnalysisInput({
      event: {
        repository: "r".repeat(200),
        workflow: "w".repeat(200),
        runId: "i".repeat(64),
        commitSha: "a".repeat(128),
        deploymentId: "d".repeat(128),
        traceId: "t".repeat(128),
      },
    }, { maxBytes: 64 * 1024 });
    const callback = vi.fn(async (input) => {
      expect(Buffer.byteLength(JSON.stringify(input), "utf8")).toBeLessThanOrEqual(1_024);
      return { title: "bounded", steps: [], evidenceRefs: [] };
    });
    await expect(runBoundedRecommendationAnalysis({ input: prebounded, callback, limits: { maxBytes: 1_024 } })).resolves.toMatchObject({ available: true });
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it("exposes exact /mcp/ci metadata without provider or invokable authority ports", async () => {
    let rerunInvoked = false;
    const callback = vi.fn(async (_input, context) => {
      expect(context.allowedTools).toEqual(["ci.workflow_status", "ci.failed_job_analysis", "ci.log_evidence", "ci.remediation_plan", "ci.rerun_failed_workflow"]);
      expect(context.allowedTools).toEqual([...ANALYSIS_TOOL_SURFACE]);
      expect(context.actionPorts).toEqual([]);
      expect(context.actionPorts).toEqual(ANALYSIS_ACTION_PORTS);
      expect(context).not.toHaveProperty("provider");
      expect(context).not.toHaveProperty("status");
      expect(context).not.toHaveProperty("deploy");
      expect(context).not.toHaveProperty("rollback");
      expect(context.rerun).toEqual(ANALYSIS_RERUN_BOUNDARY);
      expect(context.rerun.available).toBe(false);
      expect(context.rerun).not.toHaveProperty("invoke");
      const possibleInvoke = (context.rerun as unknown as { invoke?: () => void }).invoke;
      if (typeof possibleInvoke === "function") {
        rerunInvoked = true;
        possibleInvoke();
      }
      return {
        title: "inspect failure",
        rationale: "bounded evidence only",
        steps: ["read the runbook"],
        evidenceRefs: ["ci-status"],
        status: "success",
        transition: "recovery",
        dedupeKey: "attacker-controlled",
        route: "success",
        deploy: true,
        rollback: true,
        rerun: { invoke: () => { rerunInvoked = true; } },
      };
    });
    await expect(runBoundedRecommendationAnalysis({ input: policyBaseInput, callback })).resolves.toEqual({
      available: true,
      reason: "available",
      recommendation: { title: "inspect failure", rationale: "bounded evidence only", steps: ["read the runbook"], evidenceRefs: ["ci-status"] },
    });
    expect(rerunInvoked).toBe(false);
  });

  it("caps aggregate recommendation text while retaining a nonempty title", async () => {
    const result = await runBoundedRecommendationAnalysis({
      input: policyBaseInput,
      limits: { maxText: 32 },
      callback: async () => ({ title: "inspect failure", rationale: "r".repeat(512), steps: ["s".repeat(512), "later step"], evidenceRefs: ["e".repeat(64), "later-ref"] }),
    });
    expect(result).toMatchObject({ available: true, reason: "available" });
    const recommendation = result.recommendation;
    expect(recommendation).toBeDefined();
    const textualLength = (recommendation?.title.length ?? 0) + (recommendation?.rationale?.length ?? 0) + (recommendation?.steps.join("").length ?? 0) + (recommendation?.evidenceRefs.join("").length ?? 0);
    expect(textualLength).toBeLessThanOrEqual(32);
    expect(recommendation?.title.length).toBeGreaterThan(0);
  });
});

describe("Goal23 observer event envelope", () => {
  it("normalizes stable dedupe/replay identity and truthful correlation markers", () => {
    const envelope = createObserverEventEnvelope({ ...envelopeBase, correlation: { commitSha: "a".repeat(40) } });
    expect(envelope.eventId).toBe(envelopeBase.eventId);
    expect(envelope.dedupeKey).toBe(envelopeBase.eventId);
    expect(envelope.replayKey).toBe(observerReplayKey({ repo: envelopeBase.repo, workflow: envelopeBase.workflow, runId: envelopeBase.runId, runAttempt: 1 }));
    expect(envelope.correlation).toEqual({ deploymentId: { available: false, reason: "absent" }, commitSha: { available: true, value: "a".repeat(40) }, artifactDigest: { available: false, reason: "absent" }, traceId: { available: false, reason: "absent" } });
    expect(ObserverEventEnvelopeSchema.parse(envelope)).toEqual(envelope);
    expect(EventCorrelationSchema.parse(envelope.correlation)).toEqual(envelope.correlation);
  });

  it("keeps identity stable across poll and webhook and gives deterministic digest", () => {
    const poll = createObserverEventEnvelope(envelopeBase);
    const webhook = createObserverEventEnvelope({ ...envelopeBase, source: "webhook" });
    expect(poll.identity).toEqual(webhook.identity);
    expect(observerEnvelopeDigest(poll)).toBe(observerEnvelopeDigest(poll));
    expect(observerEnvelopeDigest(poll)).not.toBe(observerEnvelopeDigest(webhook));
  });

  it("rejects caller-controlled dedupe and replay identity overrides", () => {
    expect(() => createObserverEventEnvelope({ ...envelopeBase, dedupeKey: "attacker-controlled" })).toThrow("event_envelope_malformed");
    expect(() => createObserverEventEnvelope({ ...envelopeBase, replayKey: "attacker-controlled" })).toThrow("event_envelope_malformed");
    const matching = createObserverEventEnvelope({ ...envelopeBase, dedupeKey: envelopeBase.eventId, replayKey: observerReplayKey(envelopeBase) });
    expect(matching.identity).toEqual({ dedupeKey: envelopeBase.eventId, replayKey: observerReplayKey(envelopeBase) });
  });

  it.each([
    ["missing", { ...envelopeBase, repo: "" }],
    ["secret", { ...envelopeBase, workflow: "Authorization: Bearer ghp_secret" }],
    ["malformed correlation", { ...envelopeBase, correlation: { commitSha: "not-a-sha" } }],
    ["malformed structured correlation", { ...envelopeBase, correlation: { commitSha: { available: true, value: "not-a-sha" } } }],
  ])("rejects %s input", (_label, value) => {
    expect(() => createObserverEventEnvelope(value as Parameters<typeof createObserverEventEnvelope>[0])).toThrow(/event_envelope_/);
  });

  it("rejects oversized serialization without leaking the payload", () => {
    const envelope = createObserverEventEnvelope({ ...envelopeBase, warnings: [{ code: "bounded", message: "x".repeat(500) }] });
    expect(() => serializeObserverEventEnvelope(envelope, 256)).toThrow("event_envelope_too_large");
  });

  it("rejects webhook signing secrets in adversarial fields without exposing them", () => {
    const secret = "whsec_adversarial_signing_secret_123";
    const adversarial = { ...envelopeBase, webhookSigningSecret: secret } as unknown as Parameters<typeof createObserverEventEnvelope>[0];
    let error: unknown;
    try {
      createObserverEventEnvelope(adversarial);
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(Error);
    expect(String(error)).toBe("Error: event_envelope_secret");
    expect(String(error)).not.toContain(secret);
  });
});

describe("observer state and Hermes delivery", () => {
  it("writes private state atomically and leases it", () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-state-"));
    const path = join(directory, "state.json");
    try {
      const first = new FileObserverStateStore({ filePath: path, leaseMs: 30_000, clock: () => NOW });
      const second = new FileObserverStateStore({ filePath: path, leaseMs: 30_000, clock: () => NOW });
      const release = first.acquireLease();
      expect(release).toBeTypeOf("function");
      expect(second.acquireLease()).toBeUndefined();
      first.save({ version: 1, targets: {}, updatedAt: NOW.toISOString() });
      expect(statSync(path).mode & 0o077).toBe(0);
      expect(JSON.parse(readFileSync(path, "utf8"))).toMatchObject({ version: 1 });
      release?.();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("reloads suppressed delivery records from private file state", () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-suppressed-state-"));
    const path = join(directory, "state.json");
    try {
      const state = new FileObserverStateStore({ filePath: path, leaseMs: 30_000, clock: () => NOW });
      state.save({
        version: 1,
        updatedAt: NOW.toISOString(),
        targets: {
          target: {
            page: 1,
            seen: {
              "owner/repo:ci.yml:54:1": {
                outcome: "stale",
                observedAt: NOW.toISOString(),
                delivery: "suppressed",
                statusDelivery: "suppressed",
                analysisDelivery: "suppressed",
              },
            },
          },
        },
      });
      expect(state.load().targets.target?.seen["owner/repo:ci.yml:54:1"]).toMatchObject({ delivery: "suppressed" });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("signs timestamp.body and retries bounded delivery without persisting the key", async () => {
    const key = Buffer.from("hmac-key-that-is-at-least-32-bytes-long");
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response("try again", { status: 503 }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const delivery = new HermesDelivery({ url: "https://hermes.example/events", key, fetch, clock: () => NOW, sleep: vi.fn().mockResolvedValue(undefined), maxAttempts: 2, backoffMs: 10, timeoutMs: 1_000 });
    const body = JSON.stringify({ schemaVersion: "1.0", outcome: "success", runId: "1" });

    await expect(delivery.deliver(body, "event-1")).resolves.toEqual({ delivered: true, attempts: 2 });
    const timestamp = String(Math.floor(NOW.getTime() / 1_000));
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: "POST", redirect: "error", body });
    expect(fetch.mock.calls[0]?.[1]?.headers).toMatchObject({
      "X-Webhook-Timestamp": timestamp,
      "X-Webhook-Signature-V2": signHermesPayload(key, timestamp, body),
      "X-Request-ID": "event-1",
    });
    expect(fetch.mock.calls[0]?.[1]?.headers).not.toHaveProperty("X-GitHub-Event");
    expect(fetch.mock.calls[0]?.[1]?.headers).not.toHaveProperty("x-observer-timestamp");
    expect(JSON.stringify(fetch.mock.calls)).not.toContain(key.toString());
  });

  it("does not retry a bounded Hermes 429 forever", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response("quota", { status: 429 }));
    const delivery = new HermesDelivery({ url: "https://hermes.example/events", key: Buffer.from("hmac-key-that-is-at-least-32-bytes-long"), fetch, clock: () => NOW, sleep: vi.fn().mockResolvedValue(undefined), maxAttempts: 3, backoffMs: 1, timeoutMs: 1_000 });
    await expect(delivery.deliver("{}", "quota-event")).rejects.toMatchObject({ code: "unavailable" });
    expect(fetch).toHaveBeenCalledTimes(3);
  });

  it("contains model/provider quota failures as metadata warnings", async () => {
    const ci = provider({
      listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("43", "failure")], hasMore: false }),
      getFailedJobAnalysis: vi.fn().mockRejectedValue(Object.assign(new Error("model quota secret"), { code: "unavailable" })),
      getRemediationPlan: vi.fn().mockRejectedValue(Object.assign(new Error("provider quota secret"), { code: "unavailable" })),
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state: new InMemoryObserverStateStore(), deliver, clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 2 });
    expect(String(deliver.mock.calls[1]?.[0])).not.toContain("quota secret");
    expect(String(deliver.mock.calls[1]?.[0])).toContain('"code":"ci-analysis-unavailable"');
  });

  it("recovers a cursor and dedupe record after an observer restart", async () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-restart-"));
    const statePath = join(directory, "state.json");
    try {
      const firstProvider = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("42", "success")], hasMore: false }) });
      const firstDelivery = vi.fn().mockResolvedValue(undefined);
      const first = new ObserverRuntime({ config: config({ stateFile: statePath }), provider: firstProvider, state: new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }), deliver: firstDelivery, clock: () => NOW });
      await first.pollOnce();
      expect(Object.values(new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }).load().targets)[0]).toMatchObject({ page: 1, cursor: NOW.toISOString() });

      const secondProvider = provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("42", "success")], hasMore: false }) });
      const secondDelivery = vi.fn().mockResolvedValue(undefined);
      const second = new ObserverRuntime({ config: config({ stateFile: statePath }), provider: secondProvider, state: new FileObserverStateStore({ filePath: statePath, leaseMs: 30_000, clock: () => NOW }), deliver: secondDelivery, clock: () => NOW });
      await second.pollOnce();

      expect(secondProvider.listWorkflowRuns).toHaveBeenNthCalledWith(1, expect.objectContaining({ page: 1 }));
      expect(secondProvider.listWorkflowRuns).toHaveBeenNthCalledWith(2, expect.objectContaining({ page: 1, createdAfter: expect.any(String) }));
      expect(secondDelivery).not.toHaveBeenCalled();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("continues a truncated page window from durable next-page state", async () => {
    const state = new InMemoryObserverStateStore();
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockResolvedValueOnce({ runs: [run("1", "success")], hasMore: false })
        .mockResolvedValueOnce({ runs: [run("1", "success")], hasMore: true, nextPage: 2 })
        .mockResolvedValueOnce({ runs: [run("2", "success")], hasMore: false })
        .mockResolvedValueOnce({ runs: [run("3", "success")], hasMore: false }),
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({ config: config({ maxPages: 1 }), provider: ci, state, deliver, clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ truncatedTargets: 1, delivered: 0 });
    expect(Object.values(state.load().targets)[0]).toMatchObject({ page: 2 });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ truncatedTargets: 0, delivered: 0 });
    expect(ci.listWorkflowRuns).toHaveBeenNthCalledWith(1, expect.objectContaining({ page: 1 }));
    expect(vi.mocked(ci.listWorkflowRuns).mock.calls[0]?.[0]).not.toHaveProperty("createdAfter");
    expect(ci.listWorkflowRuns).toHaveBeenNthCalledWith(2, expect.objectContaining({ page: 1, createdAfter: "2026-07-12T23:55:00.000Z" }));
    expect(ci.listWorkflowRuns).toHaveBeenNthCalledWith(3, expect.objectContaining({ page: 1 }));
    expect(vi.mocked(ci.listWorkflowRuns).mock.calls[2]?.[0]).not.toHaveProperty("createdAfter");
    expect(ci.listWorkflowRuns).toHaveBeenNthCalledWith(4, expect.objectContaining({ page: 2, createdAfter: "2026-07-12T23:55:00.000Z" }));
    expect(deliver).toHaveBeenCalledTimes(0);
  });

  it("keeps one createdAfter filter across all durable backlog pages", async () => {
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockResolvedValueOnce({ runs: [run("10", "success")], hasMore: false })
        .mockResolvedValueOnce({ runs: [run("10", "success")], hasMore: true, nextPage: 2 })
        .mockResolvedValueOnce({ runs: [run("11", "success")], hasMore: false }),
    });
    const runtime = new ObserverRuntime({ config: config({ maxPages: 2 }), provider: ci, state: new InMemoryObserverStateStore(), deliver: vi.fn().mockResolvedValue(undefined), clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, truncatedTargets: 0 });
    const calls = vi.mocked(ci.listWorkflowRuns).mock.calls;
    const firstBacklog = calls[1]?.[0];
    const secondBacklog = calls[2]?.[0];
    expect(firstBacklog).toMatchObject({ page: 1, createdAfter: "2026-07-12T23:55:00.000Z" });
    expect(secondBacklog).toMatchObject({ page: 2, createdAfter: firstBacklog?.createdAfter });
  });

  it.each(["unavailable", "rate_limited"] as const)("persists bounded %s polling backoff across polls", async (code) => {
    let now = NOW;
    const state = new InMemoryObserverStateStore();
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockRejectedValueOnce(Object.assign(new Error("provider secret"), { code }))
        .mockResolvedValue({ runs: [], hasMore: false }),
    });
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state, deliver: vi.fn(), clock: () => now });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ errors: [{ outcome: "unavailable" }] });
    expect(Object.values(state.load().targets)[0]).toMatchObject({ backoffMs: 5_000, backoffUntil: "2026-07-14T00:00:05.000Z" });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ errors: [{ outcome: "unavailable" }] });
    expect(ci.listWorkflowRuns).toHaveBeenCalledTimes(1);

    now = new Date("2026-07-14T00:00:05.000Z");
    await expect(runtime.pollOnce()).resolves.toMatchObject({ errors: [], delivered: 0 });
    expect(ci.listWorkflowRuns).toHaveBeenCalledTimes(3);
    expect(Object.values(state.load().targets)[0]).not.toHaveProperty("backoffUntil");
  });

  it("degrades current health when the bounded terminal window is truncated and recovers on a clean poll", async () => {
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockResolvedValueOnce({ runs: [run("1", "success")], hasMore: false })
        .mockResolvedValueOnce({ runs: [], hasMore: true, nextPage: 2 })
        .mockResolvedValueOnce({ runs: [], hasMore: true, nextPage: 3 })
        .mockResolvedValueOnce({ runs: [], hasMore: false })
        .mockResolvedValueOnce({ runs: [run("1", "success")], hasMore: false }),
    });
    const runtime = new ObserverRuntime({ config: config({ maxPages: 2 }), provider: ci, state: new InMemoryObserverStateStore(), deliver: vi.fn().mockResolvedValue(undefined), clock: () => NOW });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ truncatedTargets: 1 });
    expect(runtime.health()).toMatchObject({ status: "degraded", metrics: { truncatedTargets: 1 } });
    await expect(runtime.pollOnce()).resolves.toMatchObject({ truncatedTargets: 0 });
    expect(runtime.health()).toMatchObject({ status: "ok", metrics: { truncatedTargets: 0 } });
  });

  it("recovers current health after a transient provider failure", async () => {
    let now = NOW;
    const ci = provider({
      listWorkflowRuns: vi.fn()
        .mockRejectedValueOnce(Object.assign(new Error("transient"), { code: "unavailable" }))
        .mockResolvedValue({ runs: [], hasMore: false }),
    });
    const runtime = new ObserverRuntime({ config: config(), provider: ci, state: new InMemoryObserverStateStore(), deliver: vi.fn(), clock: () => now });

    await runtime.pollOnce();
    expect(runtime.health()).toMatchObject({ status: "degraded", metrics: { lastError: "unavailable" } });
    now = new Date("2026-07-14T00:00:05.000Z");
    await runtime.pollOnce();
    expect(runtime.health()).toMatchObject({ status: "ok" });
    expect(runtime.health().metrics).not.toHaveProperty("lastError");
  });

  it("emits deterministic status before one bounded adversarial recommendation", async () => {
    const callback = vi.fn().mockResolvedValue({
      title: "inspect failure",
      rationale: "bounded evidence only",
      steps: ["read the runbook"],
      evidenceRefs: ["ci-status"],
      status: "success",
      deploy: true,
      rollback: true,
      rerun: true,
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({
      config: config(),
      provider: provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("goal23", "failure")], hasMore: false }) }),
      state: new InMemoryObserverStateStore(),
      deliver,
      recommendationAnalysis: callback,
      clock: () => NOW,
    });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 2 });
    expect(callback).toHaveBeenCalledTimes(1);
    expect(deliver.mock.calls[0]?.[2]).toBe("success");
    expect(JSON.parse(String(deliver.mock.calls[0]?.[0]))).toMatchObject({ status: { outcome: "failure" }, outcome: "failure" });
    const analysis = JSON.parse(String(deliver.mock.calls[1]?.[0])) as Record<string, unknown>;
    expect(analysis).toHaveProperty("recommendation.available", true);
    expect(analysis).not.toHaveProperty("deploy");
    expect(analysis).not.toHaveProperty("rollback");
    expect(analysis).not.toHaveProperty("rerun");
  });

  it("maps bounded diff, log, metric, and trace evidence into callback metadata", async () => {
    const callback = vi.fn().mockImplementation(async (input) => {
      expect(input.diff).toEqual([{ path: "src/check.ts", changeType: "modified", additions: 2, deletions: 1, hunkCount: 1 }]);
      expect(input.logs).toEqual([{ sequence: 0, text: "CI log evidence ci-log-9 (1 lines)" }]);
      expect(input.metrics).toEqual([{ name: "http-errors", state: "error", sampleCount: 0 }]);
      expect(input.traces).toEqual([{ spanDigest: createHash("sha256").update("span-9").digest("hex"), durationMs: 0, status: "error" }]);
      return { title: "inspect bounded evidence", steps: [], evidenceRefs: ["ci-log-9"] };
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({
      config: config(),
      provider: provider({
        listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("goal23-evidence", "failure")], hasMore: false }),
        forensics: {
          scm: { getChangeEvidence: vi.fn().mockResolvedValue({ schemaVersion: "1.0", observedAt: NOW.toISOString(), providerClass: "scm", freshness: "fresh", truncated: false, redactionsApplied: false, warnings: [], data: { available: true, changes: [{ path: "src/check.ts", changeType: "modified", additions: 2, deletions: 1, hunks: [{ header: "@@", lines: ["+check"] }] }] } }) },
          telemetry: { getTelemetryCorrelation: vi.fn().mockResolvedValue({ schemaVersion: "1.0", observedAt: NOW.toISOString(), providerClass: "telemetry", freshness: "fresh", truncated: false, redactionsApplied: false, warnings: [], data: { available: true, signals: [{ id: "http-errors", kind: "metric", state: "error", summary: "errors", observedAt: NOW.toISOString() }, { id: "trace-9", kind: "trace", state: "error", summary: "failed span", reference: "span-9", observedAt: NOW.toISOString() }] } }) },
        },
      }),
      state: new InMemoryObserverStateStore(),
      deliver,
      recommendationAnalysis: callback,
      clock: () => NOW,
    });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 2 });
    expect(callback).toHaveBeenCalledTimes(1);
  });

  it("contains recommendation timeout without changing failure status or state", async () => {
    const callback = vi.fn().mockImplementation(async (_input, context) => new Promise((_resolve, reject) => {
      context.signal.addEventListener("abort", () => reject(new Error("timeout")), { once: true });
    }));
    const deliver = vi.fn().mockResolvedValue(undefined);
    const runtime = new ObserverRuntime({
      config: config(),
      provider: provider({ listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("goal23-timeout", "failure")], hasMore: false }) }),
      state: new InMemoryObserverStateStore(),
      deliver,
      recommendationAnalysis: callback,
      recommendationLimits: { timeoutMs: 250 },
      clock: () => NOW,
    });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 2, errors: [] });
    expect(callback).toHaveBeenCalledTimes(1);
    expect(JSON.parse(String(deliver.mock.calls[0]?.[0]))).toMatchObject({ outcome: "failure", status: { outcome: "failure" } });
    expect(JSON.parse(String(deliver.mock.calls[1]?.[0]))).toHaveProperty("recommendation.reason", "timeout");
  });

  it("bounds a hung forensics provider after delivering status and one unavailable analysis", async () => {
    const callback = vi.fn();
    const deliver = vi.fn().mockResolvedValue(undefined);
    const ci = provider({
      listWorkflowRuns: vi.fn().mockResolvedValue({ runs: [run("goal23-hung-provider", "failure")], hasMore: false }),
      getFailedJobAnalysis: (() => new Promise<never>(() => {})) as NonNullable<ObserverProvider["getFailedJobAnalysis"]>,
    });
    const runtime = new ObserverRuntime({
      config: config(),
      provider: ci,
      state: new InMemoryObserverStateStore(),
      deliver,
      recommendationAnalysis: callback,
      recommendationLimits: { timeoutMs: 20 },
      clock: () => NOW,
    });

    const startedAt = Date.now();
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 2, errors: [] });
    expect(Date.now() - startedAt).toBeLessThan(1_000);
    expect(deliver.mock.calls.map((call) => call[2])).toEqual(["success", "analysis"]);
    const analysis = JSON.parse(String(deliver.mock.calls[1]?.[0])) as Record<string, unknown>;
    expect(analysis).toHaveProperty("analysis.freshness", "unknown");
    expect(analysis).toHaveProperty("analysis.data.provenance[0].unavailable", true);
    expect(callback).not.toHaveBeenCalled();
  });

  it("keeps transition, dedupe, status, and delivery routing deterministic despite adversarial output", async () => {
    let currentRun = run("goal23-failure", "failure");
    const source = { listTerminalRuns: vi.fn().mockImplementation(async () => ({ runs: [currentRun], hasMore: false })) };
    const rerunFailedWorkflow = vi.fn<ObserverProvider["rerunFailedWorkflow"]>();
    const callback = vi.fn().mockResolvedValue({
      title: "inspect failure",
      rationale: "bounded evidence only",
      steps: ["read the runbook"],
      evidenceRefs: ["ci-status"],
      status: "success",
      transition: "recovery",
      dedupeKey: "attacker-controlled",
      route: "success",
      deploy: true,
      rollback: true,
      rerun: { invoke: () => undefined },
    });
    const deliver = vi.fn().mockResolvedValue(undefined);
    const state = new InMemoryObserverStateStore();
    const runtime = new ObserverRuntime({
      config: config({ maxPages: 1 }),
      provider: provider({ rerunFailedWorkflow }),
      source,
      state,
      deliver,
      recommendationAnalysis: callback,
      clock: () => NOW,
    });

    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 2, observed: [{ outcome: "failure" }] });
    currentRun = run("goal23-failure", "failure");
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 0, observed: [] });
    currentRun = run("goal23-recovery", "success");
    await expect(runtime.pollOnce()).resolves.toMatchObject({ delivered: 1, observed: [{ outcome: "success" }] });

    expect(callback).toHaveBeenCalledTimes(1);
    expect(rerunFailedWorkflow).not.toHaveBeenCalled();
    expect(deliver.mock.calls.map((call) => call[2])).toEqual(["success", "analysis", "success"]);

    const status = JSON.parse(String(deliver.mock.calls[0]?.[0])) as Record<string, unknown>;
    expect(status).toMatchObject({
      eventId: `owner/repo:ci.yml:${SHA}:failure`,
      dedupeKey: `owner/repo:ci.yml:${SHA}:failure`,
      outcome: "failure",
      notification: "failure",
      severity: "red",
      status: { state: "completed", conclusion: "failure", outcome: "failure" },
    });
    expect(status).not.toHaveProperty("deploy");
    expect(status).not.toHaveProperty("rollback");
    expect(status).not.toHaveProperty("rerun");

    const analysis = JSON.parse(String(deliver.mock.calls[1]?.[0])) as Record<string, unknown>;
    expect(analysis).toMatchObject({
      type: "ci.failure.analysis",
      eventId: `owner/repo:ci.yml:${SHA}:failure`,
      dedupeKey: `owner/repo:ci.yml:${SHA}:failure`,
      recommendation: { available: true, reason: "available" },
    });
    expect(analysis).not.toHaveProperty("status");
    expect(analysis).not.toHaveProperty("transition");
    expect(analysis).not.toHaveProperty("route");
    expect(analysis).not.toHaveProperty("deploy");
    expect(analysis).not.toHaveProperty("rollback");
    expect(analysis).not.toHaveProperty("rerun");
    expect(analysis.recommendation).toEqual({
      available: true,
      reason: "available",
      recommendation: {
        title: "inspect failure",
        rationale: "bounded evidence only",
        steps: ["read the runbook"],
        evidenceRefs: ["ci-status"],
      },
    });

    const recovery = JSON.parse(String(deliver.mock.calls[2]?.[0])) as Record<string, unknown>;
    expect(recovery).toMatchObject({
      eventId: `owner/repo:ci.yml:${SHA}:success`,
      dedupeKey: `owner/repo:ci.yml:${SHA}:success`,
      outcome: "success",
      notification: "recovery",
      severity: "green",
      status: { state: "completed", conclusion: "success", outcome: "success" },
    });

    const targetState = Object.values(state.load().targets)[0];
    expect(targetState?.incidentActive).toBe(false);
    expect(targetState?.seen[`owner/repo:ci.yml:${SHA}:failure`]).toMatchObject({
      statusDelivery: "delivered",
      analysisAttempted: true,
      analysisDelivery: "delivered",
    });
  });
});
