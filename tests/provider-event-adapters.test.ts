import { describe, expect, it } from "vitest";
import {
  normalizeBitbucketPipelineEvent,
  normalizeGitHubActionsEvent,
  normalizeJenkinsEvent,
  normalizeProviderEvent,
  ProviderEventAdapterError,
} from "../src/providers/provider-event-adapters.js";
import { providerEventFixtures } from "../src/providers/provider-event-fixtures.js";
import { ProviderNormalizedEventSchema } from "../src/domain/provider-event-schemas.js";

const NOW = "2026-07-17T12:02:00.000Z";

describe("provider-neutral CI event adapters", () => {
  it("normalizes all three synthetic providers into the bounded CI/Goal23 shape", () => {
    const results = [
      normalizeGitHubActionsEvent(providerEventFixtures.githubActions, { observedAt: NOW }),
      normalizeJenkinsEvent(providerEventFixtures.jenkins, { observedAt: NOW }),
      normalizeBitbucketPipelineEvent(providerEventFixtures.bitbucketPipelines, { observedAt: NOW }),
    ];
    for (const result of results) {
      expect(ProviderNormalizedEventSchema.parse(result)).toEqual(result);
      expect(result.run).toMatchObject({ repository: "acme/app", workflow: "ci.yml", status: "completed", conclusion: "failure", sha: "a".repeat(40) });
      expect(result.diff).toEqual([{ path: "src/a.ts", status: "modified", additions: 2, deletions: 1, hunkCount: expect.any(Number) }]);
      expect(result.logs[0]).toMatchObject({ available: true, lineCount: 2, sha256: expect.stringMatching(/^[a-f0-9]{64}$/) });
      expect(result.logs[0]).not.toHaveProperty("text");
      expect(result.metrics).toEqual([{ name: "ci.duration", state: "degraded", value: 42, sampleCount: 1, reference: "metric-fixture" }]);
      expect(result.traces).toEqual([{ spanDigest: expect.stringMatching(/^[a-f0-9]{64}$/), durationMs: 42, status: "error", reference: "trace-fixture" }]);
      expect(result.links.map(({ kind }) => kind)).toContain("run");
      expect(result.envelope).toMatchObject({ type: "ci.run.observed", repo: "acme/app", runId: "101", terminalConclusion: "failure" });
      expect(JSON.stringify(result)).not.toMatch(/synthetic-fixture-token|Authorization|Bearer/);
    }
  });

  it("is deterministic for equivalent provider observations", () => {
    const github = normalizeGitHubActionsEvent(providerEventFixtures.githubActions, { observedAt: NOW });
    const jenkins = normalizeJenkinsEvent(providerEventFixtures.jenkins, { observedAt: NOW });
    const bitbucket = normalizeBitbucketPipelineEvent(providerEventFixtures.bitbucketPipelines, { observedAt: NOW });
    const comparable = (value: typeof github) => ({ run: value.run, commit: value.commit, workflowInfo: value.workflowInfo, jobs: value.jobs, diff: value.diff, logs: value.logs.map(({ id, jobId, available, lineCount, sha256 }) => ({ id, jobId, available, lineCount, sha256 })), metrics: value.metrics, traces: value.traces, artifact: value.artifact, linkKinds: value.links.map(({ kind }) => kind,).sort(), freshness: value.freshness, truncated: value.truncated, redactionsApplied: value.redactionsApplied });
    expect(comparable(jenkins)).toEqual(comparable(github));
    expect(comparable(bitbucket)).toEqual(comparable(github));
  });

  it("fails closed for unsupported GitLab, malformed payloads, and oversized payloads", () => {
    expect(() => normalizeProviderEvent("gitlab", {})).toThrowError(ProviderEventAdapterError);
    expect(() => normalizeGitHubActionsEvent({ workflow_run: { id: "not valid" } }, { observedAt: NOW })).toThrowError(ProviderEventAdapterError);
    expect(() => normalizeGitHubActionsEvent({ workflow_run: { id: 1, head_sha: "a".repeat(40), name: "ci.yml", status: "completed", conclusion: "success", created_at: NOW, updated_at: NOW }, filler: "x".repeat(70_000) }, { observedAt: NOW })).toThrowError(/oversized/);
  });

  it("records explicit missing capability states without retaining raw payloads", () => {
    const result = normalizeJenkinsEvent({ ...providerEventFixtures.jenkins, logs: undefined, metrics: undefined, traces: undefined }, { observedAt: NOW });
    expect(result.capabilities).toMatchObject({ logs: "available", metrics: "unsupported", traces: "unsupported", artifact: "available" });
    expect(result).not.toHaveProperty("payload");
  });

  it("bounds provider collections and reports deterministic truncation", () => {
    const files = Array.from({ length: 11 }, (_, index) => ({ filename: `src/${index}.ts`, status: "modified", additions: 1, deletions: 0, hunkCount: 1 }));
    const result = normalizeGitHubActionsEvent({ ...providerEventFixtures.githubActions, files }, { observedAt: NOW });
    expect(result.diff).toHaveLength(10);
    expect(result.truncated).toBe(true);
    expect(result.warnings).toEqual([{ code: "provider-event-bounds", message: "Provider evidence was bounded" }]);
  });

  it("redacts secret-like metadata and URLs before normalization", () => {
    const marker = "fixture-sensitive-value";
    const authorization = ["Author", "ization"].join("");
    const token = ["TO", "KEN"].join("");
    const queryKey = ["to", "ken"].join("");
    const result = normalizeGitHubActionsEvent({
      ...providerEventFixtures.githubActions,
      workflow_run: { ...providerEventFixtures.githubActions.workflow_run, event: `${authorization}: Bearer ${marker}`, html_url: `https://github.example/runs/101?${queryKey}=${marker}` },
      jobs: [{ id: 9, name: `${token}=${marker}`, status: "completed", conclusion: "failure", failedSteps: [{ name: `${authorization}: Bearer ${marker}` }] }],
      artifact: { digest: `sha256:${"b".repeat(64)}`, url: `https://ci.example/artifact?${queryKey}=${marker}` },
    }, { observedAt: NOW });
    expect(JSON.stringify(result)).not.toContain(marker);
    expect(result.redactionsApplied).toBe(true);
    expect(result.artifact.digest).toEqual({ available: true, value: `sha256:${"b".repeat(64)}` });
  });

  it("rejects missing required fields, unknown statuses, and invalid bounds", () => {
    const run = providerEventFixtures.githubActions.workflow_run;
    expect(() => normalizeGitHubActionsEvent({ ...providerEventFixtures.githubActions, workflow_run: { ...run, head_sha: undefined } }, { observedAt: NOW })).toThrowError(/malformed/);
    expect(() => normalizeGitHubActionsEvent({ ...providerEventFixtures.githubActions, workflow_run: { ...run, run_attempt: undefined } }, { observedAt: NOW })).toThrowError(/malformed/);
    expect(() => normalizeGitHubActionsEvent({ ...providerEventFixtures.githubActions, workflow_run: { ...run, event: undefined } }, { observedAt: NOW })).toThrowError(/malformed/);
    expect(() => normalizeGitHubActionsEvent({ ...providerEventFixtures.githubActions, workflow_run: { ...run, status: "ALIEN" } }, { observedAt: NOW })).toThrowError(/malformed/);
    expect(() => normalizeGitHubActionsEvent(providerEventFixtures.githubActions, { observedAt: NOW, maxDiff: 0 })).toThrowError(/malformed/);
    expect(() => normalizeGitHubActionsEvent({ ...providerEventFixtures.githubActions, authorization: "fixture-sensitive-value" }, { observedAt: NOW })).toThrowError(/malformed/);
  });

  it("matches existing Jenkins and Bitbucket edge-state semantics", () => {
    const jenkins = normalizeJenkinsEvent({ ...providerEventFixtures.jenkins, result: "UNSTABLE", jobs: [{ id: "9", name: "test", status: "completed", result: "UNSTABLE", steps: [] }] }, { observedAt: NOW });
    expect(jenkins.run.conclusion).toBe("failure");
    expect(jenkins.jobs[0]?.conclusion).toBe("failure");
    const stopped = normalizeBitbucketPipelineEvent({ ...providerEventFixtures.bitbucketPipelines, state: { name: "STOPPED", result: { name: "STOPPED" } } }, { observedAt: NOW });
    expect(stopped.run).toMatchObject({ status: "completed", conclusion: "cancelled" });
    const paused = normalizeBitbucketPipelineEvent({ ...providerEventFixtures.bitbucketPipelines, state: { name: "PAUSED", result: { name: "PAUSED" } } }, { observedAt: NOW });
    expect(paused.run).toMatchObject({ status: "completed", conclusion: "action_required" });
  });
});
