import { BitbucketProvider } from "../src/providers/bitbucket-provider.js";
import { GitHubActionsProvider } from "../src/providers/github-actions-provider.js";
import { JenkinsProvider } from "../src/providers/jenkins-provider.js";
import { describe, expect, it, vi } from "vitest";

import {
  APPROVAL_GATED_CI_PROVIDER_CAPABILITIES,
  CIProviderClassSchema,
  CIProviderConfigSchema,
  CIProviderRegistryConfigSchema,
  READ_ONLY_CI_PROVIDER_CAPABILITIES,
  resolveCIProviderUrl,
} from "../src/ci/index.js";
import { CIProviderRegistry } from "../src/providers/ci-provider-registry.js";
import type { CIReadProvider, CIRerunProvider } from "../src/providers/ci-provider.js";

const readProvider = (): CIReadProvider => ({
  getWorkflowStatus: vi.fn(),
  getFailedJobAnalysis: vi.fn(),
  getLogEvidence: vi.fn(),
  getRemediationPlan: vi.fn(),
});

describe("provider-neutral CI contracts", () => {
  it("uses provider-owned workflow identity matching", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const jenkins = new JenkinsProvider({ baseUrl: "https://jenkins.example", fetch });
    const github = new GitHubActionsProvider({ token: "github-token-long-enough", fetch });
    const bitbucket = new BitbucketProvider({ baseUrl: "https://bitbucket.example/2.0", token: "reader:token", fetch });

    expect(jenkins.matchesWorkflow("planpalasix-config", "planpalasix-config/main")).toBe(true);
    expect(jenkins.matchesWorkflow("planpalasix-config", "planpalasix-config/PR-9")).toBe(true);
    expect(jenkins.matchesWorkflow("planpalasix-config", "other-folder/main")).toBe(false);
    expect(github.matchesWorkflow("ci.yml", "ci.yml/x")).toBe(false);
    expect(bitbucket.matchesWorkflow("build", "build/x")).toBe(false);
  });
  it("uses one canonical provider-name schema for wire and registry identities", () => {
    expect(CIProviderClassSchema.safeParse("teamcity-primary").success).toBe(true);
    expect(CIProviderClassSchema.safeParse("TeamCity-primary").success).toBe(false);
    expect(CIProviderClassSchema.safeParse("teamcity_primary").success).toBe(false);
    expect(CIProviderClassSchema.safeParse("teamcity.primary").success).toBe(false);
  });

  it("validates provider-specific capability declarations", () => {
    const endpoint = { origin: "https://ci.example", path: "/api" };
    expect(
      CIProviderConfigSchema.safeParse({
        kind: "github-actions",
        endpoint,
        capabilities: APPROVAL_GATED_CI_PROVIDER_CAPABILITIES,
      }).success,
    ).toBe(true);
    expect(
      CIProviderConfigSchema.safeParse({
        kind: "jenkins",
        endpoint,
        capabilities: { read: true, rerun: "approval-gated" },
      }).success,
    ).toBe(false);
    expect(
      CIProviderConfigSchema.safeParse({
        kind: "bitbucket",
        endpoint,
        capabilities: READ_ONLY_CI_PROVIDER_CAPABILITIES,
        token_file: "/run/secrets/bitbucket-token",
      }).success,
    ).toBe(true);
    expect(
      CIProviderConfigSchema.safeParse({
        kind: "bitbucket",
        endpoint: { origin: "http://127.0.0.1:7990", path: "/2.0" },
        capabilities: READ_ONLY_CI_PROVIDER_CAPABILITIES,
        token_file: "/run/secrets/bitbucket-token",
      }).success,
    ).toBe(false);
  });

  it("accepts multiple named providers with independent configs", () => {
    const parsed = CIProviderRegistryConfigSchema.parse({
      "github-primary": {
        kind: "github-actions",
        endpoint: { origin: "https://api.github.com", path: "/" },
        capabilities: APPROVAL_GATED_CI_PROVIDER_CAPABILITIES,
      },
      "jenkins-readonly": {
        kind: "jenkins",
        endpoint: { origin: "https://jenkins.example", path: "/job" },
        capabilities: READ_ONLY_CI_PROVIDER_CAPABILITIES,
      },
    });

    expect(Object.keys(parsed)).toEqual(["github-primary", "jenkins-readonly"]);
  });

  it("fails closed for unknown and unsupported capabilities", () => {
    const registry = new CIProviderRegistry([
      {
        name: "jenkins-readonly",
        kind: "jenkins",
        capabilities: READ_ONLY_CI_PROVIDER_CAPABILITIES,
        provider: readProvider(),
      },
    ]);

    expect(registry.supports("jenkins-readonly", "read")).toBe(true);
    expect(registry.supports("jenkins-readonly", "rerun")).toBe(false);
    expect(() => registry.requireRerun("jenkins-readonly")).toThrowError(
      expect.objectContaining({ code: "unsupported", providerName: "jenkins-readonly", capability: "rerun" }),
    );
    expect(() => registry.requireRead("missing-provider")).toThrowError(
      expect.objectContaining({ code: "unsupported", providerName: "missing-provider", capability: "read" }),
    );
  });

  it("rejects duplicate names and rerun declarations without a rerun port", () => {
    expect(
      () => new CIProviderRegistry([
        { name: "ci", kind: "one", capabilities: READ_ONLY_CI_PROVIDER_CAPABILITIES, provider: readProvider() },
        { name: "ci", kind: "two", capabilities: READ_ONLY_CI_PROVIDER_CAPABILITIES, provider: readProvider() },
      ]),
    ).toThrow("Duplicate CI provider name");

    expect(
      () => new CIProviderRegistry([{
        name: "github-primary",
        kind: "github-actions",
        capabilities: APPROVAL_GATED_CI_PROVIDER_CAPABILITIES,
        provider: readProvider(),
      }]),
    ).toThrow("declares rerun without a rerun port");

    expect(
      () => new CIProviderRegistry([{
        name: "malformed-read",
        kind: "jenkins",
        capabilities: READ_ONLY_CI_PROVIDER_CAPABILITIES,
        provider: {
          getWorkflowStatus: vi.fn(),
          getFailedJobAnalysis: vi.fn(),
          getLogEvidence: vi.fn(),
        } as unknown as CIReadProvider,
      }]),
    ).toThrow("declares read without port getRemediationPlan");
  });

  it("routes declared read and approval-gated rerun ports", async () => {
    const rerun = vi.fn<CIRerunProvider["rerunFailedWorkflow"]>(async () => ({
      schemaVersion: "1.0",
      observedAt: "2026-07-10T00:00:00.000Z",
      providerClass: "github-actions",
      freshness: "fresh",
      truncated: false,
      redactionsApplied: false,
      warnings: [],
      data: { runId: "42", requestId: "operator-approved", accepted: true, action: "rerun-failed-jobs" },
    }));
    const provider = { ...readProvider(), rerunFailedWorkflow: rerun };
    const registry = new CIProviderRegistry([{
      name: "github-primary",
      kind: "github-actions",
      capabilities: APPROVAL_GATED_CI_PROVIDER_CAPABILITIES,
      provider,
    }]);

    await expect(registry.invokeRead("github-primary", async (value) => value)).resolves.toBe(provider);
    await expect(registry.invokeRerun("github-primary", (value) => value.rerunFailedWorkflow({
      repo: "owner/repo",
      workflow: "ci.yml",
      runId: "42",
      runAttempt: 1,
      headSha: "a".repeat(40),
    }))).resolves.toMatchObject({ data: { accepted: true, action: "rerun-failed-jobs" } });
    expect(rerun).toHaveBeenCalledTimes(1);
  });

  it("resolves endpoint paths without duplicating complete URLs", () => {
    const endpoint = { origin: "https://jenkins.example/", path: "/job/api/" };

    expect(resolveCIProviderUrl(endpoint, "42").toString()).toBe("https://jenkins.example/job/api/42");
    expect(resolveCIProviderUrl(endpoint, "/job/api/42?tree=full").toString()).toBe(
      "https://jenkins.example/job/api/42?tree=full",
    );
    expect(resolveCIProviderUrl(endpoint, "https://jenkins.example/job/api/42").toString()).toBe(
      "https://jenkins.example/job/api/42",
    );
    expect(() => resolveCIProviderUrl(endpoint, "https://other.example/job/api/42")).toThrow("origin");
  });
});
