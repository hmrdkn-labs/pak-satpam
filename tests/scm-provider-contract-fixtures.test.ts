import { describe, expect, it, vi } from "vitest";
import { BitbucketSCMProvider, GitHubSCMProvider, JenkinsSCMProvider, SCMSelectorSchema } from "../src/scm/index.js";

const NOW = new Date("2026-07-15T00:00:00.000Z");
const BASE = "a".repeat(40);
const HEAD = "b".repeat(40);
const budget = { maxBytes: 8_000, maxFiles: 10, maxHunks: 10, maxLines: 100, maxProviderRequests: 4, maxDurationMs: 5_000 };

function assertReadOnlyRequests(fetch: ReturnType<typeof vi.fn>): void {
  for (const [url, init] of fetch.mock.calls) {
    expect(init?.method ?? "GET").toBe("GET");
    expect(String(url)).not.toMatch(/checkout|clone|archive|contents|search|raw/i);
  }
}

describe("SCM normalized provider fixtures", () => {
  it("accepts one provider-neutral selector shape including compare ranges", () => {
    expect(SCMSelectorSchema.parse({ repository: "acme/app", compare: { base: "main", head: "feature" } })).toEqual({ repository: "acme/app", compare: { base: "main", head: "feature" } });
  });

  it("normalizes a GitHub compare range without widening the selector", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ repository: { full_name: "acme/app" }, base_commit: { sha: BASE }, head_commit: { sha: HEAD }, files: [{ filename: "src/a.ts", status: "modified", additions: 1, deletions: 0, patch: "@@ -1 +1 @@\n-a\n+b" }] })));
    const result = await new GitHubSCMProvider({ token: "reader-token", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main", "feature"] }).getChangeEvidence({ repository: "acme/app", compare: { base: "main", head: "feature" }, budget });
    expect(result.data.selector).toEqual({ compare: { base: "main", head: "feature" } });
    expect(result.data.base).toEqual({ ref: "main", sha: BASE });
    expect(result.data.head).toEqual({ ref: "feature", sha: HEAD });
    expect(String(fetch.mock.calls[0]?.[0])).toContain("/compare/main...");
  });

  it("GitHub controlled success is normalized and bounded", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ number: 7, state: "open", title: "safe", base: { ref: "main", sha: BASE, repo: { full_name: "acme/app" } }, head: { ref: "feature", sha: HEAD, repo: { full_name: "acme/app" } } })))
      .mockResolvedValueOnce(new Response(JSON.stringify([{ filename: "src/a.ts", status: "modified", additions: 1, deletions: 1, patch: "@@ -1 +1 @@\n-safe\n+safe" }])));
    const result = await new GitHubSCMProvider({ token: "reader-token", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main", "feature"] })
      .getChangeEvidence({ repository: "acme/app", pullRequest: "7", commit: HEAD, budget });

    expect(result.providerClass).toBe("github");
    expect(result.data.head.sha).toBe(HEAD);
    expect(result.digest).toBe(result.digest);
    expect(result.budget.usedProviderRequests).toBe(2);
    expect(result.truncation).toEqual({ files: false, hunks: false, lines: false, bytes: false, providerRequests: false, timeWindow: false });
    assertReadOnlyRequests(fetch);
  });

  it("GitHub controlled failure rejects a requested PR commit mismatch", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ number: 7, base: { ref: "main", sha: BASE, repo: { full_name: "acme/app" } }, head: { ref: "feature", sha: "c".repeat(40), repo: { full_name: "acme/app" } } })));
    const provider = new GitHubSCMProvider({ token: "reader-token", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main", "feature"] });
    await expect(provider.getChangeEvidence({ repository: "acme/app", pullRequest: "7", commit: HEAD, budget })).rejects.toMatchObject({ code: "permission" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("Jenkins controlled success is normalized without checkout or diff access", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ number: 7, timestamp: NOW.getTime(), branchName: "feature", actions: [{ lastBuiltRevision: { SHA1: HEAD } }], scm: { userRemoteConfigs: [{ url: "https://github.com/acme/app.git" }] }, changeSets: [{ items: [{ paths: [{ editType: "edit", file: "src/a.ts" }] }] }] })));
    const result = await new JenkinsSCMProvider({ baseUrl: "https://jenkins.example/reverse-proxy", job: "ci", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["feature"] })
      .getChangeEvidence({ repository: "acme/app", ref: "feature", commit: HEAD, budget });

    expect(result.providerClass).toBe("jenkins");
    expect(result.data.files[0]).toMatchObject({ path: "src/a.ts", status: "modified" });
    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://jenkins.example/reverse-proxy/job/ci/job/feature/lastBuild/api/json");
    assertReadOnlyRequests(fetch);
  });

  it("Jenkins controlled failure rejects an out-of-policy reported ref", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ number: 7, branchName: "main", actions: [{ lastBuiltRevision: { SHA1: HEAD } }], scm: { userRemoteConfigs: [{ url: "https://github.com/acme/app.git" }] } })));
    const provider = new JenkinsSCMProvider({ baseUrl: "https://jenkins.example", job: "ci", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main", "feature"] });
    await expect(provider.getChangeEvidence({ repository: "acme/app", ref: "feature", budget })).rejects.toMatchObject({ code: "permission" });
  });

  it("Bitbucket Cloud controlled success is normalized with bounded diff access", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 7, title: "safe", state: "OPEN", destination: { branch: { name: "main" }, commit: { hash: BASE } }, source: { branch: { name: "feature" }, commit: { hash: HEAD } }, repository: { full_name: "acme/app" } })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ values: [{ status: { type: "modified" }, lines_added: 1, lines_removed: 1, old: { path: "src/a.ts" }, new: { path: "src/a.ts" } }] })))
      .mockResolvedValueOnce(new Response("diff --git a/src/a.ts b/src/a.ts\n@@ -1 +1 @@\n-safe\n+safe\n"));
    const result = await new BitbucketSCMProvider({ baseUrl: "https://bitbucket.example/2.0", token: "reader-token", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main", "feature"] })
      .getChangeEvidence({ repository: "acme/app", pullRequest: "7", commit: HEAD, budget });

    expect(result.providerClass).toBe("bitbucket-cloud");
    expect(result.data.head.sha).toBe(HEAD);
    expect(result.budget.usedProviderRequests).toBe(3);
    expect(String(fetch.mock.calls[1]?.[0])).toBe("https://bitbucket.example/2.0/repositories/acme/app/pullrequests/7/diffstat?pagelen=10");
    assertReadOnlyRequests(fetch);
  });

  it("Bitbucket Cloud controlled failure rejects a wrong repository response", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ id: 7, repository: { full_name: "other/app" } })));
    const provider = new BitbucketSCMProvider({ baseUrl: "https://bitbucket.example/2.0", token: "reader-token", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main"] });
    await expect(provider.getChangeEvidence({ repository: "acme/app", pullRequest: "7", budget })).rejects.toMatchObject({ code: "malformed" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("enforces SCM transport boundaries and provider request budgets", async () => {
    expect(() => new GitHubSCMProvider({ apiBaseUrl: "https://api.github.com:8443", token: "reader-token", fetch: vi.fn(), allowedRepositories: ["acme/app"], allowedRefs: ["main"] })).toThrow("expected port");
    expect(() => new JenkinsSCMProvider({ baseUrl: "http://127.0.0.1:8080", job: "ci", fetch: vi.fn(), allowedRepositories: ["acme/app"], allowedRefs: ["main"] })).toThrow("explicit loopback");
    expect(() => new JenkinsSCMProvider({ baseUrl: "http://127.0.0.1:8080", job: "ci", allowInsecureHttp: true, fetch: vi.fn(), allowedRepositories: ["acme/app"], allowedRefs: ["main"] })).not.toThrow();
    expect(() => new JenkinsSCMProvider({ baseUrl: "http://jenkins.example", job: "ci", allowInsecureHttp: true, fetch: vi.fn(), allowedRepositories: ["acme/app"], allowedRefs: ["main"] })).toThrow("explicit loopback");

    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ number: 7, base: { ref: "main", sha: BASE, repo: { full_name: "acme/app" } }, head: { ref: "feature", sha: HEAD, repo: { full_name: "acme/app" } } })));
    const provider = new GitHubSCMProvider({ token: "reader-token", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main", "feature"] });
    await expect(provider.getChangeEvidence({ repository: "acme/app", pullRequest: "7", budget: { ...budget, maxProviderRequests: 1 } })).rejects.toMatchObject({ code: "unavailable" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("reports file, hunk, line, byte, and digest bounds deterministically", async () => {
    const files = JSON.stringify([
      { filename: "src/a.ts", status: "modified", additions: 2, deletions: 1, patch: "@@ -1 +1 @@\n-a\n+b\n@@ -3 +3 @@\n-c\n+d" },
      { filename: "src/b.ts", status: "modified", additions: 1, deletions: 0, patch: "@@ -1 +1 @@\n-a\n+b" },
    ]);
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(new Response(JSON.stringify({ number: 7, base: { ref: "main", sha: BASE, repo: { full_name: "acme/app" } }, head: { ref: "feature", sha: HEAD, repo: { full_name: "acme/app" } } }))).mockResolvedValueOnce(new Response(files));
    const result = await new GitHubSCMProvider({ token: "reader-token", fetch, clock: () => NOW, allowedRepositories: ["acme/app"], allowedRefs: ["main", "feature"] })
      .getChangeEvidence({ repository: "acme/app", pullRequest: "7", budget: { ...budget, maxFiles: 1, maxHunks: 1, maxLines: 2, maxBytes: 1_024 } });

    expect(result.data.files).toHaveLength(1);
    expect(result.budget.usedFiles).toBeLessThanOrEqual(1);
    expect(result.budget.usedHunks).toBeLessThanOrEqual(1);
    expect(result.budget.usedLines).toBeLessThanOrEqual(2);
    expect(result.budget.usedBytes).toBeLessThanOrEqual(1_024);
    expect(result.truncated).toBe(true);
    expect(result.truncation).toMatchObject({ files: true, hunks: true });
    expect(result.digest).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(result)).not.toContain("checkout");
  });

  it("enforces the time window before a provider request starts", async () => {
    let ticks = 0;
    const fetch = vi.fn<typeof globalThis.fetch>();
    const provider = new JenkinsSCMProvider({ baseUrl: "https://jenkins.example", job: "ci", fetch, clock: () => ticks++ === 0 ? NOW : new Date(NOW.getTime() + 6_000), allowedRepositories: ["acme/app"], allowedRefs: ["feature"] });
    await expect(provider.getChangeEvidence({ repository: "acme/app", ref: "feature", budget: { ...budget, maxDurationMs: 100 } })).rejects.toMatchObject({ code: "unavailable" });
    expect(fetch).not.toHaveBeenCalled();
  });
});
