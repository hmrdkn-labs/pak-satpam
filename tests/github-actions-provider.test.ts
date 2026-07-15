import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { GitHubActionsProvider } from "../src/providers/github-actions-provider.js";
import { GitHubAppTokenProvider } from "../src/providers/github-app-token-provider.js";

const NOW = new Date("2026-07-10T00:00:00.000Z");

function provider(fetch: typeof globalThis.fetch) {
  return new GitHubActionsProvider({
    token: "github-token-used-only-in-header",
    fetch,
    clock: () => NOW,
    maxFreshnessMs: 5 * 60_000,
    apiBaseUrl: "https://api.github.com/",
  });
}

describe("GitHub Actions adapter", () => {
  it("mints a cached repository-scoped GitHub App token with Actions read permission by default", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const installationToken = `ghs_${"x".repeat(32)}`;
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response(JSON.stringify({ token: installationToken, expires_at: "2026-07-10T01:00:00Z" }), {
        headers: { "content-type": "application/json" },
      }),
    );
    const tokenProvider = new GitHubAppTokenProvider({
      appId: "123",
      installationId: "456",
      privateKeyPem: privateKey.export({ type: "pkcs1", format: "pem" }).toString(),
      allowedRepositories: ["owner/repo"],
      fetch,
      clock: () => NOW,
    });

    await expect(tokenProvider.getToken("owner/repo")).resolves.toBe(installationToken);
    await expect(tokenProvider.getToken("owner/repo")).resolves.toBe(installationToken);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url, init] = fetch.mock.calls[0] ?? [];
    expect(url).toBe("https://api.github.com/app/installations/456/access_tokens");
    expect(init).toMatchObject({ method: "POST", redirect: "error" });
    expect(JSON.parse(String(init && "body" in init ? init.body : "{}"))).toEqual({
      repositories: ["repo"],
      permissions: { actions: "read" },
    });
    await expect(tokenProvider.getToken("owner/other")).rejects.toMatchObject({ code: "permission" });
  });

  it("keeps installation-token cache entries scoped per repository", async () => {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "token-for-one-123456", expires_at: "2026-07-10T01:00:00Z" })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ token: "token-for-two-123456", expires_at: "2026-07-10T01:00:00Z" })));
    const tokenProvider = new GitHubAppTokenProvider({
      appId: "123",
      installationId: "456",
      privateKeyPem: privateKey.export({ type: "pkcs1", format: "pem" }).toString(),
      allowedRepositories: ["owner/one", "owner/two"],
      fetch,
      clock: () => NOW,
    });
    await expect(tokenProvider.getToken("owner/one")).resolves.toBe("token-for-one-123456");
    await expect(tokenProvider.getToken("owner/two")).resolves.toBe("token-for-two-123456");
    await expect(tokenProvider.getToken("owner/one")).resolves.toBe("token-for-one-123456");
    expect(fetch).toHaveBeenCalledTimes(2);
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({ repositories: ["one"] });
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toMatchObject({ repositories: ["two"] });
  });

  it("normalizes workflow status and marks old runs stale", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
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
              created_at: "2026-07-09T23:00:00Z",
              updated_at: "2026-07-09T23:01:00Z",
            },
          ],
        }),
        { headers: { "content-type": "application/json" } },
      ),
    );

    const result = await provider(fetch).getWorkflowStatus({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
    });

    expect(result.data.run).toMatchObject({
      id: "101",
      status: "completed",
      conclusion: "failure",
      runAttempt: 1,
    });
    expect(result.freshness).toBe("stale");
    expect(fetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/owner/repo/actions/workflows/goal14-controlled-fixture.yml/runs?per_page=1",
      expect.objectContaining({
        method: "GET",
        redirect: "error",
        headers: expect.objectContaining({ authorization: "Bearer github-token-used-only-in-header" }),
      }),
    );
  });

  it("preserves a structured API reverse-proxy prefix without duplicating it", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({
      id: 101,
      status: "completed",
      conclusion: "success",
      run_attempt: 1,
      event: "workflow_dispatch",
      head_branch: "main",
      head_sha: "a".repeat(40),
      created_at: "2026-07-10T00:00:00Z",
      updated_at: "2026-07-10T00:00:00Z",
    })));
    const adapter = new GitHubActionsProvider({
      token: "github-token-used-only-in-header",
      endpoint: { origin: "https://api.github.com", path: "/reverse-proxy/api/v3" },
      fetch,
      clock: () => NOW,
    });

    await adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "ci.yml", runId: "101" });

    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://api.github.com/reverse-proxy/api/v3/repos/owner/repo/actions/runs/101");
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("api/v3/reverse-proxy");
  });

  it("preserves provider-native string and UUID run and job IDs", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: "{550e8400-e29b-41d4-a716-446655440000}",
        status: "completed",
        conclusion: "failure",
        run_attempt: 1,
        event: "workflow_dispatch",
        head_branch: "main",
        head_sha: "a".repeat(40),
        created_at: "2026-07-10T00:00:00Z",
        updated_at: "2026-07-10T00:00:00Z",
      })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ jobs: [{
        id: "job-main-7",
        name: "test",
        status: "completed",
        conclusion: "failure",
        steps: [],
      }] })));

    const result = await provider(fetch).getFailedJobAnalysis({
      repo: "owner/repo",
      workflow: "ci.yml",
      runId: "{550e8400-e29b-41d4-a716-446655440000}",
    });

    expect(result.data.run.id).toBe("{550e8400-e29b-41d4-a716-446655440000}");
    expect(result.data.failedJobs[0]?.id).toBe("job-main-7");
  });

  it("classifies failed jobs and returns only bounded sanitized log evidence", async () => {
    const fetch = vi
      .fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            id: 101,
            status: "completed",
            conclusion: "failure",
            run_attempt: 1,
            event: "workflow_dispatch",
            head_branch: "main",
            head_sha: "a".repeat(40),
            created_at: "2026-07-09T23:00:00Z",
            updated_at: "2026-07-09T23:01:00Z",
          }),
          { headers: { "content-type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(
          JSON.stringify({
            jobs: [
              {
                id: 9,
                name: "lint",
                status: "completed",
                conclusion: "failure",
                steps: [{ name: "ESLint", conclusion: "failure" }],
              },
              { id: 10, name: "build", status: "completed", conclusion: "success", steps: [] },
            ],
          }),
          { headers: { "content-type": "application/json" } },
        ),
      )
      .mockResolvedValueOnce(
        new Response(null, {
          status: 302,
          headers: { location: "https://pipelines.actions.githubusercontent.com/logs/job-9.txt" },
        }),
      )
      .mockResolvedValueOnce(
        new Response("Authorization: Bearer ghp_supersecret\nESLint failed\n", {
          headers: { "content-type": "text/plain" },
        }),
      );

    const adapter = provider(fetch);
    const analysis = await adapter.getFailedJobAnalysis({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
    });
    const logs = await adapter.getLogEvidence({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
      jobId: "9",
      maxLines: 1,
    });

    expect(analysis.data.failedJobs).toMatchObject([
      { id: "9", category: "lint", conclusion: "failure" },
    ]);
    expect(logs.redactionsApplied).toBe(true);
    expect(logs.truncated).toBe(true);
    expect(JSON.stringify(logs)).not.toContain("ghp_supersecret");
    expect(JSON.stringify(logs)).not.toContain("Authorization:");
    expect(fetch).toHaveBeenLastCalledWith(
      new URL("https://pipelines.actions.githubusercontent.com/logs/job-9.txt"),
      expect.objectContaining({ method: "GET", redirect: "error" }),
    );
    expect(fetch.mock.calls.at(-1)?.[1]).not.toHaveProperty("headers");
  });
  it("reports secret redaction separately from excerpt truncation", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response("x".repeat(1_500), { headers: { "content-type": "text/plain" } }));
    const logs = await provider(fetch).getLogEvidence({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
      jobId: "9",
      maxLines: 1,
    });

    expect(logs.redactionsApplied).toBe(false);
    expect(logs.truncated).toBe(true);
    expect(logs.data.lines[0]?.text).toContain("[TRUNCATED]");
  });

  it("rejects an untrusted GitHub API base URL", () => {
    expect(() => new GitHubActionsProvider({
      token: "github-token-used-only-in-header",
      fetch: vi.fn<typeof globalThis.fetch>(),
      apiBaseUrl: "https://example.com",
    })).toThrow("not trusted");
  });

  it("rejects a log redirect outside GitHub Actions storage", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response(null, { status: 302, headers: { location: "https://example.com/logs.txt" } }),
    );
    await expect(provider(fetch).getLogEvidence({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
      jobId: "9",
      maxLines: 10,
    })).rejects.toMatchObject({ code: "permission" });
  });

  it("accepts GitHub Actions signed Azure log storage without forwarding authorization", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(null, {
        status: 302,
        headers: { location: "https://productionresultssa13.blob.core.windows.net/actions-results/job.txt?sig=synthetic" },
      }))
      .mockResolvedValueOnce(new Response("test failed\n", {
        headers: { "content-type": "text/plain" },
      }));
    const result = await provider(fetch).getLogEvidence({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
      jobId: "9",
      maxLines: 10,
    });
    expect(result.data.available).toBe(true);
    expect(fetch.mock.calls.at(-1)?.[1]).not.toHaveProperty("headers");
  });

  it("maps malformed, unavailable, and permission responses without echoing bodies", async () => {
    for (const response of [
      new Response("upstream-secret", { status: 500 }),
      new Response("not-json-secret", { status: 200 }),
      new Response("permission-secret", { status: 403 }),
    ]) {
      const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(response);
      await expect(
        provider(fetch).getWorkflowStatus({ repo: "owner/repo", workflow: "ci.yml" }),
      ).rejects.toMatchObject({
        code: expect.stringMatching(/^(unavailable|malformed|permission)$/),
      });
      await expect(
        provider(fetch).getWorkflowStatus({ repo: "owner/repo", workflow: "ci.yml" }),
      ).rejects.not.toThrow("secret");
    }
  });

  it("calls only GitHub's rerun-failed-jobs endpoint", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(null, { status: 201 }));
    const result = await provider(fetch).rerunFailedWorkflow({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
    });

    expect(result.data).toMatchObject({ runId: "101", accepted: true, action: "rerun-failed-jobs" });
    expect(fetch).toHaveBeenCalledWith(
      "https://api.github.com/repos/owner/repo/actions/runs/101/rerun-failed-jobs",
      expect.objectContaining({ method: "POST", redirect: "error" }),
    );
  });

  it("uses the read token for reads and the separate write token only for reruns", async () => {
    const readTokenProvider = { getToken: vi.fn(async () => "github-read-token-123456") };
    const writeTokenProvider = { getToken: vi.fn(async () => "github-write-token-123456") };
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        id: 101,
        status: "completed",
        conclusion: "failure",
        run_attempt: 1,
        event: "workflow_dispatch",
        head_branch: "main",
        head_sha: "a".repeat(40),
        created_at: "2026-07-10T00:00:00Z",
        updated_at: "2026-07-10T00:00:00Z",
      }), { headers: { "content-type": "application/json" } }))
      .mockResolvedValueOnce(new Response(null, { status: 201 }));
    const adapter = new GitHubActionsProvider({
      tokenProvider: readTokenProvider,
      writeTokenProvider,
      fetch,
      clock: () => NOW,
    });

    await adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "ci.yml", runId: "101" });
    await adapter.rerunFailedWorkflow({ repo: "owner/repo", workflow: "ci.yml", runId: "101" });

    expect(readTokenProvider.getToken).toHaveBeenCalledTimes(1);
    expect(writeTokenProvider.getToken).toHaveBeenCalledTimes(1);
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({
      headers: expect.objectContaining({ authorization: "Bearer github-read-token-123456" }),
    });
    expect(fetch.mock.calls[1]?.[1]).toMatchObject({
      headers: expect.objectContaining({ authorization: "Bearer github-write-token-123456" }),
    });
  });

  it("maps a failed rerun without exposing the provider response", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(
      new Response("provider-secret-must-not-surface", { status: 500 }),
    );
    await expect(provider(fetch).rerunFailedWorkflow({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
    })).rejects.toMatchObject({ code: "unavailable" });
    await expect(provider(fetch).rerunFailedWorkflow({
      repo: "owner/repo",
      workflow: "goal14-controlled-fixture.yml",
      runId: "101",
    })).rejects.not.toThrow("secret");
  });
});
