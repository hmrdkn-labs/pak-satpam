import { describe, expect, it, vi } from "vitest";
import { BitbucketProvider } from "../src/providers/bitbucket-provider.js";
import { JenkinsProvider } from "../src/providers/jenkins-provider.js";

const NOW = new Date("2026-07-10T00:00:00.000Z");

describe("Jenkins read-only CI adapter", () => {
  it("normalizes status, bounds/redacts console evidence, and never reruns", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        number: 42,
        result: "FAILURE",
        building: false,
        timestamp: Date.parse("2026-07-10T00:00:00Z"),
        duration: 1_000,
        displayName: "main",
        actions: [{ lastBuiltRevision: { SHA1: "a".repeat(40) } }],
      })))
      .mockResolvedValueOnce(new Response("setup noise\ncompile failed\nAuthorization: Bearer jenkins-secret\nthird line\n"));
    const adapter = new JenkinsProvider({ baseUrl: "https://jenkins.local/jenkins/", branch: "main", fetch, clock: () => NOW });

    const status = await adapter.getWorkflowStatus({ repo: "academytools/planpal-backend-learner-6", workflow: "planpal-backend", runId: "42" });
    const logs = await adapter.getLogEvidence({ repo: "academytools/planpal-backend-learner-6", workflow: "planpal-backend", runId: "42", jobId: "42", maxLines: 2 });

    expect(status.data.run).toMatchObject({ id: "42", conclusion: "failure", ref: "main", sha: "a".repeat(40) });
    expect(logs.data.lines).toEqual([{ sequence: 1, text: "[REDACTED]" }, { sequence: 2, text: "third line" }]);
    expect(logs.redactionsApplied).toBe(true);
    expect(logs.truncated).toBe(true);
    expect(fetch.mock.calls.map(([url, init]) => [String(url), init?.method])).toEqual([
      ["https://jenkins.local/jenkins/job/planpal-backend/job/main/42/api/json", "GET"],
      ["https://jenkins.local/jenkins/job/planpal-backend/job/main/42/consoleText", "GET"],
    ]);
    await expect(adapter.rerunFailedWorkflow({ repo: "academytools/planpal-backend-learner-6", workflow: "planpal-backend", runId: "42" })).rejects.toMatchObject({ code: "permission" });
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("returns the tail of oversized console logs instead of malformed", async () => {
    const consoleBody = `${Array.from({ length: 300_000 }, (_, index) => `line ${index}\n`).join("")}FATAL: boom\n`;
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValueOnce(new Response(consoleBody));
    const adapter = new JenkinsProvider({ baseUrl: "https://jenkins.local/", fetch, clock: () => NOW });

    const logs = await adapter.getLogEvidence({
      repo: "academytools/planpal-config-6",
      workflow: "planpalasix-config/PR-240",
      runId: "1",
      jobId: "1",
      maxLines: 5,
    });

    expect(logs.data.available).toBe(true);
    expect(logs.truncated).toBe(true);
    expect(logs.data.lines.at(-1)?.text).toBe("FATAL: boom");
  });

  it("uses Jenkins Basic API-token auth without exposing the token and rejects unsafe job paths", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({
      number: 7,
      result: "SUCCESS",
      building: false,
      timestamp: NOW.getTime(),
      duration: 0,
    })));
    const adapter = new JenkinsProvider({
      baseUrl: "https://jenkins.local/reverse-proxy/",
      branch: "main",
      username: "ci-reader",
      token: "jenkins-api-token-only-in-header",
      fetch,
      clock: () => NOW,
    });

    const result = await adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "folder/backend", runId: "7" });

    expect(result.providerClass).toBe("jenkins");
    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://jenkins.local/reverse-proxy/job/folder/job/backend/job/main/7/api/json");
    expect(fetch.mock.calls[0]?.[1]?.headers).toMatchObject({
      authorization: `Basic ${Buffer.from("ci-reader:jenkins-api-token-only-in-header").toString("base64")}`,
    });
    expect(JSON.stringify(result)).not.toContain("jenkins-api-token-only-in-header");

    const unsafe = new JenkinsProvider({ baseUrl: "https://jenkins.local/", fetch });
    await expect(unsafe.getWorkflowStatus({ repo: "owner/repo", workflow: "folder//backend", runId: "7" })).rejects.toMatchObject({ code: "malformed" });
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("uses a structured reverse-proxy endpoint without duplicating its prefix", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({
      number: 7,
      result: "SUCCESS",
      building: false,
      timestamp: NOW.getTime(),
      duration: 0,
    })));
    const adapter = new JenkinsProvider({
      endpoint: { origin: "https://jenkins.local", path: "/reverse-proxy" },
      branch: "main",
      fetch,
      clock: () => NOW,
    });

    await adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "folder/backend", runId: "7" });

    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://jenkins.local/reverse-proxy/job/folder/job/backend/job/main/7/api/json");
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("reverse-proxy/reverse-proxy");
  });

  it("uses the full multibranch workflow path without appending a default branch", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({
      number: 1,
      result: "SUCCESS",
      building: false,
      timestamp: NOW.getTime(),
      duration: 0,
    })));
    const adapter = new JenkinsProvider({ baseUrl: "https://jenkins.local/", fetch, clock: () => NOW });

    await adapter.getWorkflowStatus({ repo: "academytools/planpal-config-6", workflow: "planpalasix-config/PR-240", runId: "1" });

    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://jenkins.local/job/planpalasix-config/job/PR-240/1/api/json");
  });

  it("accepts a provider-native string build identifier", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({
      number: "build-main-7",
      result: "SUCCESS",
      building: false,
      timestamp: NOW.getTime(),
      duration: 0,
    })));
    const adapter = new JenkinsProvider({ baseUrl: "https://jenkins.local/", fetch, clock: () => NOW });

    await expect(adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "ci", runId: "build-main-7" })).resolves.toMatchObject({
      data: { run: { id: "build-main-7" } },
    });
  });

  it.each([
    "https://user:password@jenkins.local",
    "ftp://jenkins.local",
    "https://jenkins.local/?target=https://attacker.invalid",
  ])("rejects unsafe Jenkins base URLs: %s", (baseUrl) => {
    expect(() => new JenkinsProvider({ baseUrl, fetch: vi.fn<typeof globalThis.fetch>() })).toThrow();
  });

  it("rejects Jenkins credentials over cleartext HTTP and only allows explicit loopback anonymous HTTP", () => {
    expect(() => new JenkinsProvider({
      baseUrl: "http://127.0.0.1:8080",
      username: "ci-reader",
      token: "jenkins-api-token-only-in-header",
      fetch: vi.fn<typeof globalThis.fetch>(),
    })).toThrow("HTTPS");
    expect(() => new JenkinsProvider({
      baseUrl: "http://127.0.0.1:8080",
      fetch: vi.fn<typeof globalThis.fetch>(),
    })).toThrow("explicit loopback");
    expect(() => new JenkinsProvider({
      baseUrl: "http://127.0.0.1:8080",
      allowInsecureHttp: true,
      fetch: vi.fn<typeof globalThis.fetch>(),
    })).not.toThrow();
  });
});

describe("Bitbucket read-only CI adapter", () => {
  it("normalizes pipeline status, sends Basic auth, and provides bounded PR diff hunks", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        build_number: 7,
        state: { name: "COMPLETED", result: { name: "FAILED" } },
        created_on: "2026-07-10T00:00:00Z",
        completed_on: "2026-07-10T00:01:00Z",
        target: { ref_name: "main", commit: { hash: "b".repeat(40) } },
      })))
      .mockResolvedValueOnce(new Response("@@ -1,1 +1,1 @@\n-secret\n+safe\n"));
    const adapter = new BitbucketProvider({ baseUrl: "https://bitbucket.example/2.0/", token: "reader:token-value", fetch, clock: () => NOW });

    const status = await adapter.getWorkflowStatus({ repo: "academytools/planpal-config-6", workflow: "pipeline", runId: "7" });
    const diff = await adapter.getDiffHunks("academytools/planpal-config-6", "12");

    expect(status.data.run).toMatchObject({ id: "7", conclusion: "failure", ref: "main", sha: "b".repeat(40) });
    expect(status.providerClass).toBe("bitbucket-cloud");
    expect(diff.hunks).toEqual(["@@ -1,1 +1,1 @@\n-secret\n+safe\n"]);
    expect(fetch.mock.calls[0]?.[1]).toMatchObject({ method: "GET", headers: expect.objectContaining({ authorization: `Basic ${Buffer.from("reader:token-value").toString("base64")}` }) });
    expect(String(fetch.mock.calls[1]?.[0])).toBe("https://bitbucket.example/2.0/repositories/academytools/planpal-config-6/pullrequests/12/diff");
    await expect(adapter.rerunFailedWorkflow({ repo: "academytools/planpal-config-6", workflow: "pipeline", runId: "7" })).rejects.toMatchObject({ code: "permission" });
    expect(fetch).toHaveBeenCalledTimes(2);
  });
  it("normalizes commit and pull-request status without returning provider payloads", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({ values: [{ key: "build", state: "SUCCESSFUL", name: "CI", description: "green" }] })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ id: 12, state: "OPEN", title: "Safe change", source: { branch: { name: "feature" } }, destination: { branch: { name: "main" } } })));
    const adapter = new BitbucketProvider({ baseUrl: "https://bitbucket.example/2.0", token: "reader:token-value", fetch });
    await expect(adapter.getCommitStatus("academytools/planpal-config-6", "a".repeat(40))).resolves.toEqual([{ key: "build", state: "SUCCESSFUL", name: "CI", description: "green" }]);
    await expect(adapter.getPullRequestStatus("academytools/planpal-config-6", "12")).resolves.toEqual({ id: "12", state: "OPEN", title: "Safe change", source: "feature", destination: "main" });
    expect(fetch.mock.calls.map(([url]) => String(url))).toEqual([
      "https://bitbucket.example/2.0/repositories/academytools/planpal-config-6/commit/" + "a".repeat(40) + "/statuses",
      "https://bitbucket.example/2.0/repositories/academytools/planpal-config-6/pullrequests/12",
    ]);
  });

  it("uses a structured full API base path exactly once", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ values: [] })));
    const adapter = new BitbucketProvider({
      endpoint: { origin: "https://bitbucket.example", path: "/reverse-proxy/2.0" },
      token: "reader:token-value",
      fetch,
    });

    await adapter.getCommitStatus("academytools/planpal-config-6", "a".repeat(40));

    expect(String(fetch.mock.calls[0]?.[0])).toBe("https://bitbucket.example/reverse-proxy/2.0/repositories/academytools/planpal-config-6/commit/" + "a".repeat(40) + "/statuses");
    expect(String(fetch.mock.calls[0]?.[0])).not.toContain("2.0/reverse-proxy");
  });

  it("normalizes Cloud in-progress and terminal result states without inventing a completed result", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        build_number: 8,
        state: { name: "IN_PROGRESS" },
        created_on: "2026-07-10T00:00:00Z",
        target: { ref_name: "feature", commit: { hash: "c".repeat(40) } },
      })))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        build_number: 9,
        state: { name: "COMPLETED" },
        created_on: "2026-07-10T00:00:00Z",
        completed_on: "2026-07-10T00:01:00Z",
        target: { ref_name: "main", commit: { hash: "d".repeat(40) } },
      })));
    const adapter = new BitbucketProvider({ baseUrl: "https://api.bitbucket.org/2.0", token: "reader:token-value", fetch, clock: () => NOW });

    await expect(adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "pipeline", runId: "8" })).resolves.toMatchObject({
      data: { run: { status: "in_progress", conclusion: null } },
    });
    await expect(adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "pipeline", runId: "9" })).resolves.toMatchObject({
      data: { run: { status: "completed", conclusion: "unknown" } },
    });
  });

  it("accepts a Bitbucket Cloud UUID pipeline identifier", async () => {
    const pipelineId = "{550e8400-e29b-41d4-a716-446655440000}";
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({
      state: { name: "COMPLETED", result: { name: "SUCCESSFUL" } },
      created_on: "2026-07-10T00:00:00Z",
      completed_on: "2026-07-10T00:01:00Z",
      target: { ref_name: "main", commit: { hash: "d".repeat(40) } },
    })));
    const adapter = new BitbucketProvider({ baseUrl: "https://api.bitbucket.org/2.0", token: "reader:token-value", fetch, clock: () => NOW });

    await expect(adapter.getWorkflowStatus({ repo: "owner/repo", workflow: "pipeline", runId: pipelineId })).resolves.toMatchObject({
      data: { run: { id: pipelineId, conclusion: "success" } },
    });
  });

  it.each([
    "https://user:password@bitbucket.example/2.0",
    "ftp://bitbucket.example/2.0",
  ])("rejects unsafe Bitbucket Cloud base URLs: %s", (baseUrl) => {
    expect(() => new BitbucketProvider({ baseUrl, token: "reader:token-value", fetch: vi.fn<typeof globalThis.fetch>() })).toThrow();
  });

  it("rejects Bitbucket credentials over cleartext HTTP", () => {
    expect(() => new BitbucketProvider({
      baseUrl: "http://127.0.0.1:7990/2.0",
      token: "reader:token-value",
      fetch: vi.fn<typeof globalThis.fetch>(),
    })).toThrow("HTTPS");
  });

});
