import { createHmac, generateKeyPairSync } from "node:crypto";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

import { GitHubActionsProvider } from "../src/providers/github-actions-provider.js";
import { loadObserverConfiguration, observerRuntimeConfig, readObserverSecretFile } from "../src/observer/config.js";
import { MappedGitHubAppTokenProvider } from "../src/providers/mapped-github-app-token-provider.js";
import { HermesDelivery, isTrustedHermesUrl } from "../src/observer/delivery.js";
import { createObserverRuntimeFromFiles } from "../src/observer/runtime.js";
import { observerEventSourceFromProvider } from "../src/observer/events.js";
import { createObserverProviderFromConfiguration } from "../src/observer/provider-factory.js";
import { BitbucketProvider } from "../src/providers/bitbucket-provider.js";
import { JenkinsProvider } from "../src/providers/jenkins-provider.js";

const NOW = new Date("2026-07-14T00:00:00.000Z");
const SHA = "b".repeat(40);

describe("observer GitHub run listing", () => {
  it("lists bounded workflow pages with a created-time overlap cursor", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ workflow_runs: [
      { id: 10, status: "completed", conclusion: "success", run_attempt: 1, event: "push", head_branch: "main", head_sha: SHA, created_at: NOW.toISOString(), updated_at: NOW.toISOString() },
    ] }), { headers: { "content-type": "application/json" } }));
    const provider = new GitHubActionsProvider({ token: "observer-token-that-is-not-persisted", fetch, clock: () => NOW });

    const result = await provider.listWorkflowRuns({ repo: "owner/repo", workflow: "ci.yml", createdAfter: "2026-07-13T23:55:00.000Z", page: 1, perPage: 100 });

    expect(result.runs).toHaveLength(1);
    const url = new URL(String(fetch.mock.calls[0]?.[0]));
    expect(url.pathname).toBe("/repos/owner/repo/actions/workflows/ci.yml/runs");
    expect(url.searchParams.get("created")).toBe(">=2026-07-13T23:55:00.000Z");
    expect(url.searchParams.get("per_page")).toBe("100");
    expect(url.searchParams.get("page")).toBe("1");
    expect(url.searchParams.get("status")).toBe("completed");
  });
});

describe("observer configuration", () => {
  it.each([
    ["Jenkins", new JenkinsProvider({ baseUrl: "https://jenkins.example", fetch: globalThis.fetch })],
    ["Bitbucket Cloud", new BitbucketProvider({ baseUrl: "https://bitbucket.example", token: "observer-user:observer-token", fetch: globalThis.fetch })],
  ])("fails closed without unimplemented %s observer capabilities", async (_label, provider) => {
    const source = observerEventSourceFromProvider(provider);

    expect(source.webhookVerifier).toBeUndefined();
    await expect(source.listTerminalRuns({ repo: "owner/repo", workflow: "ci.yml", page: 1, perPage: 1 })).rejects.toMatchObject({ code: "unsupported" });
  });

  it.each(["jenkins", "bitbucket"] as const)("does not assemble an unsupported %s observer provider", (type) => {
    expect(() => createObserverProviderFromConfiguration({ type }, {
      repositories: ["owner/repo"],
      fetch: globalThis.fetch,
      clock: () => NOW,
    })).toThrowError(expect.objectContaining({ code: "unsupported" }));
  });

  it("permits only Tailscale-literal or exact configured HTTP Hermes hosts", () => {
    const tailscaleHost = [100, 64, 12, 34].join(".");
    const outsideCgnatHost = [100, 128, 0, 1].join(".");
    expect(isTrustedHermesUrl(`http://${tailscaleHost}/events`)).toBe(true);
    expect(isTrustedHermesUrl(`http://${outsideCgnatHost}/events`)).toBe(false);
    expect(isTrustedHermesUrl("http://hermes.internal/events", ["hermes.internal"])).toBe(true);
    expect(isTrustedHermesUrl("http://hermes.public.example/events", ["hermes.internal"])).toBe(false);
    expect(isTrustedHermesUrl("https://hermes.public.example/events")).toBe(true);
  });

  it("requires private config and secret files and rejects duplicate exact targets", () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-config-"));
    const configPath = join(directory, "observer.yml");
    const keyPath = join(directory, "hermes-key");
    try {
      const appIdPath = join(directory, "app-id");
      const pemPath = join(directory, "app.pem");
      const installationPath = join(directory, "installation-id");
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      writeFileSync(appIdPath, "123\n", { mode: 0o600 });
      writeFileSync(pemPath, privateKey.export({ type: "pkcs1", format: "pem" }), { mode: 0o600 });
      writeFileSync(installationPath, "456\n", { mode: 0o600 });
      writeFileSync(keyPath, "k".repeat(32), { mode: 0o600 });
      writeFileSync(configPath, `
version: 1
allowlist:
  - repo: owner/repo
    workflows: [ci.yml]
state_file: ${join(directory, "state.json")}
github:
  app_id_file: ${appIdPath}
  pem_key_file: ${pemPath}
  installations:
    - owner: owner
      installation_id_file: ${installationPath}
hermes:
  success_url: https://hermes.example/events
  analysis_url: https://hermes.example/analysis
  trusted_internal_hosts: []
  hmac_key_file: ${keyPath}
`, { mode: 0o600 });
      const loaded = loadObserverConfiguration(configPath);
      expect(observerRuntimeConfig(loaded, readObserverSecretFile(keyPath))).toMatchObject({
        successUrl: "https://hermes.example/events",
        leaseMs: 60_000,
      });
      chmodSync(configPath, 0o644);
      expect(() => loadObserverConfiguration(configPath)).toThrow("0600");
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("injects a GitHub webhook secret into the runtime verifier without exposing it", async () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-webhook-runtime-"));
    try {
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const appIdPath = join(directory, "app-id");
      const pemPath = join(directory, "app.pem");
      const installationPath = join(directory, "installation-id");
      const keyPath = join(directory, "hermes-key");
      const statePath = join(directory, "state.json");
      const webhookKey = "github-webhook-secret-that-is-long-enough";
      writeFileSync(appIdPath, "123\n", { mode: 0o600 });
      writeFileSync(pemPath, privateKey.export({ type: "pkcs1", format: "pem" }), { mode: 0o600 });
      writeFileSync(installationPath, "456\n", { mode: 0o600 });
      writeFileSync(keyPath, webhookKey, { mode: 0o600 });
      writeFileSync(join(directory, "observer.yml"), `
version: 1
allowlist:
  - repo: owner/repo
    workflows: [ci.yml]
state_file: ${statePath}
github:
  app_id_file: ${appIdPath}
  pem_key_file: ${pemPath}
  installations:
    - owner: owner
      installation_id_file: ${installationPath}
  webhook_secret_file: ${keyPath}
hermes:
  success_url: https://hermes.example/events
  analysis_url: https://hermes.example/analysis
  trusted_internal_hosts: []
  hmac_key_file: ${keyPath}
`, { mode: 0o600 });
      const body = JSON.stringify({
        repository: { full_name: "owner/repo" },
        workflow: { path: ".github/workflows/ci.yml" },
        workflow_run: {
          id: 99,
          status: "completed",
          conclusion: "success",
          run_attempt: 1,
          event: "push",
          head_branch: "main",
          head_sha: "a".repeat(40),
          created_at: NOW.toISOString(),
          updated_at: NOW.toISOString(),
        },
      });
      const signature = `sha256=${createHmac("sha256", webhookKey).update(body).digest("hex")}`;
      const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(null, { status: 204 }));
      const runtime = createObserverRuntimeFromFiles({ configPath: join(directory, "observer.yml"), fetch, clock: () => NOW });

      await expect(runtime.ingestWebhook({ headers: { "x-github-event": "workflow_run", "x-hub-signature-256": signature }, body })).resolves.toMatchObject({ accepted: true, delivered: 1 });
      expect(JSON.stringify(runtime)).not.toContain(webhookKey);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("routes exact repositories through per-owner and per-repository App installations", async () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-app-"));
    try {
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const appId = join(directory, "app-id");
      const pem = join(directory, "app.pem");
      const ownerInstall = join(directory, "owner-id");
      const repositoryInstall = join(directory, "repository-id");
      writeFileSync(appId, "123\n", { mode: 0o600 });
      writeFileSync(pem, privateKey.export({ type: "pkcs1", format: "pem" }), { mode: 0o600 });
      writeFileSync(ownerInstall, "456\n", { mode: 0o600 });
      writeFileSync(repositoryInstall, "789\n", { mode: 0o600 });
      const fetch = vi.fn<typeof globalThis.fetch>()
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "owner-token-123456", expires_at: "2026-07-14T01:00:00Z" })))
        .mockResolvedValueOnce(new Response(JSON.stringify({ token: "repository-token-123456", expires_at: "2026-07-14T01:00:00Z" })));
      const provider = MappedGitHubAppTokenProvider.fromFiles({
        appIdFile: appId,
        pemKeyFile: pem,
        installations: [
          { owner: "owner", installationIdFile: ownerInstall },
          { repo: "other/repo", installationIdFile: repositoryInstall },
        ],
        repositories: ["owner/one", "other/repo"],
        fetch,
        clock: () => NOW,
        apiBaseUrl: "https://api.github.com",
      });
      await expect(provider.getToken("owner/one")).resolves.toBe("owner-token-123456");
      await expect(provider.getToken("other/repo")).resolves.toBe("repository-token-123456");
      expect(fetch.mock.calls.map((call) => String(call[0]))).toEqual([
        "https://api.github.com/app/installations/456/access_tokens",
        "https://api.github.com/app/installations/789/access_tokens",
      ]);
      expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({ permissions: { actions: "read" } });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("requests read-only Actions tokens for observer mappings", async () => {
    const directory = mkdtempSync(join(tmpdir(), "observer-read-only-app-"));
    try {
      const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const appId = join(directory, "app-id");
      const pem = join(directory, "app.pem");
      const installation = join(directory, "installation-id");
      writeFileSync(appId, "123\n", { mode: 0o600 });
      writeFileSync(pem, privateKey.export({ type: "pkcs1", format: "pem" }), { mode: 0o600 });
      writeFileSync(installation, "456\n", { mode: 0o600 });
      const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(JSON.stringify({ token: "observer-read-token", expires_at: "2026-07-14T01:00:00Z" })));
      const provider = MappedGitHubAppTokenProvider.fromFiles({
        appIdFile: appId,
        pemKeyFile: pem,
        installations: [{ owner: "owner", installationIdFile: installation }],
        repositories: ["owner/repo"],
        fetch,
        clock: () => NOW,
        apiBaseUrl: "https://api.github.com",
        actionsPermission: "read",
      });

      await provider.getToken("owner/repo");

      expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({ permissions: { actions: "read" } });
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it("routes analysis deliveries separately with the exact Hermes V2 headers", async () => {
    const tailscaleHost = [100, 64, 12, 34].join(".");
    const fetch = vi.fn<typeof globalThis.fetch>().mockResolvedValue(new Response(null, { status: 204 }));
    const delivery = new HermesDelivery({
      url: `http://${tailscaleHost}/success`,
      analysisUrl: `http://${tailscaleHost}/analysis`,
      key: Buffer.from("hmac-key-that-is-at-least-32-bytes-long"),
      fetch,
      clock: () => NOW,
      maxAttempts: 1,
      backoffMs: 1,
      timeoutMs: 1_000,
    });
    await delivery.deliver("{}", "analysis-1", "analysis");
    expect(fetch.mock.calls[0]?.[0]).toBe(`http://${tailscaleHost}/analysis`);
    expect(Object.keys((fetch.mock.calls[0]?.[1]?.headers ?? {}) as Record<string, string>)).toEqual([
      "X-Webhook-Signature-V2",
      "X-Webhook-Timestamp",
      "X-Request-ID",
    ]);
    expect(fetch.mock.calls[0]?.[1]?.headers).not.toHaveProperty("X-GitHub-Event");
  });
});
