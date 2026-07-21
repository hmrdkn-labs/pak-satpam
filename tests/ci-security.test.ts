import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  FileApprovalAuditStore,
  InMemoryApprovalAuditStore,
  ApprovalTokenService,
  MAX_APPROVAL_TTL_SECONDS,
} from "../src/ci/approval.js";
import { redactText } from "../src/ci/redaction.js";
import { isCIResourceAllowed, assertCIResourceAllowed, createCIAllowlist } from "../src/ci/policy.js";
import { JenkinsProvider } from "../src/providers/jenkins-provider.js";

const BINDING = {
  repo: "owner/repo",
  workflow: "ci.yml",
  runId: "101",
  runAttempt: 1,
  headSha: "a".repeat(40),
  requestId: "request-1",
};

describe("CI approval and redaction controls", () => {
  it("allows Jenkins multibranch children while denying other repositories and folders", () => {
    const provider = new JenkinsProvider({ baseUrl: "https://jenkins.example", fetch: vi.fn<typeof globalThis.fetch>() });
    const policy = createCIAllowlist({ "academytools/planpal-config-6": ["planpalasix-config"] });
    const matches = provider.matchesWorkflow.bind(provider);

    expect(isCIResourceAllowed(policy, "academytools/planpal-config-6", "planpalasix-config/main", matches)).toBe(true);
    expect(isCIResourceAllowed(policy, "academytools/planpal-config-6", "planpalasix-config/PR-9", matches)).toBe(true);
    expect(isCIResourceAllowed(policy, "academytools/other-repo", "planpalasix-config/main", matches)).toBe(false);
    expect(isCIResourceAllowed(policy, "academytools/planpal-config-6", "unlisted-folder/main", matches)).toBe(false);
    expect(() => assertCIResourceAllowed(policy, "academytools/planpal-config-6", "unlisted-folder/main", matches)).toThrow("ci_policy_denied");
  });

  it("redacts common secret forms before evidence or audit", () => {
    const syntheticGitHubToken = `ghp_${"x".repeat(32)}`;
    const result = redactText(
      `token=super-secret Authorization: Bearer ${syntheticGitHubToken} and password: nope`,
    );
    expect(result.redacted).toBe(true);
    expect(result.text).not.toContain("super-secret");
    expect(result.text).not.toContain(syntheticGitHubToken);
    expect(result.text).not.toContain("nope");
    const awsKey = `AKIA${"1234567890ABCDEF"}`;
    const cloudSecret = "cloud" + "-secret";
    const jwt = ["eyJhbGciOiJIUzI1NiJ9", "payload", "signature"].join(".");
    const cloud = redactText(`AWS_ACCESS_KEY_ID=${awsKey} AZURE_CLIENT_SECRET=${cloudSecret} ${jwt}`);
    expect(cloud.redacted).toBe(true);
    expect(cloud.text).not.toContain(awsKey);
    expect(cloud.text).not.toContain(cloudSecret);
    expect(cloud.text).not.toContain("eyJhbGci");
  });

  it("binds approval to all request fields, enforces short TTL, and consumes once", () => {
    const audit = new InMemoryApprovalAuditStore();
    const service = new ApprovalTokenService({
      key: Buffer.from("a".repeat(32)),
      clock: () => new Date("2026-07-10T00:00:00.000Z"),
      audit,
    });
    const token = service.issue({ ...BINDING, ttlSeconds: MAX_APPROVAL_TTL_SECONDS });

    expect(service.verifyAndConsume(token, BINDING).ok).toBe(true);
    expect(service.verifyAndConsume(token, BINDING)).toMatchObject({ ok: false, code: "replay" });
    expect(service.verifyAndConsume(token, { ...BINDING, requestId: "request-2" })).toMatchObject({
      ok: false,
      code: "binding",
    });
    expect(audit.events.every((event) => !JSON.stringify(event).includes("a".repeat(32)))).toBe(true);
  });

  it("rejects a mismatched run attempt before consuming the approval", () => {
    const audit = new InMemoryApprovalAuditStore();
    const service = new ApprovalTokenService({
      key: Buffer.from("c".repeat(32)),
      clock: () => new Date("2026-07-10T00:00:00.000Z"),
      audit,
    });
    const token = service.issue({ ...BINDING, ttlSeconds: 60 });

    expect(service.verifyAndConsume(token, { ...BINDING, runAttempt: 2 })).toMatchObject({
      ok: false,
      code: "binding",
    });
    expect(service.verifyAndConsume(token, BINDING)).toMatchObject({ ok: true });
  });

  it("rejects a mismatched head SHA before consuming the approval", () => {
    const audit = new InMemoryApprovalAuditStore();
    const service = new ApprovalTokenService({
      key: Buffer.from("d".repeat(32)),
      clock: () => new Date("2026-07-10T00:00:00.000Z"),
      audit,
    });
    const token = service.issue({ ...BINDING, ttlSeconds: 60 });

    expect(service.verifyAndConsume(token, { ...BINDING, headSha: "b".repeat(40) })).toMatchObject({
      ok: false,
      code: "binding",
    });
    expect(service.verifyAndConsume(token, BINDING)).toMatchObject({ ok: true });
  });

  it("rejects duplicate requests, expired tokens, oversized TTL, and bad key files", () => {
    const audit = new InMemoryApprovalAuditStore();
    let now = new Date("2026-07-10T00:00:00.000Z");
    const service = new ApprovalTokenService({ key: Buffer.from("b".repeat(32)), clock: () => now, audit });
    expect(() => service.issue({ ...BINDING, ttlSeconds: MAX_APPROVAL_TTL_SECONDS + 1 })).toThrow(
      "approval TTL",
    );
    const first = service.issue({ ...BINDING, ttlSeconds: 60 });
    expect(service.verifyAndConsume(first, BINDING).ok).toBe(true);
    const second = service.issue({ ...BINDING, ttlSeconds: 60, nonce: "different-nonce-12345" });
    expect(service.verifyAndConsume(second, BINDING)).toMatchObject({ ok: false, code: "duplicate" });
    const expired = service.issue({ ...BINDING, requestId: "request-2", ttlSeconds: 60 });
    now = new Date("2026-07-10T00:02:00.000Z");
    expect(service.verifyAndConsume(expired, {
      ...BINDING,
      requestId: "request-2",
    })).toMatchObject({ ok: false, code: "expired" });

    const directory = mkdtempSync(join(tmpdir(), "goal14-approval-"));
    const keyPath = join(directory, "key");
    writeFileSync(keyPath, "key-material", { mode: 0o600 });
    chmodSync(keyPath, 0o644);
    expect(() => ApprovalTokenService.readKeyFile(keyPath)).toThrow("0600");
    rmSync(directory, { recursive: true, force: true });
  });

  it("persists replay metadata and appends sanitized audit records", () => {
    const directory = mkdtempSync(join(tmpdir(), "goal14-audit-"));
    const replayPath = join(directory, "replay.jsonl");
    const auditPath = join(directory, "audit.jsonl");
    const store = new FileApprovalAuditStore({ replayPath, auditPath });
    store.recordApprovalUse({
      ...BINDING,
      nonce: "nonce-value",
      outcome: "success",
      at: "2026-07-10T00:00:00.000Z",
    });
    store.append({ event: "rerun", repo: "owner/repo", workflow: "ci.yml", detail: "Bearer ghp_secret" });

    const restored = new FileApprovalAuditStore({ replayPath, auditPath });
    expect(restored.hasNonce("nonce-value")).toBe(true);
    expect(readFileSync(auditPath, "utf8")).not.toContain("ghp_secret");
    expect(readFileSync(replayPath, "utf8")).not.toContain("nonce-value");
    expect(readFileSync(auditPath, "utf8")).toContain('"event":"rerun"');
    rmSync(directory, { recursive: true, force: true });
  });

  it("permits only one concurrent action lease per workflow run", () => {
    const store = new InMemoryApprovalAuditStore();
    const release = store.acquireActionLease(BINDING);
    expect(release).toBeTypeOf("function");
    expect(store.acquireActionLease(BINDING)).toBeUndefined();
    release?.();
    expect(store.acquireActionLease(BINDING)).toBeTypeOf("function");
  });
});
